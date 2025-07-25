use self::rtmr::TdxRtmrEvent;

use crate::tsm_report::*;
use crate::Attester;
use crate::utils::pad;
use crate::InitDataResult;

use anyhow::*;
use base64::Engine;
use scroll::Pread;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use tdx_attest_rs::tdx_report_t;

pub mod report;
pub mod rtmr;
pub mod quote;
pub mod claims;

pub use quote::*;
pub use report::*;
pub use claims::*;

const TDX_REPORT_DATA_SIZE: usize = 64;
const CCEL_PATH: &str = "/sys/firmware/acpi/tables/data/CCEL";

pub fn detect_platform() -> bool {
    TsmReportPath::new(TsmReportProvider::Tdx).is_ok() || Path::new("/dev/tdx_guest").exists()
}

fn get_quote_ioctl(report_data: &Vec<u8>) -> Result<Vec<u8>> {
    let tdx_report_data = tdx_attest_rs::tdx_report_data_t {
        d: report_data.as_slice().try_into().unwrap(),
    };

    match tdx_attest_rs::tdx_att_get_quote(Some(&tdx_report_data), None, None, 0) {
        (tdx_attest_rs::tdx_attest_error_t::TDX_ATTEST_SUCCESS, Some(q)) => Ok(q),
        (error_code, _) => Err(anyhow!(
            "TDX getquote ioctl: failed with error code: {:?}",
            error_code
        )),
    }
}

// Return true if the TD environment can extend runtime measurement,
// else false. The best guess at the moment is that if "TSM reports"
// is available, the TD runs Linux upstream kernel and is _currently_
// not able to do it.
fn runtime_measurement_extend_available() -> bool {
    if Path::new("/sys/kernel/config/tsm/report").exists() {
        return true;
    }

    false
}

pub const DEFAULT_EVENTLOG_PATH: &str = "/run/attestation-agent/eventlog";

#[derive(Serialize, Deserialize)]
pub struct TdxEvidence {
    // Base64 encoded CC Eventlog ACPI table
    // refer to https://uefi.org/specs/ACPI/6.5/05_ACPI_Software_Programming_Model.html#cc-event-log-acpi-table.
    pub cc_eventlog: Option<String>,
    // Base64 encoded TD quote.
    pub quote: String,
    // Eventlog of Attestation Agent
    pub aa_eventlog: Option<String>,
}

#[derive(Debug, Default)]
pub struct TdxAttester {}

impl TdxAttester {
    fn get_report() -> Result<TdReport> {
        let mut report = tdx_report_t { d : [0; 1024]};
        match tdx_attest_rs::tdx_att_get_report(None, &mut report) {
            tdx_attest_rs::tdx_attest_error_t::TDX_ATTEST_SUCCESS => {
                log::debug!("Successfully got report")
            }
            error_code => {
                bail!(
                    "TDX Attester: Failed to get TD report. Error code: {:?}",
                    error_code
                );
            }
        }

        let td_report = report
            .d
            .pread::<report::TdReport>(0)
            .context("Parse TD report failed")?;

        Ok(td_report)
    }

    fn pcr_to_rtmr(register_index: u64) -> u64 {
        match register_index {
            1 | 7 => 0,
            2..=6 => 1,
            8..=15 => 2,
            _ => 3,
        }
    }
}

#[async_trait::async_trait]
impl Attester for TdxAttester {
    async fn get_evidence(&self, mut report_data: Vec<u8>) -> Result<String> {
        if report_data.len() > TDX_REPORT_DATA_SIZE {
            bail!("TDX Attester: Report data must be no more than {TDX_REPORT_DATA_SIZE} bytes");
        }

        report_data.resize(TDX_REPORT_DATA_SIZE, 0);

        let quote_bytes = TsmReportPath::new(TsmReportProvider::Tdx).map_or_else(
            |notsm| {
                get_quote_ioctl(&report_data)
                    .context(format!("TDX Attester: quote generation using ioctl() fallback failed after a TSM report error ({notsm})"))
            },
            |tsm| {
                tsm.attestation_report(TsmReportData::Tdx(report_data.clone()))
                    .context("TDX Attester: quote generation using TSM reports failed")
            },
        )?;

        let engine = base64::engine::general_purpose::STANDARD;
        let quote = engine.encode(quote_bytes);

        let cc_eventlog = match std::fs::read(CCEL_PATH) {
            Result::Ok(el) => Some(engine.encode(el)),
            Result::Err(e) => {
                log::warn!("Read CC Eventlog failed: {:?}", e);
                None
            }
        };

        let aa_eventlog = match fs::read_to_string(DEFAULT_EVENTLOG_PATH) {
            Result::Ok(el) => Some(el),
            Result::Err(e) => {
                log::warn!("Read AA Eventlog failed: {:?}", e);
                None
            }
        };

        let evidence = TdxEvidence {
            cc_eventlog,
            quote,
            aa_eventlog,
        };

        serde_json::to_string(&evidence).context("Serialize TDX evidence failed")
    }

    async fn extend_runtime_measurement(
        &self,
        event_digest: Vec<u8>,
        register_index: u64,
    ) -> Result<()> {
        if !runtime_measurement_extend_available() {
            bail!("TDX Attester: Cannot extend runtime measurement on this system");
        }

        let rtmr_index = Self::pcr_to_rtmr(register_index);

        let extend_data: [u8; 48] = pad(&event_digest);
        let event: Vec<u8> = TdxRtmrEvent::default()
            .with_extend_data(extend_data)
            .with_rtmr_index(rtmr_index)
            .into();

        match tdx_attest_rs::tdx_att_extend(&event) {
            tdx_attest_rs::tdx_attest_error_t::TDX_ATTEST_SUCCESS => {
                log::debug!("TDX extend runtime measurement succeeded.")
            }
            error_code => {
                bail!(
                    "TDX Attester: Failed to extend RTMR. Error code: {:?}",
                    error_code
                );
            }
        }

        Ok(())
    }

    async fn bind_init_data(&self, init_data_digest: &[u8]) -> Result<InitDataResult> {
        let td_report = Self::get_report()?;
        let init_data: [u8; 48] = pad(init_data_digest);
        if init_data != td_report.tdinfo.mrconfigid {
            bail!("Init data does not match!");
        }

        Ok(InitDataResult::Ok)
    }

    async fn get_runtime_measurement(&self, pcr_index: u64) -> Result<Vec<u8>> {
        let td_report = Self::get_report()?;
        let rtmr_index = Self::pcr_to_rtmr(pcr_index) as usize;

        Ok(td_report.get_rtmr(rtmr_index))
    }
}
