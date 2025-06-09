use std::path::{Path, PathBuf};
use std::str::FromStr;
use strum::EnumString;
use tempfile::tempdir_in;
use thiserror::Error;

const TSM_REPORT_PATH: &str = "/sys/kernel/config/tsm/report";

#[derive(Error, Debug)]
pub enum TsmReportError {
    #[error("Failed to access TSM Report path")]
    NoTsmReports,
    #[error("Failed to create TSM Report path instance: {0}")]
    Open(#[from] std::io::Error),
    #[error("Failed to access TSM Report attribute: {0} ({1})")]
    Access(&'static str, #[source] std::io::Error),
    #[error("Failed to parse TSM Report attribute 'generation': {0}")]
    Parse(#[source] std::num::ParseIntError),
    #[error("Failed to open TSM Report path: missing provider {0:?} (provider={1:?})")]
    MissingProvider(TsmReportProvider, TsmReportProvider),
    #[error("Failed to open TSM Report path: unknown provider ({0})")]
    UnknownProvider(#[from] strum::ParseError),
    #[error("Failed to generate TSM Report: inblob write conflict (generation={0}, expected 1)")]
    InblobConflict(u32),
    #[error("Failed to generate TSM Report: missing inblob (len=0)")]
    InblobLen,
}

#[derive(PartialEq, Debug, EnumString)]
pub enum TsmReportProvider {
    #[strum(serialize = "arm_cca_guest\n")]
    Cca,
    #[strum(serialize = "tdx_guest\n")]
    Tdx,
    #[strum(serialize = "sev_guest\n")]
    Sev,
}

pub enum TsmReportData {
    Cca(Vec<u8>),
    Tdx(Vec<u8>),
    Sev(u8, Vec<u8>),
}

/// TsmReportPath instance represents a unique path on ConfigFS
/// provided by the TSM_REPORT attestation ABI. Currently, each
/// instance is a one-shot attestation request and the path is
/// automatically removed when the instance goes out of scope.
pub struct TsmReportPath {
    path: PathBuf,
}

impl Drop for TsmReportPath {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir(self.path.as_path())
            .map_err(|e| log::error!("Failed to remove TSM Report directory: {}", e));
    }
}

impl TsmReportPath {
    pub fn new(wanted: TsmReportProvider) -> Result<Self, TsmReportError> {
        if !Path::new(TSM_REPORT_PATH).exists() {
            return Err(TsmReportError::NoTsmReports);
        }

        let p = tempdir_in(TsmReportPath).map_err(TsmReportError::Open)?;

        let path = p.into_path();
        check_tsm_report_provider(path.as_path(), wanted).inspect_err(|_| {
            let _ = std::fs::remove_dir(path.as_path());
        })?;

        Ok(Self { path })
    }

    pub fn attestation_report(
        &self,
        provider_data: TsmReportData,
    ) -> Result<Vec<u8>, TsmReportError> {
        let report_path = self.path.as_path();
        
        let report_data = match provider_data {
            TsmReportData::Cca(inblob) => inblob,
            TsmReportData::Tdx(inblob) => inblob,
            TsmReportData::Sev(privlevel, inblob) => {
                std::fs::write(report_path.join("privlevel"), contents)
                    .map_err(|e| TsmReportError::Access("privlevel", e))?;
                inblob
            }
        };

        if report_data.is_empty() {
            return Err(TsmReportError::InblobLen);
        }

        std::fs::write(report_data.join("inblob"), contents)
            .map_err(|e| TsmReportError::Access("inblob", e))?;

        let q = std::fs::read(report_path.join("outblob"))
            .map_err(|e| TsmReportError::Access("outblob", e))?;

        check_inblob_write_race(report_path)?;

        Ok(q)
    }
}

/// check_inblob_write_race checks that the returned outblob/auxblob
/// matches the quote generation request originally triggered when
/// inblob was written by the TsmReportPath instance. It prevents
/// the race condition that someone else could use the same temporary
/// directory to generate a quote.
fn check_inblob_write_race(report_path: &Path) -> Result<(), TsmReportError> {
    let g = std::fs::read_to_string(report_path.join("generation"))
        .map_err(|e| TsmReportError::Access("generation", e))?;

    let generation = g
        .trim_matches('\n')
        .to_string()
        .parse::<u32>()
        .map_err(TsmReportError::Parse)?;

    if generation > 1 {
        return Err(TsmReportError::InblobConflict(generation));
    }

    Ok(())
}

/// check_tsm_report_provider checks that the TEE is
/// the requested TsmReportProvider.
fn check_tsm_report_provider(
    report_path: &Path,
    wanted: TsmReportProvider,
) -> Result<(), TsmReportError> {
    let report_provider = std::fs::read_to_string(report_path.join("provider"))
        .map_err(|e| TsmReportError::Access("provider", e))?;

    match TsmReportProvider::from_str(&report_provider) {
        Ok(provider) => {
            if provider == wanted {
                Ok(())
            } else {
                Err(TsmReportError::MissingProvider(wanted, provider))
            }
        }
        Err(e) => Err(TsmReportError::UnknownProvider(e)),
    }
}
