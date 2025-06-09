use anyhow::*;
use kbs_types::Tee;

pub mod sample;
pub mod utils;

#[cfg(feature = "tdx-attester")]
pub mod eventlog;

#[cfg(feature = "tdx-attester")]
pub mod tdx;

#[cfg(feature = "tdx-attester")]
pub mod tsm_report;

pub type BoxedAttester = Box<dyn Attester + Send + Sync>;

impl TryFrom<Tee> for BoxedAttester {
    type Error = anyhow::Error;

    fn try_from(value: Tee) -> Result<Self> {
        let attester: Box<dyn Attester + Send + Sync> = match value {
            Tee::Sample => Box::<sample::SampleAttester>::default(),
            #[cfg(feature = "tdx-attester")]
            Tee::Tdx => Box::<tdx::TdxAttester>::default(),
            _ => bail!("TEE is not supported!"),
        };

        Ok(attester)
    }
}

pub enum InitDataResult {
    Ok,
    Unsupported,
}

#[async_trait::async_trait]
pub trait Attester {
    /// Call the hardware driver to get the Hardware specific evidence.
    /// The parameter `report_data` will be used as the user input of the
    /// evidence to avoid reply attack.
    async fn get_evidence(&self, report_data: Vec<u8>) -> Result<String>;

    /// Extend TEE specific dynamic measurement register
    /// to enable dynamic measurement capabilities for input data at runtime.
    async fn extend_runtime_measurement(
        &self,
        _event_digest: Vec<u8>,
        _register_index: u64,
    ) -> Result<()> {
        bail!("Unimplemented")
    }

    async fn bind_init_data(&self, _init_data_digest: &[u8]) -> Result<InitDataResult> {
        Ok(InitDataResult::Unsupported)
    }

    /// This function is used to get the runtime measurement registry value of
    /// the given PCR register index. Different platforms have different mapping
    /// relationship between PCR and platform RTMR.
    async fn get_runtime_measurement(&self, _pcr_index: u64) -> Result<Vec<u8>> {
        bail!("Unimplemented")
    }
}

pub fn detect_tee_type() -> Tee {
    #[cfg(feature = "tdx-attester")]
    if tdx::detect_platform() {
        return Tee::Tdx;
    }

    log::warn!("No TEE platform detected. Sample Attester will be used.");
    Tee::Sample
}
