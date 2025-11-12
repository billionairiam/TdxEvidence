use aael::BoxedAttester;
use aael::detect_tee_type;
use aael::eventlog::*;
use aael::tdx::*;

use anyhow::*;
use base64::Engine;
use crypto::HashAlgorithm;
use log::{info, warn};
use serde_json::to_string_pretty;
use std::str::FromStr;
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<()> {
    let tee = detect_tee_type();
    let attester: BoxedAttester = tee.try_into()?;
    let attester = Arc::new(attester);
    let mut el = EventLog::new(attester.clone(), HashAlgorithm::Sha384, 17)
        .await
        .unwrap();
    let report_data: Vec<u8> = vec![0; 48];

    let ev = LogEntry::Event {
        domain: "one",
        operation: "two",
        content: "three".try_into().unwrap(),
    };
    el.extend_entry(ev, 17).await.unwrap();
    let evidence = attester.get_evidence(report_data).await.unwrap();
    let evidence: TdxEvidence = serde_json::from_str(evidence.as_str())?;
    if evidence.quote.is_empty() {
        bail!("TDX Quote is empty.");
    }

    // Verify TD quote ECDSA signature.
    let quote_bin = base64::engine::general_purpose::STANDARD.decode(evidence.quote)?;
    let quote = parse_tdx_quote(&quote_bin)?;

    // Verify Integrity of CC Eventlog
    let mut ccel_option = Option::default();
    match &evidence.cc_eventlog {
        Some(el) if !el.is_empty() => {
            let ccel_data = base64::engine::general_purpose::STANDARD.decode(el)?;
            let ccel = CcEventLog::try_from(ccel_data)
                .map_err(|e| anyhow!("Parse CC Eventlog failed: {:?}", e))?;
            ccel_option = Some(ccel.clone());

            log::debug!("Get CC Eventlog. \n{}\n", &ccel.cc_events);

            let rtmr_from_quote = Rtmr {
                rtmr0: quote.rtmr_0().try_into().expect("must be 48 bytes"),
                rtmr1: quote.rtmr_1().try_into().expect("must be 48 bytes"),
                rtmr2: quote.rtmr_2().try_into().expect("must be 48 bytes"),
                rtmr3: quote.rtmr_3().try_into().expect("must be 48 bytes"),
            };

            ccel.integrity_check(rtmr_from_quote)?;
            info!("CCEL integrity check succeeded.");
        }
        _ => {
            warn!("No CC Eventlog included inside the TDX evidence.");
        }
    }

    // Verify Integrity of AA eventlog
    let aael_option = match &evidence.aa_eventlog {
        Some(el) if !el.is_empty() => {
            let aael =
                AAEventlog::from_str(el).context("failed to parse AA Eventlog from evidence")?;
            // We assume we always use PCR 17, rtmr 3 for the application side events.

            let checkresult = aael.integrity_check(quote.rtmr_3());
            assert!(checkresult, "CCEL integrity check succeeded");
            Some(aael)
        }
        _ => {
            warn!("No AA Eventlog included inside the TDX evidence.");
            None
        }
    };

    let claims = generate_parsed_claim(quote, ccel_option, aael_option)?;
    let readable_json = to_string_pretty(&claims)?;
    println!("{}", readable_json);

    Ok(())
}
