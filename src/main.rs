use aael::Attester; 
use aael::eventlog::*;
use aael::TeeEvidenceParsedClaim;
use aael::tdx::*;

use anyhow::*;
use base64::Engine;
use serde_json::{Map, Value, to_string_pretty};
use std::str::FromStr;
use log::{debug, warn, info};

macro_rules! parse_claim {
    ($map_name: ident, $key_name: literal, $field: ident) => {
        $map_name.insert($key_name.to_string(), serde_json::Value::Object($field))
    };
    ($map_name: ident, $key_name: literal, $field: expr) => {
        $map_name.insert(
            $key_name.to_string(),
            serde_json::Value::String(hex::encode($field)),
        )
    };
}

fn generate_parsed_claim(
    quote: Quote,
    cc_eventlog: Option<CcEventLog>,
    aa_eventlog: Option<AAEventlog>,
) -> Result<TeeEvidenceParsedClaim> {
    let mut quote_map = Map::new();
    let mut quote_body = Map::new();
    let mut quote_header = Map::new();

    match &quote {
        Quote::V4 { header, body } => {
            parse_claim!(quote_header, "version", b"\x04\x00");
            parse_claim!(quote_header, "att_key_type", header.att_key_type);
            parse_claim!(quote_header, "tee_type", header.tee_type);
            parse_claim!(quote_header, "reserved", header.reserved);
            parse_claim!(quote_header, "vendor_id", header.vendor_id);
            parse_claim!(quote_header, "user_data", header.user_data);
            parse_claim!(quote_body, "tcb_svn", body.tcb_svn);
            parse_claim!(quote_body, "mr_seam", body.mr_seam);
            parse_claim!(quote_body, "mrsigner_seam", body.mrsigner_seam);
            parse_claim!(quote_body, "seam_attributes", body.seam_attributes);
            parse_claim!(quote_body, "td_attributes", body.td_attributes);
            parse_claim!(quote_body, "xfam", body.xfam);
            parse_claim!(quote_body, "mr_td", body.mr_td);
            parse_claim!(quote_body, "mr_config_id", body.mr_config_id);
            parse_claim!(quote_body, "mr_owner", body.mr_owner);
            parse_claim!(quote_body, "mr_owner_config", body.mr_owner_config);
            parse_claim!(quote_body, "rtmr_0", body.rtmr_0);
            parse_claim!(quote_body, "rtmr_1", body.rtmr_1);
            parse_claim!(quote_body, "rtmr_2", body.rtmr_2);
            parse_claim!(quote_body, "rtmr_3", body.rtmr_3);
            parse_claim!(quote_body, "report_data", body.report_data);

            parse_claim!(quote_map, "header", quote_header);
            parse_claim!(quote_map, "body", quote_body);
        }
        Quote::V5 {
            header,
            r#type,
            size,
            body,
        } => {
            parse_claim!(quote_header, "version", b"\x05\x00");
            parse_claim!(quote_header, "att_key_type", header.att_key_type);
            parse_claim!(quote_header, "tee_type", header.tee_type);
            parse_claim!(quote_header, "reserved", header.reserved);
            parse_claim!(quote_header, "vendor_id", header.vendor_id);
            parse_claim!(quote_header, "user_data", header.user_data);
            parse_claim!(quote_map, "type", r#type.as_bytes());
            parse_claim!(quote_map, "size", &size[..]);
            match body {
                QuoteV5Body::Tdx10(body) => {
                    parse_claim!(quote_body, "tcb_svn", body.tcb_svn);
                    parse_claim!(quote_body, "mr_seam", body.mr_seam);
                    parse_claim!(quote_body, "mrsigner_seam", body.mrsigner_seam);
                    parse_claim!(quote_body, "seam_attributes", body.seam_attributes);
                    parse_claim!(quote_body, "td_attributes", body.td_attributes);
                    parse_claim!(quote_body, "xfam", body.xfam);
                    parse_claim!(quote_body, "mr_td", body.mr_td);
                    parse_claim!(quote_body, "mr_config_id", body.mr_config_id);
                    parse_claim!(quote_body, "mr_owner", body.mr_owner);
                    parse_claim!(quote_body, "mr_owner_config", body.mr_owner_config);
                    parse_claim!(quote_body, "rtmr_0", body.rtmr_0);
                    parse_claim!(quote_body, "rtmr_1", body.rtmr_1);
                    parse_claim!(quote_body, "rtmr_2", body.rtmr_2);
                    parse_claim!(quote_body, "rtmr_3", body.rtmr_3);
                    parse_claim!(quote_body, "report_data", body.report_data);

                    parse_claim!(quote_map, "header", quote_header);
                    parse_claim!(quote_map, "body", quote_body);
                }
                QuoteV5Body::Tdx15(body) => {
                    parse_claim!(quote_body, "tcb_svn", body.tcb_svn);
                    parse_claim!(quote_body, "mr_seam", body.mr_seam);
                    parse_claim!(quote_body, "mrsigner_seam", body.mrsigner_seam);
                    parse_claim!(quote_body, "seam_attributes", body.seam_attributes);
                    parse_claim!(quote_body, "td_attributes", body.td_attributes);
                    parse_claim!(quote_body, "xfam", body.xfam);
                    parse_claim!(quote_body, "mr_td", body.mr_td);
                    parse_claim!(quote_body, "mr_config_id", body.mr_config_id);
                    parse_claim!(quote_body, "mr_owner", body.mr_owner);
                    parse_claim!(quote_body, "mr_owner_config", body.mr_owner_config);
                    parse_claim!(quote_body, "rtmr_0", body.rtmr_0);
                    parse_claim!(quote_body, "rtmr_1", body.rtmr_1);
                    parse_claim!(quote_body, "rtmr_2", body.rtmr_2);
                    parse_claim!(quote_body, "rtmr_3", body.rtmr_3);
                    parse_claim!(quote_body, "report_data", body.report_data);

                    parse_claim!(quote_body, "tee_tcb_svn2", body.tee_tcb_svn2);
                    parse_claim!(quote_body, "mr_servicetd", body.mr_servicetd);

                    parse_claim!(quote_map, "header", quote_header);
                    parse_claim!(quote_map, "body", quote_body);
                }
            }
        }
    }

    // Claims from CC EventLog.
    let mut ccel_map = Map::new();
    if let Some(ccel) = cc_eventlog {
        parse_ccel(ccel, &mut ccel_map)?;
    }

    let td_attributes = parse_td_attributes(quote.td_attributes())?;

    let mut claims = Map::new();

    // Claims from AA eventlog
    if let Some(aael) = aa_eventlog {
        let aael_map = aael.to_parsed_claims();
        parse_claim!(claims, "aael", aael_map);
    }

    parse_claim!(claims, "quote", quote_map);
    parse_claim!(claims, "ccel", ccel_map);
    parse_claim!(claims, "td_attributes", td_attributes);

    parse_claim!(claims, "report_data", quote.report_data());
    parse_claim!(claims, "init_data", quote.mr_config_id());

    let claims_str = serde_json::to_string_pretty(&claims)?;
    debug!("Parsed Evidence claims map: \n{claims_str}\n");

    Ok(Value::Object(claims) as TeeEvidenceParsedClaim)
}

fn parse_ccel(ccel: CcEventLog, ccel_map: &mut Map<String, Value>) -> Result<()> {
    // Digest of kernel using td-shim
    match ccel.query_digest(MeasuredEntity::TdShimKernel) {
        Some(kernel_digest) => {
            ccel_map.insert(
                "kernel".to_string(),
                serde_json::Value::String(kernel_digest),
            );
        }
        _ => {
            warn!("No td-shim kernel hash in CCEL");
        }
    }

    // Digest of kernel using TDVF
    match ccel.query_digest(MeasuredEntity::TdvfKernel) {
        Some(kernel_digest) => {
            ccel_map.insert(
                "kernel".to_string(),
                serde_json::Value::String(kernel_digest),
            );
        }
        _ => {
            warn!("No tdvf kernel hash in CCEL");
        }
    }

    // Digest of kernel cmdline using TDVF
    match ccel.query_digest(MeasuredEntity::TdvfKernelParams) {
        Some(cmdline_digest) => {
            ccel_map.insert(
                "cmdline".to_string(),
                serde_json::Value::String(cmdline_digest),
            );
        }
        _ => {
            warn!("No tdvf kernel cmdline hash in CCEL");
        }
    }

    // Digest of initrd using TDVF
    match ccel.query_digest(MeasuredEntity::TdvfInitrd) {
        Some(initrd_digest) => {
            ccel_map.insert(
                "initrd".to_string(),
                serde_json::Value::String(initrd_digest),
            );
        }
        _ => {
            warn!("No tdvf initrd hash in CCEL");
        }
    }

    // Map of Kernel Parameters
    match ccel.query_event_data(MeasuredEntity::TdShimKernelParams) {
        Some(config_info) => {
            let td_shim_platform_config_info =
                TdShimPlatformConfigInfo::try_from(&config_info[..])?;

            let parameters = parse_kernel_parameters(td_shim_platform_config_info.data)?;
            ccel_map.insert(
                "kernel_parameters".to_string(),
                serde_json::Value::Object(parameters),
            );
        }
        _ => {
            warn!("No td-shim kernel parameters in CCEL");
        }
    }

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let attester = TdxAttester::default();
    let report_data: Vec<u8> = vec![0; 48];
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
