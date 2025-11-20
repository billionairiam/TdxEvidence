use anyhow::Result;
use bitflags::{Flags, bitflags};
use byteorder::{LittleEndian, ReadBytesExt};
use log::{debug, warn};
use serde_json::{Map, Value};
use thiserror::Error;

use super::quote::*;
use crate::TeeEvidenceParsedClaim;
use crate::eventlog::AAEventlog;
use crate::eventlog::CcEventLog;
use crate::eventlog::MeasuredEntity;

macro_rules! parse_claim {
    ($map_name: ident, $key_name: literal, $field: ident) => {
        if let Ok(val) = serde_json::to_value(&$field) {
            $map_name.insert($key_name.to_string(), val);
        }
    };
    ($map_name: ident, $key_name: literal, $field: expr) => {
        $map_name.insert(
            $key_name.to_string(),
            serde_json::Value::String(hex::encode($field)),
        )
    };
}

pub fn generate_parsed_claim(
    quote: Quote,
    cc_eventlog: Option<CcEventLog>,
    aa_eventlog: Option<AAEventlog>,
) -> Result<TeeEvidenceParsedClaim> {
    let mut quote_map = Map::new();
    let mut quote_body = Map::new();
    let mut quote_header = Map::new();

    match &quote {
        Quote::V4 {
            header,
            body,
            certs,
        } => {
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
            parse_claim!(quote_map, "certs", certs);
        }
        Quote::V5 {
            header,
            r#type,
            size,
            body,
            certs,
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
                    parse_claim!(quote_map, "certs", certs);
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
                    parse_claim!(quote_map, "certs", certs);
                }
            }
        }
    }

    let mut claims = Map::new();

    // Claims from CC EventLog.
    let mut ccel_map = Map::new();
    if let Some(ccel) = cc_eventlog {
        parse_ccel(ccel, &mut ccel_map)?;
        parse_claim!(claims, "ccel", ccel_map);
    }

    let td_attributes = parse_td_attributes(quote.td_attributes())?;

    // Claims from AA eventlog
    if let Some(aael) = aa_eventlog {
        let aael_map = aael.to_parsed_claims();
        parse_claim!(claims, "aael", aael_map);
    }

    parse_claim!(claims, "quote", quote_map);
    parse_claim!(claims, "td_attributes", td_attributes);

    parse_claim!(claims, "report_data", quote.report_data());

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

bitflags! {
    #[derive(Debug, Clone)]
    struct TdAttributesFlags: u64 {
        const DEBUG            = 1 << 0;
        const SEPTVE_DISABLE   = 1 << 28;
        const PROTECTION_KEYS  = 1 << 30;
        const KEY_LOCKER       = 1 << 31;
        const PERFMON          = 1 << 63;
    }
}

pub fn parse_td_attributes(data: &[u8]) -> Result<Map<String, Value>> {
    let arr = <[u8; 8]>::try_from(data)?;
    let td = TdAttributesFlags::from_bits_retain(u64::from_le_bytes(arr));
    let attribs = TdAttributesFlags::FLAGS
        .iter()
        .map(|f| {
            (
                f.name().to_string().to_lowercase(),
                Value::Bool(td.contains(f.value().clone())),
            )
        })
        .collect();

    Ok(attribs)
}

#[derive(Error, Debug, PartialEq)]
pub enum PlatformConfigInfoError {
    #[error("Failed to parse `Descriptor`")]
    ParseDescriptor,

    #[error("Failed to parse `InfoLength`")]
    ReadInfoLength,

    #[error("invalid header")]
    InvalidHeader,

    #[error("not enough data after header")]
    NotEnoughData,
}

type Descriptor = [u8; 16];
type InfoLength = u32;

/// Kernel Commandline Event inside Eventlog
#[derive(Debug, PartialEq)]
pub struct TdShimPlatformConfigInfo<'a> {
    pub descriptor: Descriptor,
    pub info_length: InfoLength,
    pub data: &'a [u8],
}

impl<'a> TryFrom<&'a [u8]> for TdShimPlatformConfigInfo<'a> {
    type Error = PlatformConfigInfoError;

    fn try_from(data: &'a [u8]) -> std::result::Result<Self, Self::Error> {
        let descriptor_size = core::mem::size_of::<Descriptor>();

        let info_size = core::mem::size_of::<InfoLength>();

        let header_size = descriptor_size + info_size;

        if data.len() < header_size {
            return Err(PlatformConfigInfoError::InvalidHeader);
        }

        let descriptor = data[0..descriptor_size]
            .try_into()
            .map_err(|_| PlatformConfigInfoError::ParseDescriptor)?;

        let info_length = (&data[descriptor_size..header_size])
            .read_u32::<LittleEndian>()
            .map_err(|_| PlatformConfigInfoError::ReadInfoLength)?;

        let total_size = header_size + info_length as usize;

        let data = data
            .get(header_size..total_size)
            .ok_or(PlatformConfigInfoError::NotEnoughData)?;

        std::result::Result::Ok(Self {
            descriptor,
            info_length,
            data,
        })
    }
}

pub fn parse_kernel_parameters(kernel_parameters: &[u8]) -> Result<Map<String, Value>> {
    let parameters_str = String::from_utf8(kernel_parameters.to_vec())?;
    debug!("kernel parameters: {parameters_str}");

    let parameters = parameters_str
        .split(&[' ', '\n', '\r', '\0'])
        .collect::<Vec<&str>>()
        .iter()
        .filter_map(|item| {
            if item.is_empty() {
                return None;
            }

            let it = item.split_once('=');

            match it {
                Some((k, v)) => Some((k.into(), v.into())),
                None => Some((item.to_string(), Value::Null)),
            }
        })
        .collect();

    Ok(parameters)
}
