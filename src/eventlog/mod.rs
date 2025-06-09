use crate::BoxedAttester;

use std::{
    fmt::Display,
    fs::{File, OpenOptions},
    io::Write,
    path::Path,
    str::FromStr,
    sync::Arc,
};

use anyhow::{bail, Context, Result};

use const_format::concatcp;

use crypto::HashAlgorithm;
use event::AAEventlog;
use log::debug;

/// AA's eventlog will be put into this parent directory
pub const EVENTLOG_PARENT_DIR_PATH: &str = "/run/attestation-agent";

/// AA's eventlog will be stored inside the file
pub const EVENTLOG_PATH: &str = concatcp!(EVENTLOG_PARENT_DIR_PATH, "/eventlog");

pub struct EventLog {
    writer: Box<dyn Writer>,
    rtmr_extender: Arc<BoxedAttester>,
    alg: HashAlgorithm,
    pcr: u64,
}

trait Writer: Sync + Send {
    fn append(&mut self, entry: &LogEntry) -> Result<()>;
}

pub struct FileWriter {
    file: File,
}

impl Writer for FileWriter {
    fn append(&mut self, entry: &LogEntry) -> Result<()> {
        writeln!(self.file, "{entry}").context("failed to write log")?;
        self.file
            .flush()
            .context("failed to flush log to I/O media")?;
        Ok(())
    }
}

impl EventLog {
    pub async fn new(
        rtmr_extender: Arc<BoxedAttester>,
        alg: HashAlgorithm,
        pcr: u64,
    ) -> Result<Self> {
        tokio::fs::create_dir_all(EVENTLOG_PARENT_DIR_PATH)
            .await
            .context("create eventlog parent dir")?;
        if Path::new(EVENTLOG_PATH).exists() {
            debug!("Previous AAEL found. Skip INIT entry recording...");
            let content = tokio::fs::read_to_string(EVENTLOG_PATH)
                .await
                .context("Read AAEL")?;

            // The content of AAEL can be empty when the previous AA created this file
            // but did not do anything.
            if content.is_empty() {
                let file = File::open(EVENTLOG_PATH).context("open eventlog")?;
                let mut eventlog = Self {
                    writer: Box::new(FileWriter { file }),
                    rtmr_extender,
                    alg,
                    pcr,
                };
                eventlog
                    .extend_init_entry()
                    .await
                    .context("extend INIT entry")?;
                return Ok(eventlog);
            }

            let aael = AAEventlog::from_str(&content).context("Parse AAEL")?;
            let rtmr = rtmr_extender
                .get_runtime_measurement(pcr)
                .await
                .context("Get RTMR failed")?;

            // The integrity check might fail when previous AA record the entry into
            // aael but failed to extend RTMR. This check will try to catch this case
            // and do then unfinished RTMR extending.
            match aael.integrity_check(&rtmr) {
                true => debug!("Existing RTMR is consistent with current AAEL"),
                false => {
                    debug!(
                        "Existing RTMR is not consistent with current AAEL, do a RTMR extending..."
                    );
                    let digest = match aael.events.is_empty() {
                        true => alg.digest(
                            format!(
                                "INIT {}/{:0>width$}",
                                aael.hash_algorithm,
                                hex::encode(aael.init_state),
                                width = aael.hash_algorithm.digest_len(),
                            ).as_bytes()
                        ),
                        false => alg.digest(aael.events[0].as_bytes()),
                    };
                    rtmr_extender
                        .extend_runtime_measurement(digest, pcr)
                        .await
                        .context("Extend RTMR failed")?;
                }
            }

            let file = OpenOptions::new()
                .append(true)
                .open(EVENTLOG_PATH)
                .context("open eventlog")?;

            return Ok(Self {
                writer: Box::new(FileWriter { file }),
                rtmr_extender,
                alg,
                pcr,
            })
        }

        debug!("No AA eventlog exists, creating a new one and do INIT entry recording...");
        let file = File::create(EVENTLOG_PATH).context("create eventlog")?;
        let writer = Box::new(FileWriter { file });
        let mut eventlog = Self {
            writer,
            rtmr_extender,
            alg,
            pcr,
        };
        eventlog
            .extend_init_entry()
            .await
            .context("extend INIT entry")?;
        Ok(eventlog)
    }

    pub async fn extend_entry(&mut self, log_entry: LogEntry<'_>, pcr: u64) -> Result<()> {
        let digest = log_entry.digest_with(self.alg);
        // The order must be ensured to keep consistency. s.t. first write AAEL
        // and then extend RTMR.
        self.writer.append(&log_entry).context("write log entry")?;
        self.rtmr_extender
            .extend_runtime_measurement(digest, pcr)
            .await?;

        Ok(())
    }

    pub async fn extend_init_entry(&mut self) -> Result<()> {
        let pcr = self.rtmr_extender.get_runtime_measurement(self.pcr).await?;
        let init_value = hex::encode(pcr);
        let init_value = format!("{:0>width$}", init_value, width = self.alg.digest_len());
        let init_entry = LogEntry::Init {
            hash_alg: self.alg,
            value: &init_value,
        };

        let digest = init_entry.digest_with(self.alg);
        self.writer
            .append(&init_entry)
            .context("write INIT log entry")?;

        self.rtmr_extender
            .extend_runtime_measurement(digest, self.pcr)
            .await
            .context("write INIT entry")?;
        Ok(())
    }
}

pub struct Content<'a>(&'a str);

impl<'a> TryFrom<&'a str> for Content<'a> {
    type Error = anyhow::Error;

    fn try_from(value: &'a str) -> Result<Self, Self::Error> {
        if value.chars().any(|c| c == '\n') {
            bail!("content contains newline");
        }
        Ok(Content(value))
    }
}

pub enum LogEntry<'a> {
    Event {
        domain: &'a str,
        operation: &'a str,
        content: Content<'a>
    },
    Init {
        hash_alg: HashAlgorithm,
        value: &'a str,
    }
}

impl LogEntry<'_> {
    pub fn digest_with(&self, hash_alg: HashAlgorithm) -> Vec<u8> {
        let log_entry = self.to_string();
        hash_alg.digest(log_entry.as_bytes())
    }
}

impl Display for LogEntry<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LogEntry::Event {
                domain,
                operation,
                content,
            } => {
                write!(f, "{} {} {}", domain, operation, content.0)
            }
            LogEntry::Init { hash_alg, value } => {
                let (sha, init_value) = match hash_alg {
                    HashAlgorithm::Sha256 => ("sha256", value),
                    HashAlgorithm::Sha384 => ("sha384", value),
                    HashAlgorithm::Sha512 => ("sha512", value),
                };
                write!(f, "INIT {}/{}", sha, init_value)
            }
        }
    }
}
