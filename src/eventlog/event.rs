use std::str::FromStr;

use anyhow::{anyhow, bail, Context, Result};
use crypto::HashAlgorithm;
use sha2::{digest::FixedOutput, Digest, Sha256, Sha384, Sha512};
use serde_json::{Map, Value};
use serde::{Deserialize, Serialize};

#[derive(Clone)]
pub struct AAEvent {
    pub domain: String,
    pub operation: String,
    pub content: String,
}

impl FromStr for AAEvent {
    type Err = anyhow::Error;

    fn from_str(input: &str) -> Result<Self> {
        let input_trimed = input.trim_end();
        let sections: Vec<&str> = input_trimed.split(' ').collect();
        if sections.len() != 3 {
            bail!("Illegal AA event entry format. Should be `<domain> <operation> <content>`");
        }
        Ok(Self {
            domain: sections[0].into(),
            operation: sections[1].into(),
            content: sections[2].into(),
        })
    }
}

#[derive(Clone, Deserialize, Serialize)]
pub struct AAEventlog {
    pub hash_algorithm: HashAlgorithm,
    pub init_state: Vec<u8>,
    pub events: Vec<String>,
}

impl FromStr for AAEventlog {
    type Err = anyhow::Error;

    fn from_str(input: &str) -> Result<Self> {
        let all_lines = input.lines().collect::<Vec<&str>>();

        let (initline, eventlines) = all_lines
            .split_first()
            .ok_or(anyhow!("at least one line should be included in AAEL"))?;

        // Init line looks like
        // INIT sha256/0000000000000000000000000000000000000000000000000000000000000000
        let init_line_items = initline.split_ascii_whitespace().collect::<Vec<&str>>();
        if init_line_items.len() != 2 {
            bail!("Illegal INIT event record.");
        }

        if init_line_items[0] != "INIT" {
            bail!("INIT event should start with `INIT` key word");
        }

        let (hash_algorithm, init_state) = init_line_items[1].split_once('/').ok_or(
            anyhow!("INIT event should have `<sha-algorithm>/<init-PCR-value>` as content after `INIT`")
        )?;

        let hash_algorithm = HashAlgorithm::from_str(hash_algorithm)
            .context("parse Hash Algorithm in INIT entry")?;
        let init_state = hex::decode(init_state).context("parse init state in INIT entry")?;

        let events = eventlines
            .iter()
            .map(|line| line.trim_end().to_string())
            .collect();

        Ok(Self {
            events,
            hash_algorithm,
            init_state,
        })
    }
}

impl AAEventlog {
    fn accumulate_hash<D: Digest + FixedOutput>(&self) -> Vec<u8> {
        let mut state = self.init_state.clone();

        let mut init_event_hasher = D::new();
        let init_event = format!(
            "INIT {}/{}",
            self.hash_algorithm.as_ref(),
            hex::encode(&self.init_state),
        );
        
        Digest::update(&mut init_event_hasher, init_event.as_bytes());
        let init_event_hash = init_event_hasher.finalize();

        let mut hasher = D::new();
        Digest::update(&mut hasher, &state);
        Digest::update(&mut hasher, init_event_hash);
        state = hasher.finalize().to_vec();

        self.events.iter().for_each(|event| {
            let mut event_hasher = D::new();
            Digest::update(&mut event_hasher, event);
            let event_hash = event_hasher.finalize();

            let mut hasher = D::new();
            Digest::update(&mut hasher, &state);
            Digest::update(&mut hasher, event_hash);
            state = hasher.finalize().to_vec();
        });

        state
    }

    /// Check the integrity of the AAEL, and gets a digest. Return whether the rtmr is the same as the digest.
    pub fn integrity_check(&self, rtmr: &[u8]) -> bool {
        let result = match self.hash_algorithm {
            HashAlgorithm::Sha256 => self.accumulate_hash::<Sha256>(),
            HashAlgorithm::Sha384 => self.accumulate_hash::<Sha384>(),
            HashAlgorithm::Sha512 => self.accumulate_hash::<Sha512>(),
        };

        rtmr == result
    }

    pub fn to_parsed_claims(&self) -> Map<String, Value> {
        let mut aael = Map::new();
        for eventlog in &self.events {
            let aaevent = eventlog.parse::<AAEvent>().unwrap();
            let key = format!("{}/{}", aaevent.domain, aaevent.operation);
            let item = Value::String(aaevent.content.clone());
            match aael.get_mut(&key) {
                Some(value) => value
                    .as_array_mut()
                    .expect("Only array can be inserted")
                    .push(item),
                None => {
                    // This insertion will ensure the value in AAEL always be
                    // `Array`s. This will make `as_array_mut()` always result
                    // in `Some`.
                    aael.insert(key, Value::Array(vec![item]));
                }
            }
        }

        aael
    }
}