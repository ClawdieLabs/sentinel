use crate::simulation::SimulationResult;
use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};
use sled::Db;
use solana_sdk::hash::hash;
use solana_sdk::transaction::Transaction;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Decision {
    Allowed,
    Blocked(String),
    PendingApproval(String),
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "UPPERCASE")]
pub enum AuditResult {
    Allowed,
    #[default]
    Blocked,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TransactionDetails {
    pub request_payload_base64: Option<String>,
    pub signature: Option<String>,
    #[serde(default)]
    pub program_ids: Vec<String>,
    #[serde(default)]
    pub account_keys: Vec<String>,
}

impl TransactionDetails {
    pub fn from_request_payload(request_payload_base64: String) -> Self {
        Self {
            request_payload_base64: Some(request_payload_base64),
            signature: None,
            program_ids: vec![],
            account_keys: vec![],
        }
    }

    pub fn from_transaction_request(request_payload_base64: String, tx: &Transaction) -> Self {
        Self {
            request_payload_base64: Some(request_payload_base64),
            signature: tx.signatures.first().map(|sig| sig.to_string()),
            program_ids: tx
                .message
                .instructions
                .iter()
                .filter_map(|ix| {
                    tx.message
                        .account_keys
                        .get(usize::from(ix.program_id_index))
                        .map(|key| key.to_string())
                })
                .collect(),
            account_keys: tx
                .message
                .account_keys
                .iter()
                .map(|k| k.to_string())
                .collect(),
        }
    }

    pub fn from_transaction(tx: &Transaction) -> Self {
        Self {
            request_payload_base64: None,
            signature: tx.signatures.first().map(|sig| sig.to_string()),
            program_ids: tx
                .message
                .instructions
                .iter()
                .filter_map(|ix| {
                    tx.message
                        .account_keys
                        .get(usize::from(ix.program_id_index))
                        .map(|key| key.to_string())
                })
                .collect(),
            account_keys: tx
                .message
                .account_keys
                .iter()
                .map(|k| k.to_string())
                .collect(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub timestamp: u64,
    #[serde(default)]
    pub transaction_id: Option<String>,
    pub transaction_signature: Option<String>,
    pub decision: Decision,
    pub simulation_result: Option<SimulationResult>,
    pub intent: Option<String>,
    #[serde(default)]
    pub result: AuditResult,
    #[serde(default)]
    pub reasoning: String,
    #[serde(default)]
    pub simulation_logs: Vec<String>,
    #[serde(default)]
    pub transaction_details: Option<TransactionDetails>,
}

pub fn hash_transaction_payload(payload: &str) -> String {
    hash(payload.as_bytes()).to_string()
}

pub struct AuditLogger {
    db: Db,
}

impl AuditLogger {
    pub fn new(path: impl AsRef<Path>) -> Result<Self> {
        let db = sled::open(path).map_err(|e| anyhow!("Failed to open sled database: {}", e))?;
        Ok(Self { db })
    }

    pub fn log(&self, entry: AuditEntry) -> Result<()> {
        let key = self
            .db
            .generate_id()
            .map_err(|e| anyhow!("Failed to generate sled id: {}", e))?
            .to_be_bytes();
        let value = serde_json::to_vec(&entry)
            .map_err(|e| anyhow!("Failed to serialize audit entry: {}", e))?;

        self.db
            .insert(key, value)
            .map_err(|e| anyhow!("Failed to insert into sled: {}", e))?;

        self.db
            .flush()
            .map_err(|e| anyhow!("Failed to flush sled: {}", e))?;

        Ok(())
    }

    pub fn get_logs(&self) -> Result<Vec<AuditEntry>> {
        let mut logs = Vec::new();
        for item in self.db.iter() {
            let (_key, value) = item.map_err(|e| anyhow!("Sled iteration error: {}", e))?;
            let entry: AuditEntry = serde_json::from_slice(&value)
                .map_err(|e| anyhow!("Failed to deserialize audit entry: {}", e))?;
            logs.push(entry);
        }
        Ok(logs)
    }
}

pub fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs()
}
