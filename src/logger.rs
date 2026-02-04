use crate::simulation::SimulationResult;
use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};
use sled::Db;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Serialize, Deserialize)]
pub enum Decision {
    Allowed,
    Blocked(String),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuditEntry {
    pub timestamp: u64,
    pub transaction_signature: Option<String>,
    pub decision: Decision,
    pub simulation_result: Option<SimulationResult>,
}

pub struct AuditLogger {
    db: Db,
}

impl AuditLogger {
    pub fn new(path: &str) -> Result<Self> {
        let db = sled::open(path).map_err(|e| anyhow!("Failed to open sled database: {}", e))?;
        Ok(Self { db })
    }

    pub fn log(&self, entry: AuditEntry) -> Result<()> {
        let key = entry.timestamp.to_be_bytes();
        let value = serde_json::to_vec(&entry)
            .map_err(|e| anyhow!("Failed to serialize audit entry: {}", e))?;

        self.db
            .insert(key, value)
            .map_err(|e| anyhow!("Failed to insert into sled: {}", e))?;

        // Ensure data is persisted
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
