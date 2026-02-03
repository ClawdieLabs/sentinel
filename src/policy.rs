use serde::Deserialize;

use solana_sdk::transaction::Transaction;

#[derive(Debug, Deserialize, Clone)]
pub struct Policy {
    pub max_sol_per_tx: Option<u64>,
    pub allowed_programs: Vec<String>,
    pub blocked_addresses: Vec<String>,
}

impl Policy {
    pub fn check_transaction(&self, _tx: &Transaction) -> Result<(), String> {
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct PolicyEngine {
    policy: Policy,
}

impl PolicyEngine {
    pub fn new(policy: Policy) -> Self {
        Self { policy }
    }

    pub fn check_transaction(&self, tx: &Transaction) -> Result<(), String> {
        self.policy.check_transaction(tx)
    }
}
