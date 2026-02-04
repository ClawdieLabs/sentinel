use serde::Deserialize;

use solana_sdk::transaction::Transaction;

#[derive(Debug, Deserialize, Clone)]
pub struct Policy {
    pub max_sol_per_tx: Option<u64>,
    pub allowed_programs: Vec<String>,
    pub blocked_addresses: Vec<String>,
}

impl Policy {
    pub fn check_transaction(&self, tx: &Transaction) -> Result<(), String> {
        for instruction in &tx.message.instructions {
            let program_id_index = usize::from(instruction.program_id_index);
            let program_id = tx
                .message
                .account_keys
                .get(program_id_index)
                .ok_or_else(|| format!("Invalid program_id_index: {}", program_id_index))?;
            let program_id_str = program_id.to_string();

            if !self.allowed_programs.is_empty()
                && !self
                    .allowed_programs
                    .iter()
                    .any(|allowed_program| allowed_program == &program_id_str)
            {
                return Err(format!("Program not allowed: {}", program_id));
            }
        }

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

    pub fn update_allowed_programs(&mut self, allowed_programs: Vec<String>) {
        self.policy.allowed_programs = allowed_programs;
    }
}
