use crate::simulation::SimulationResult;
use serde::Deserialize;

use solana_sdk::transaction::Transaction;

#[derive(Debug, Deserialize, Clone)]
pub struct Policy {
    pub max_sol_per_tx: Option<u64>,
    pub max_balance_drain_lamports: Option<u64>,
    pub allowed_programs: Vec<String>,
    pub blocked_addresses: Vec<String>,
    #[serde(default)]
    pub simulation_checks_enabled: bool,
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

pub trait SimulationCheck: Send + Sync {
    fn check(&self, result: &SimulationResult) -> Result<(), String>;
}

#[derive(Debug, Clone, Copy)]
pub struct NoErrorCheck;

impl SimulationCheck for NoErrorCheck {
    fn check(&self, result: &SimulationResult) -> Result<(), String> {
        if let Some(err) = &result.error {
            return Err(format!("Simulation error: {err}"));
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
pub struct MaxUnitsCheck;

impl MaxUnitsCheck {
    pub const LIMIT: u64 = 200_000;
}

impl SimulationCheck for MaxUnitsCheck {
    fn check(&self, result: &SimulationResult) -> Result<(), String> {
        let units = result
            .units_consumed
            .ok_or_else(|| "Simulation missing units consumed".to_string())?;

        if units > Self::LIMIT {
            return Err(format!(
                "Simulation exceeded max units: {} > {}",
                units, Self::LIMIT
            ));
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
pub struct MaxBalanceDrainCheck {
    pub limit: u64,
}

impl SimulationCheck for MaxBalanceDrainCheck {
    fn check(&self, result: &SimulationResult) -> Result<(), String> {
        for (account, change) in &result.balance_changes {
            if *change < 0 {
                let drain = change.abs() as u64;
                if drain > self.limit {
                    return Err(format!(
                        "Account {} balance drain {} exceeds limit {}",
                        account, drain, self.limit
                    ));
                }
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

    pub fn simulation_checks_enabled(&self) -> bool {
        self.policy.simulation_checks_enabled
    }

    pub fn max_balance_drain_lamports(&self) -> Option<u64> {
        self.policy.max_balance_drain_lamports
    }
}
