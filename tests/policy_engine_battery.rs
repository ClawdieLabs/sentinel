use solana_sdk::{
    instruction::Instruction, message::Message, pubkey::Pubkey, signature::Keypair, signer::Signer,
    stake, system_program, transaction::Transaction,
};
use std::str::FromStr;

use sentinel::policy::{Policy, PolicyEngine};

fn dex_swap_program_id() -> Pubkey {
    Pubkey::from_str("JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4").expect("valid pubkey")
}

fn build_transaction(program_ids: &[Pubkey]) -> Transaction {
    let payer = Keypair::new();
    let instructions: Vec<Instruction> = program_ids
        .iter()
        .map(|program_id| Instruction {
            program_id: *program_id,
            accounts: vec![],
            data: vec![1, 2, 3],
        })
        .collect();

    let message = Message::new(&instructions, Some(&payer.pubkey()));
    Transaction::new_unsigned(message)
}

fn policy_with_allowed(program_ids: &[Pubkey]) -> Policy {
    Policy {
        max_sol_per_tx: None,
        allowed_programs: program_ids.iter().map(Pubkey::to_string).collect(),
        blocked_addresses: vec![],
        simulation_checks_enabled: true,
    }
}

#[test]
fn allows_dex_swap_transfer_and_stake_when_all_programs_are_whitelisted() {
    let dex_id = dex_swap_program_id();
    let transfer_id = system_program::id();
    let stake_id = stake::program::id();

    let engine = PolicyEngine::new(policy_with_allowed(&[dex_id, transfer_id, stake_id]));

    let dex_tx = build_transaction(&[dex_id]);
    let transfer_tx = build_transaction(&[transfer_id]);
    let stake_tx = build_transaction(&[stake_id]);

    assert!(engine.check_transaction(&dex_tx).is_ok());
    assert!(engine.check_transaction(&transfer_tx).is_ok());
    assert!(engine.check_transaction(&stake_tx).is_ok());
}

#[test]
fn blocks_dex_swap_when_dex_program_is_not_whitelisted() {
    let dex_id = dex_swap_program_id();
    let transfer_id = system_program::id();
    let stake_id = stake::program::id();

    let engine = PolicyEngine::new(policy_with_allowed(&[transfer_id, stake_id]));
    let dex_tx = build_transaction(&[dex_id]);

    let err = engine
        .check_transaction(&dex_tx)
        .expect_err("dex transaction should be blocked");
    assert!(err.contains(&dex_id.to_string()));
}

#[test]
fn blocks_transaction_when_any_instruction_uses_non_whitelisted_program() {
    let dex_id = dex_swap_program_id();
    let transfer_id = system_program::id();

    let engine = PolicyEngine::new(policy_with_allowed(&[transfer_id]));
    let mixed_tx = build_transaction(&[transfer_id, dex_id]);

    let err = engine
        .check_transaction(&mixed_tx)
        .expect_err("mixed transaction should be blocked");
    assert!(err.contains(&dex_id.to_string()));
}

#[test]
fn update_allowed_programs_unblocks_stake_transactions() {
    let transfer_id = system_program::id();
    let stake_id = stake::program::id();

    let mut engine = PolicyEngine::new(policy_with_allowed(&[transfer_id]));
    let stake_tx = build_transaction(&[stake_id]);

    assert!(engine.check_transaction(&stake_tx).is_err());

    engine.update_allowed_programs(vec![transfer_id.to_string(), stake_id.to_string()]);

    assert!(engine.check_transaction(&stake_tx).is_ok());
}
