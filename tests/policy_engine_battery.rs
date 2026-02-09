use solana_sdk::{
    instruction::{AccountMeta, Instruction},
    message::Message,
    pubkey::Pubkey,
    signature::Keypair,
    signer::Signer,
    stake, system_instruction, system_program,
    transaction::Transaction,
};
use std::str::FromStr;

use sentinel::policy::{Policy, PolicyEngine};

fn dex_swap_program_id() -> Pubkey {
    Pubkey::from_str("JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4").expect("valid pubkey")
}

fn build_transaction(instructions: Vec<Instruction>) -> Transaction {
    let payer = Keypair::new();
    let message = Message::new(&instructions, Some(&payer.pubkey()));
    Transaction::new_unsigned(message)
}

fn jupiter_swap_transaction() -> Transaction {
    let payer = Keypair::new();
    let authority = payer.pubkey();
    let instruction = Instruction {
        program_id: dex_swap_program_id(),
        accounts: vec![
            AccountMeta::new(authority, true),
            AccountMeta::new_readonly(Pubkey::new_unique(), false),
            AccountMeta::new(Pubkey::new_unique(), false),
        ],
        data: vec![9, 9, 9, 1],
    };
    let message = Message::new(&[instruction], Some(&authority));
    Transaction::new_unsigned(message)
}

fn system_transfer_transaction() -> Transaction {
    let payer = Keypair::new();
    let recipient = Pubkey::new_unique();
    build_transaction(vec![system_instruction::transfer(
        &payer.pubkey(),
        &recipient,
        1_500_000,
    )])
}

fn stake_delegate_transaction() -> Transaction {
    let authority = Keypair::new();
    let stake_account = Pubkey::new_unique();
    let vote_account = Pubkey::new_unique();
    build_transaction(vec![stake::instruction::delegate_stake(
        &stake_account,
        &authority.pubkey(),
        &vote_account,
    )])
}

fn stake_deactivate_transaction() -> Transaction {
    let authority = Keypair::new();
    let stake_account = Pubkey::new_unique();
    build_transaction(vec![stake::instruction::deactivate_stake(
        &stake_account,
        &authority.pubkey(),
    )])
}

fn policy_with_allowed(program_ids: &[Pubkey]) -> Policy {
    Policy {
        max_sol_per_tx: None,
        max_balance_drain_lamports: None,
        allowed_programs: program_ids.iter().map(Pubkey::to_string).collect(),
        blocked_addresses: vec![],
        simulation_checks_enabled: true,
    }
}

#[test]
fn allows_jupiter_transfer_and_stake_instructions_when_all_programs_are_whitelisted() {
    let dex_id = dex_swap_program_id();
    let transfer_id = system_program::id();
    let stake_id = stake::program::id();

    let engine = PolicyEngine::new(policy_with_allowed(&[dex_id, transfer_id, stake_id]));

    let battery = vec![
        ("jupiter-swap", jupiter_swap_transaction()),
        ("system-transfer", system_transfer_transaction()),
        ("stake-delegate", stake_delegate_transaction()),
        ("stake-deactivate", stake_deactivate_transaction()),
    ];

    for (name, tx) in battery {
        assert!(
            engine.check_transaction(&tx).is_ok(),
            "expected {name} to be allowed"
        );
    }
}

#[test]
fn blocks_jupiter_swap_when_dex_program_is_not_whitelisted() {
    let dex_id = dex_swap_program_id();
    let transfer_id = system_program::id();
    let stake_id = stake::program::id();

    let engine = PolicyEngine::new(policy_with_allowed(&[transfer_id, stake_id]));
    let dex_tx = jupiter_swap_transaction();

    let err = engine
        .check_transaction(&dex_tx)
        .expect_err("dex transaction should be blocked");
    assert!(err.contains(&dex_id.to_string()));
}

#[test]
fn blocks_system_transfer_when_system_program_is_not_whitelisted() {
    let dex_id = dex_swap_program_id();
    let stake_id = stake::program::id();
    let transfer_id = system_program::id().to_string();

    let engine = PolicyEngine::new(policy_with_allowed(&[dex_id, stake_id]));
    let transfer_tx = system_transfer_transaction();

    let err = engine
        .check_transaction(&transfer_tx)
        .expect_err("transfer should be blocked");
    assert!(err.contains(&transfer_id));
}

#[test]
fn blocks_stake_instruction_when_stake_program_is_not_whitelisted() {
    let dex_id = dex_swap_program_id();
    let transfer_id = system_program::id();
    let stake_id = stake::program::id().to_string();

    let engine = PolicyEngine::new(policy_with_allowed(&[dex_id, transfer_id]));
    let stake_tx = stake_delegate_transaction();

    let err = engine
        .check_transaction(&stake_tx)
        .expect_err("stake transaction should be blocked");
    assert!(err.contains(&stake_id));
}

#[test]
fn blocks_mixed_transaction_if_any_instruction_program_is_not_whitelisted() {
    let transfer_id = system_program::id();
    let engine = PolicyEngine::new(policy_with_allowed(&[transfer_id]));

    let mixed_tx = build_transaction(vec![
        system_instruction::transfer(&Pubkey::new_unique(), &Pubkey::new_unique(), 5_000),
        Instruction {
            program_id: dex_swap_program_id(),
            accounts: vec![AccountMeta::new_readonly(Pubkey::new_unique(), false)],
            data: vec![1, 2, 3],
        },
    ]);

    let err = engine
        .check_transaction(&mixed_tx)
        .expect_err("mixed transaction should be blocked");
    assert!(err.contains(&dex_swap_program_id().to_string()));
}

#[test]
fn update_allowed_programs_unblocks_stake_transactions() {
    let transfer_id = system_program::id();
    let stake_id = stake::program::id();

    let mut engine = PolicyEngine::new(policy_with_allowed(&[transfer_id]));
    let stake_tx = stake_delegate_transaction();

    assert!(engine.check_transaction(&stake_tx).is_err());

    engine.update_allowed_programs(vec![transfer_id.to_string(), stake_id.to_string()]);

    assert!(engine.check_transaction(&stake_tx).is_ok());
}
