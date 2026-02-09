use anyhow::Result;
use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use base64::Engine as _;
use solana_sdk::{
    instruction::Instruction, message::Message, pubkey::Pubkey, signature::Keypair, signer::Signer,
    stake, system_program, transaction::Transaction,
};
use std::sync::Arc;
use tempfile::TempDir;
use tower::ServiceExt;

use sentinel::{
    build_app,
    logger::{AuditEntry, AuditLogger, Decision},
    policy::{MaxUnitsCheck, Policy},
    simulation::{ReturnData, Simulate, SimulationResult},
};

#[derive(Clone)]
struct MockSimulator {
    result: SimulationResult,
}

impl Simulate for MockSimulator {
    fn simulate_transaction(&self, _tx: &Transaction) -> Result<SimulationResult> {
        Ok(self.result.clone())
    }
}

fn build_transaction(program_id: Pubkey) -> Transaction {
    let payer = Keypair::new();
    let instruction = Instruction {
        program_id,
        accounts: vec![],
        data: vec![7, 7, 7],
    };
    let message = Message::new(&[instruction], Some(&payer.pubkey()));
    Transaction::new_unsigned(message)
}

fn encoded_transaction(program_id: Pubkey) -> String {
    let tx = build_transaction(program_id);
    let tx_bytes = bincode::serialize(&tx).expect("serialize tx");
    base64::engine::general_purpose::STANDARD.encode(tx_bytes)
}

fn mock_result() -> SimulationResult {
    SimulationResult {
        logs: vec!["simulated transaction".to_string()],
        units_consumed: Some(42_000),
        return_data: Some(ReturnData {
            data: "AQID".to_string(),
            encoding: "base64".to_string(),
            program_id: system_program::id().to_string(),
        }),
        error: None,
        balance_changes: std::collections::HashMap::new(),
    }
}

fn simulation_result_with_error() -> SimulationResult {
    SimulationResult {
        logs: vec!["simulated transaction".to_string()],
        units_consumed: Some(120_000),
        return_data: None,
        error: Some(serde_json::json!({
            "InstructionError": [0, {"Custom": 6001}]
        })),
        balance_changes: std::collections::HashMap::new(),
    }
}

fn simulation_result_with_units(units_consumed: u64) -> SimulationResult {
    SimulationResult {
        logs: vec!["simulated transaction".to_string()],
        units_consumed: Some(units_consumed),
        return_data: None,
        error: None,
        balance_changes: std::collections::HashMap::new(),
    }
}

fn simulation_result_with_drain(account: String, drain: u64) -> SimulationResult {
    let mut balance_changes = std::collections::HashMap::new();
    balance_changes.insert(account, -(drain as i64));
    SimulationResult {
        logs: vec!["simulated transaction".to_string()],
        units_consumed: Some(50_000),
        return_data: None,
        error: None,
        balance_changes,
    }
}

fn test_policy(
    allowed_programs: Vec<String>,
    simulation_checks_enabled: bool,
    max_balance_drain_lamports: Option<u64>,
) -> Policy {
    Policy {
        max_sol_per_tx: None,
        max_balance_drain_lamports,
        allowed_programs,
        blocked_addresses: vec![],
        simulation_checks_enabled,
    }
}

fn test_app_with_result_and_policy(
    policy: Policy,
    simulation_result: SimulationResult,
) -> (axum::Router, TempDir) {
    let tmp_dir = tempfile::tempdir().expect("temp dir");
    let db_path = tmp_dir.path().join("audit.sled");
    let logger = Arc::new(AuditLogger::new(db_path.to_str().expect("db path")).expect("logger"));
    let simulator: Arc<dyn Simulate + Send + Sync> = Arc::new(MockSimulator {
        result: simulation_result,
    });

    (build_app(policy, simulator, logger), tmp_dir)
}

fn test_app_with_result(
    allowed_programs: Vec<String>,
    simulation_result: SimulationResult,
) -> (axum::Router, TempDir) {
    test_app_with_result_and_policy(test_policy(allowed_programs, true, None), simulation_result)
}

fn test_app(allowed_programs: Vec<String>) -> (axum::Router, TempDir) {
    test_app_with_result(allowed_programs, mock_result())
}

fn json_request(path: &str, payload: serde_json::Value) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(path)
        .header("content-type", "application/json")
        .body(Body::from(payload.to_string()))
        .expect("request")
}

#[tokio::test]
async fn healthcheck_returns_hello_world() {
    let (app, _tmp_dir) = test_app(vec![]);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body bytes");
    assert_eq!(body, "Hello, world!");
}

#[tokio::test]
async fn simulate_rejects_invalid_base64_payload() {
    let (app, _tmp_dir) = test_app(vec![]);

    let response = app
        .oneshot(json_request(
            "/simulate",
            serde_json::json!({ "transaction": "not-base64" }),
        ))
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn policy_endpoint_allows_stake_after_update() {
    let transfer_id = system_program::id();
    let stake_id = stake::program::id();

    let (app, _tmp_dir) = test_app(vec![transfer_id.to_string()]);
    let stake_tx = encoded_transaction(stake_id);

    let before_update = app
        .clone()
        .oneshot(json_request(
            "/simulate",
            serde_json::json!({ "transaction": stake_tx.clone() }),
        ))
        .await
        .expect("response");
    assert_eq!(before_update.status(), StatusCode::FORBIDDEN);

    let update_response = app
        .clone()
        .oneshot(json_request(
            "/policy",
            serde_json::json!({
                "allowed_programs": [transfer_id.to_string(), stake_id.to_string()]
            }),
        ))
        .await
        .expect("response");
    assert_eq!(update_response.status(), StatusCode::OK);

    let after_update = app
        .oneshot(json_request(
            "/simulate",
            serde_json::json!({ "transaction": stake_tx }),
        ))
        .await
        .expect("response");
    assert_eq!(after_update.status(), StatusCode::OK);
}

#[tokio::test]
async fn simulate_logs_allowed_and_blocked_transactions() {
    let transfer_id = system_program::id();
    let (app, _tmp_dir) = test_app(vec![transfer_id.to_string()]);

    let simulate_response = app
        .clone()
        .oneshot(json_request(
            "/simulate",
            serde_json::json!({ "transaction": encoded_transaction(transfer_id) }),
        ))
        .await
        .expect("response");

    assert_eq!(simulate_response.status(), StatusCode::OK);
    let simulation_body = to_bytes(simulate_response.into_body(), usize::MAX)
        .await
        .expect("simulation bytes");
    let simulation: SimulationResult =
        serde_json::from_slice(&simulation_body).expect("simulation result");
    assert_eq!(simulation.units_consumed, Some(42_000));

    let blocked_response = app
        .clone()
        .oneshot(json_request(
            "/simulate",
            serde_json::json!({ "transaction": encoded_transaction(stake::program::id()) }),
        ))
        .await
        .expect("response");

    assert_eq!(blocked_response.status(), StatusCode::FORBIDDEN);

    let logs_response = app
        .oneshot(
            Request::builder()
                .uri("/logs")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(logs_response.status(), StatusCode::OK);
    let logs_body = to_bytes(logs_response.into_body(), usize::MAX)
        .await
        .expect("logs bytes");
    let logs: Vec<AuditEntry> = serde_json::from_slice(&logs_body).expect("audit entries");

    assert!(logs.iter().any(|entry| {
        matches!(entry.decision, Decision::Allowed)
            && entry
                .simulation_result
                .as_ref()
                .and_then(|r| r.units_consumed)
                == Some(42_000)
    }));
    assert!(
        logs.iter()
            .any(|entry| matches!(entry.decision, Decision::Blocked(_)))
    );
}

#[tokio::test]
async fn simulate_enforces_no_error_check_and_logs_failure() {
    let transfer_id = system_program::id();
    let (app, _tmp_dir) = test_app_with_result(
        vec![transfer_id.to_string()],
        simulation_result_with_error(),
    );

    let response = app
        .clone()
        .oneshot(json_request(
            "/simulate",
            serde_json::json!({ "transaction": encoded_transaction(transfer_id) }),
        ))
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("response bytes");
    let payload: serde_json::Value = serde_json::from_slice(&body).expect("error payload");
    let error = payload["error"].as_str().expect("error text");
    assert!(error.contains("Simulation error"));

    let logs_response = app
        .oneshot(
            Request::builder()
                .uri("/logs")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(logs_response.status(), StatusCode::OK);
    let logs_body = to_bytes(logs_response.into_body(), usize::MAX)
        .await
        .expect("logs bytes");
    let logs: Vec<AuditEntry> = serde_json::from_slice(&logs_body).expect("audit entries");

    assert!(logs.iter().any(|entry| {
        matches!(entry.decision, Decision::PendingApproval(_))
            && entry
                .simulation_result
                .as_ref()
                .and_then(|result| result.error.as_ref())
                .is_some()
    }));
}

#[tokio::test]
async fn simulate_enforces_max_units_check_and_logs_failure() {
    let transfer_id = system_program::id();
    let over_limit_units = MaxUnitsCheck::LIMIT + 1;
    let (app, _tmp_dir) = test_app_with_result(
        vec![transfer_id.to_string()],
        simulation_result_with_units(over_limit_units),
    );

    let response = app
        .clone()
        .oneshot(json_request(
            "/simulate",
            serde_json::json!({ "transaction": encoded_transaction(transfer_id) }),
        ))
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("response bytes");
    let payload: serde_json::Value = serde_json::from_slice(&body).expect("error payload");
    let error = payload["error"].as_str().expect("error text");
    assert!(error.contains("Simulation exceeded max units"));

    let logs_response = app
        .oneshot(
            Request::builder()
                .uri("/logs")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(logs_response.status(), StatusCode::OK);
    let logs_body = to_bytes(logs_response.into_body(), usize::MAX)
        .await
        .expect("logs bytes");
    let logs: Vec<AuditEntry> = serde_json::from_slice(&logs_body).expect("audit entries");

    assert!(logs.iter().any(|entry| {
        matches!(entry.decision, Decision::PendingApproval(_))
            && entry
                .simulation_result
                .as_ref()
                .and_then(|result| result.units_consumed)
                .is_some_and(|units| units > MaxUnitsCheck::LIMIT)
    }));
}

#[tokio::test]
async fn simulate_enforces_max_balance_drain_check() {
    let transfer_id = system_program::id();
    let limit = 1_000_000; // 1M lamports
    let drain = limit + 1;
    let account = Pubkey::new_unique().to_string();
    
    let policy = test_policy(vec![transfer_id.to_string()], true, Some(limit));
    let (app, _tmp_dir) = test_app_with_result_and_policy(
        policy,
        simulation_result_with_drain(account.clone(), drain),
    );

    let response = app
        .oneshot(json_request(
            "/simulate",
            serde_json::json!({ "transaction": encoded_transaction(transfer_id) }),
        ))
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body = to_bytes(response.into_body(), usize::MAX).await.expect("body");
    let payload: serde_json::Value = serde_json::from_slice(&body).expect("payload");
    assert!(payload["error"].as_str().unwrap().contains("balance drain"));
}

#[tokio::test]
async fn simulate_logs_intent_field() {
    let transfer_id = system_program::id();
    let intent = "Test Intent".to_string();
    let (app, _tmp_dir) = test_app(vec![transfer_id.to_string()]);

    let response = app
        .clone()
        .oneshot(json_request(
            "/simulate",
            serde_json::json!({
                "transaction": encoded_transaction(transfer_id),
                "intent": intent
            }),
        ))
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::OK);

    let logs_response = app
        .oneshot(
            Request::builder()
                .uri("/logs")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    let body = to_bytes(logs_response.into_body(), usize::MAX).await.expect("body");
    let logs: Vec<AuditEntry> = serde_json::from_slice(&body).expect("logs");
    
    assert!(logs.iter().any(|entry| entry.intent.as_ref() == Some(&intent)));
}

#[tokio::test]
async fn override_workflow_allows_blocked_transaction() {
    let transfer_id = system_program::id();
    let limit = 1_000_000;
    let drain = limit + 1;
    let account = Pubkey::new_unique().to_string();
    let intent = "drain me daddy".to_string();

    let policy = test_policy(vec![transfer_id.to_string()], true, Some(limit));
    let (app, _tmp_dir) = test_app_with_result_and_policy(
        policy,
        simulation_result_with_drain(account.clone(), drain),
    );

    // 1. Initial simulation should block and return block_id
    let response = app
        .clone()
        .oneshot(json_request(
            "/simulate",
            serde_json::json!({
                "transaction": encoded_transaction(transfer_id),
                "intent": intent
            }),
        ))
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body = to_bytes(response.into_body(), usize::MAX).await.expect("body");
    let payload: serde_json::Value = serde_json::from_slice(&body).expect("payload");
    let block_id = payload["block_id"].as_str().expect("block_id exists").to_string();

    // 2. Log should show PendingApproval
    let logs_response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/logs")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    let logs_body = to_bytes(logs_response.into_body(), usize::MAX).await.expect("body");
    let logs: Vec<AuditEntry> = serde_json::from_slice(&logs_body).expect("logs");
    assert!(logs.iter().any(|entry| {
        matches!(entry.decision, Decision::PendingApproval(ref id) if id == &block_id)
    }));

    // 3. Send ALLOW override
    let override_response = app
        .clone()
        .oneshot(json_request(
            "/override",
            serde_json::json!({
                "block_id": block_id,
                "action": "ALLOW"
            }),
        ))
        .await
        .expect("response");

    assert_eq!(override_response.status(), StatusCode::OK);
    let override_body = to_bytes(override_response.into_body(), usize::MAX).await.expect("body");
    let result: SimulationResult = serde_json::from_slice(&override_body).expect("simulation result");
    assert_eq!(result.balance_changes.get(&account), Some(&-(drain as i64)));

    // 4. Final log should show Allowed
    let logs_response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/logs")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    let logs_body = to_bytes(logs_response.into_body(), usize::MAX).await.expect("body");
    let logs: Vec<AuditEntry> = serde_json::from_slice(&logs_body).expect("logs");
    
    // We expect both the Pending and the Allowed entry
    assert!(logs.iter().any(|entry| matches!(entry.decision, Decision::Allowed)));
}

#[tokio::test]
async fn override_workflow_rejects_transaction() {
    let transfer_id = system_program::id();
    let (app, _tmp_dir) = test_app_with_result(
        vec![transfer_id.to_string()],
        simulation_result_with_error(),
    );

    let response = app
        .clone()
        .oneshot(json_request(
            "/simulate",
            serde_json::json!({ "transaction": encoded_transaction(transfer_id) }),
        ))
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body = to_bytes(response.into_body(), usize::MAX).await.expect("body");
    let payload: serde_json::Value = serde_json::from_slice(&body).expect("payload");
    let block_id = payload["block_id"].as_str().expect("block_id").to_string();

    let override_response = app
        .clone()
        .oneshot(json_request(
            "/override",
            serde_json::json!({
                "block_id": block_id,
                "action": "REJECT"
            }),
        ))
        .await
        .expect("response");

    assert_eq!(override_response.status(), StatusCode::FORBIDDEN);
    let body = to_bytes(override_response.into_body(), usize::MAX).await.expect("body");
    let payload: serde_json::Value = serde_json::from_slice(&body).expect("payload");
    assert_eq!(payload["error"], "Rejected by human override");
}

