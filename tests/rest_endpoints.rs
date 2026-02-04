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
    policy::Policy,
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
    }
}

fn test_policy(allowed_programs: Vec<String>) -> Policy {
    Policy {
        max_sol_per_tx: None,
        allowed_programs,
        blocked_addresses: vec![],
    }
}

fn test_app(allowed_programs: Vec<String>) -> (axum::Router, TempDir) {
    let tmp_dir = tempfile::tempdir().expect("temp dir");
    let db_path = tmp_dir.path().join("audit.sled");
    let logger = Arc::new(AuditLogger::new(db_path.to_str().expect("db path")).expect("logger"));
    let simulator: Arc<dyn Simulate + Send + Sync> = Arc::new(MockSimulator {
        result: mock_result(),
    });

    (
        build_app(test_policy(allowed_programs), simulator, logger),
        tmp_dir,
    )
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
async fn simulate_logs_allowed_transaction_and_exposes_it_via_logs_endpoint() {
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
}
