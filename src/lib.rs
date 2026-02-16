use axum::{
    Json, Router,
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
};
use base64::Engine as _;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tower_http::services::ServeDir;
use uuid::Uuid;

pub mod logger;
pub mod policy;
pub mod simulation;

use logger::{
    AuditEntry, AuditLogger, AuditResult, Decision, TransactionDetails, current_timestamp,
    hash_transaction_payload,
};
use policy::{MaxUnitsCheck, NoErrorCheck, Policy, PolicyEngine, SimulationCheck};
use simulation::{Simulate, SimulationResult};

#[derive(Clone, serde::Serialize)]
struct PendingApproval {
    #[serde(serialize_with = "serialize_tx")]
    transaction: solana_sdk::transaction::Transaction,
    simulation_result: SimulationResult,
    intent: Option<String>,
}

fn serialize_tx<S>(
    tx: &solana_sdk::transaction::Transaction,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    let bytes = bincode::serialize(tx).map_err(serde::ser::Error::custom)?;
    serializer.serialize_str(&base64::engine::general_purpose::STANDARD.encode(bytes))
}

#[derive(Clone)]
struct AppState {
    policy_engine: Arc<RwLock<PolicyEngine>>,
    simulator: Arc<dyn Simulate + Send + Sync>,
    logger: Arc<AuditLogger>,
    pending_approvals: Arc<RwLock<HashMap<String, PendingApproval>>>,
}

#[derive(serde::Deserialize)]
struct SimulateRequest {
    transaction: String,
    intent: Option<String>,
}

#[derive(serde::Deserialize)]
struct UpdatePolicyRequest {
    allowed_programs: Vec<String>,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum OverrideAction {
    Allow,
    Reject,
}

#[derive(serde::Deserialize)]
struct OverrideRequest {
    block_id: String,
    action: OverrideAction,
}

#[derive(serde::Serialize)]
struct ErrorResponse {
    error: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    block_id: Option<String>,
}

async fn hello() -> &'static str {
    "Hello, world!"
}

async fn update_policy(
    State(state): State<AppState>,
    Json(request): Json<UpdatePolicyRequest>,
) -> StatusCode {
    let mut policy_engine = state.policy_engine.write().await;
    policy_engine.update_allowed_programs(request.allowed_programs);
    StatusCode::OK
}

fn build_audit_entry(
    transaction_signature: Option<String>,
    decision: Decision,
    result: AuditResult,
    reasoning: String,
    simulation_result: Option<SimulationResult>,
    intent: Option<String>,
    transaction_details: Option<TransactionDetails>,
) -> AuditEntry {
    let simulation_logs = simulation_result
        .as_ref()
        .map(|result| result.logs.clone())
        .unwrap_or_default();
    let transaction_id = transaction_signature.clone().or_else(|| {
        transaction_details
            .as_ref()
            .and_then(|details| details.request_payload_base64.as_ref())
            .map(|payload| hash_transaction_payload(payload))
    });

    AuditEntry {
        timestamp: current_timestamp(),
        transaction_id,
        transaction_signature,
        decision,
        simulation_result,
        intent,
        result,
        reasoning,
        simulation_logs,
        transaction_details,
    }
}

async fn simulate(
    State(state): State<AppState>,
    Json(request): Json<SimulateRequest>,
) -> impl IntoResponse {
    let intent = request.intent.clone();
    let request_payload = request.transaction.clone();
    let request_details = TransactionDetails::from_request_payload(request_payload.clone());

    let tx_bytes = match base64::engine::general_purpose::STANDARD.decode(&request.transaction) {
        Ok(bytes) => bytes,
        Err(err) => {
            let reason = format!("Invalid base64 transaction: {err}");
            let entry = AuditEntry {
                transaction_signature: None,
                ..build_audit_entry(
                    None,
                    Decision::Blocked(reason.clone()),
                    AuditResult::Blocked,
                    reason.clone(),
                    None,
                    intent.clone(),
                    Some(request_details.clone()),
                )
            };
            let _ = state.logger.log(entry);
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: reason,
                    block_id: None,
                }),
            )
                .into_response();
        }
    };

    let tx: solana_sdk::transaction::Transaction = match bincode::deserialize(&tx_bytes) {
        Ok(tx) => tx,
        Err(err) => {
            let reason = format!("Invalid transaction payload: {err}");
            let entry = AuditEntry {
                transaction_signature: None,
                ..build_audit_entry(
                    None,
                    Decision::Blocked(reason.clone()),
                    AuditResult::Blocked,
                    reason.clone(),
                    None,
                    intent.clone(),
                    Some(request_details.clone()),
                )
            };
            let _ = state.logger.log(entry);
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: reason,
                    block_id: None,
                }),
            )
                .into_response();
        }
    };

    let tx_details = TransactionDetails::from_transaction_request(request_payload, &tx);
    let signature = tx_details.signature.clone();

    let policy_check = {
        let engine = state.policy_engine.read().await;
        engine.check_transaction(&tx)
    };

    if let Err(err) = policy_check {
        let entry = AuditEntry {
            ..build_audit_entry(
                signature.clone(),
                Decision::Blocked(err.clone()),
                AuditResult::Blocked,
                err.clone(),
                None,
                intent.clone(),
                Some(tx_details.clone()),
            )
        };
        let _ = state.logger.log(entry);

        return (
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: err,
                block_id: None,
            }),
        )
            .into_response();
    }

    let simulator = state.simulator.clone();
    let tx_clone = tx.clone();
    let spawn_result =
        tokio::task::spawn_blocking(move || simulator.simulate_transaction(&tx_clone)).await;

    let res = match spawn_result {
        Ok(r) => r,
        Err(err) => {
            let reason = format!("Simulation task failed: {err}");
            let entry = AuditEntry {
                ..build_audit_entry(
                    signature.clone(),
                    Decision::Blocked(reason.clone()),
                    AuditResult::Blocked,
                    reason.clone(),
                    None,
                    intent.clone(),
                    Some(tx_details.clone()),
                )
            };
            let _ = state.logger.log(entry);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: reason,
                    block_id: None,
                }),
            )
                .into_response();
        }
    };

    let result = match res {
        Ok(r) => r,
        Err(err) => {
            let reason = format!("Simulation failed: {err}");
            let entry = AuditEntry {
                ..build_audit_entry(
                    signature.clone(),
                    Decision::Blocked(reason.clone()),
                    AuditResult::Blocked,
                    reason.clone(),
                    None,
                    intent.clone(),
                    Some(tx_details.clone()),
                )
            };
            let _ = state.logger.log(entry);
            return (
                StatusCode::BAD_GATEWAY,
                Json(ErrorResponse {
                    error: reason,
                    block_id: None,
                }),
            )
                .into_response();
        }
    };

    let simulation_checks_enabled = {
        let engine = state.policy_engine.read().await;
        engine.simulation_checks_enabled()
    };

    if simulation_checks_enabled {
        let max_balance_drain = {
            let engine = state.policy_engine.read().await;
            engine.max_balance_drain_lamports()
        };

        let checks: Vec<Box<dyn SimulationCheck>> = if let Some(limit) = max_balance_drain {
            vec![
                Box::new(NoErrorCheck),
                Box::new(MaxUnitsCheck),
                Box::new(policy::MaxBalanceDrainCheck { limit }),
            ]
        } else {
            vec![Box::new(NoErrorCheck), Box::new(MaxUnitsCheck)]
        };

        for check in checks {
            if let Err(err) = check.check(&result) {
                let block_id = Uuid::new_v4().to_string();

                let entry = AuditEntry {
                    ..build_audit_entry(
                        signature.clone(),
                        Decision::PendingApproval(block_id.clone()),
                        AuditResult::Blocked,
                        err.clone(),
                        Some(result.clone()),
                        intent.clone(),
                        Some(tx_details.clone()),
                    )
                };
                let _ = state.logger.log(entry);

                let mut pending_approvals = state.pending_approvals.write().await;
                pending_approvals.insert(
                    block_id.clone(),
                    PendingApproval {
                        transaction: tx,
                        simulation_result: result.clone(),
                        intent,
                    },
                );

                return (
                    StatusCode::FORBIDDEN,
                    Json(ErrorResponse {
                        error: err,
                        block_id: Some(block_id),
                    }),
                )
                    .into_response();
            }
        }
    }

    let entry = AuditEntry {
        ..build_audit_entry(
            signature,
            Decision::Allowed,
            AuditResult::Allowed,
            "All policy and simulation checks passed".to_string(),
            Some(result.clone()),
            intent.clone(),
            Some(tx_details),
        )
    };
    let _ = state.logger.log(entry);

    Json(result).into_response()
}

async fn get_logs(State(state): State<AppState>) -> impl IntoResponse {
    match state.logger.get_logs() {
        Ok(logs) => Json(logs).into_response(),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("Failed to retrieve logs: {err}"),
                block_id: None,
            }),
        )
            .into_response(),
    }
}

async fn get_pending(State(state): State<AppState>) -> impl IntoResponse {
    let pending = state.pending_approvals.read().await;
    Json(pending.clone()).into_response()
}

async fn override_block(
    State(state): State<AppState>,
    Json(request): Json<OverrideRequest>,
) -> impl IntoResponse {
    let mut pending_approvals = state.pending_approvals.write().await;
    let pending = match pending_approvals.remove(&request.block_id) {
        Some(p) => p,
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: "Block ID not found".to_string(),
                    block_id: None,
                }),
            )
                .into_response();
        }
    };

    let tx_details = TransactionDetails::from_transaction(&pending.transaction);
    let signature = tx_details.signature.clone();

    match request.action {
        OverrideAction::Allow => {
            let reason = format!(
                "Approved by human override for block_id={}",
                request.block_id
            );
            let entry = AuditEntry {
                ..build_audit_entry(
                    signature,
                    Decision::Allowed,
                    AuditResult::Allowed,
                    reason,
                    Some(pending.simulation_result.clone()),
                    pending.intent,
                    Some(tx_details),
                )
            };
            let _ = state.logger.log(entry);
            Json(pending.simulation_result).into_response()
        }
        OverrideAction::Reject => {
            let reason = "Rejected by human override".to_string();
            let entry = AuditEntry {
                ..build_audit_entry(
                    signature,
                    Decision::Blocked(reason.clone()),
                    AuditResult::Blocked,
                    reason.clone(),
                    Some(pending.simulation_result),
                    pending.intent,
                    Some(tx_details),
                )
            };
            let _ = state.logger.log(entry);
            (
                StatusCode::FORBIDDEN,
                Json(ErrorResponse {
                    error: reason,
                    block_id: None,
                }),
            )
                .into_response()
        }
    }
}

pub fn build_app(
    policy: Policy,
    simulator: Arc<dyn Simulate + Send + Sync>,
    logger: Arc<AuditLogger>,
) -> Router {
    let app_state = AppState {
        policy_engine: Arc::new(RwLock::new(PolicyEngine::new(policy))),
        simulator,
        logger,
        pending_approvals: Arc::new(RwLock::new(HashMap::new())),
    };

    Router::new()
        .route("/", get(hello))
        .route("/simulate", post(simulate))
        .route("/logs", get(get_logs))
        .route("/pending", get(get_pending))
        .route("/policy", post(update_policy))
        .route("/override", post(override_block))
        .nest_service("/dashboard", ServeDir::new("static"))
        .with_state(app_state)
}
