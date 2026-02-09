use axum::{
    extract::State,
    http::StatusCode,
    routing::{get, post},
    Json, Router,
    response::IntoResponse,
};
use base64::Engine as _;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

pub mod logger;
pub mod policy;
pub mod simulation;

use logger::{current_timestamp, AuditEntry, AuditLogger, Decision};
use policy::{MaxUnitsCheck, NoErrorCheck, Policy, PolicyEngine, SimulationCheck};
use simulation::{Simulate, SimulationResult};

#[derive(Clone)]
struct PendingApproval {
    transaction: solana_sdk::transaction::Transaction,
    simulation_result: SimulationResult,
    intent: Option<String>,
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

async fn simulate(
    State(state): State<AppState>,
    Json(request): Json<SimulateRequest>,
) -> impl IntoResponse {
    let intent = request.intent.clone();
    let tx_bytes = match base64::engine::general_purpose::STANDARD.decode(&request.transaction) {
        Ok(bytes) => bytes,
        Err(err) => {
            let entry = AuditEntry {
                timestamp: current_timestamp(),
                transaction_signature: None,
                decision: Decision::Blocked(format!("Invalid base64 transaction: {err}")),
                simulation_result: None,
                intent: intent.clone(),
            };
            let _ = state.logger.log(entry);
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: format!("Invalid base64 transaction: {err}"),
                    block_id: None,
                }),
            ).into_response();
        }
    };

    let tx: solana_sdk::transaction::Transaction = match bincode::deserialize(&tx_bytes) {
        Ok(tx) => tx,
        Err(err) => {
            let entry = AuditEntry {
                timestamp: current_timestamp(),
                transaction_signature: None,
                decision: Decision::Blocked(format!("Invalid transaction payload: {err}")),
                simulation_result: None,
                intent: intent.clone(),
            };
            let _ = state.logger.log(entry);
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: format!("Invalid transaction payload: {err}"),
                    block_id: None,
                }),
            ).into_response();
        }
    };

    let signature = tx.signatures.first().map(|s| s.to_string());

    let policy_check = {
        let engine = state.policy_engine.read().await;
        engine.check_transaction(&tx)
    };

    if let Err(err) = policy_check {
        let entry = AuditEntry {
            timestamp: current_timestamp(),
            transaction_signature: signature.clone(),
            decision: Decision::Blocked(err.clone()),
            simulation_result: None,
            intent: intent.clone(),
        };
        let _ = state.logger.log(entry);

        return (
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: err,
                block_id: None,
            }),
        ).into_response();
    }

    let simulator = state.simulator.clone();
    let tx_clone = tx.clone();
    let spawn_result = tokio::task::spawn_blocking(move || simulator.simulate_transaction(&tx_clone))
        .await;

    let res = match spawn_result {
        Ok(r) => r,
        Err(err) => {
            let reason = format!("Simulation task failed: {err}");
            let entry = AuditEntry {
                timestamp: current_timestamp(),
                transaction_signature: signature.clone(),
                decision: Decision::Blocked(reason.clone()),
                simulation_result: None,
                intent: intent.clone(),
            };
            let _ = state.logger.log(entry);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: reason,
                    block_id: None,
                }),
            ).into_response();
        }
    };

    let result = match res {
        Ok(r) => r,
        Err(err) => {
            let reason = format!("Simulation failed: {err}");
            let entry = AuditEntry {
                timestamp: current_timestamp(),
                transaction_signature: signature.clone(),
                decision: Decision::Blocked(reason.clone()),
                simulation_result: None,
                intent: intent.clone(),
            };
            let _ = state.logger.log(entry);
            return (
                StatusCode::BAD_GATEWAY,
                Json(ErrorResponse {
                    error: reason,
                    block_id: None,
                }),
            ).into_response();
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
            vec![
                Box::new(NoErrorCheck),
                Box::new(MaxUnitsCheck),
            ]
        };

        for check in checks {
            if let Err(err) = check.check(&result) {
                let block_id = Uuid::new_v4().to_string();

                let entry = AuditEntry {
                    timestamp: current_timestamp(),
                    transaction_signature: signature.clone(),
                    decision: Decision::PendingApproval(block_id.clone()),
                    simulation_result: Some(result.clone()),
                    intent: intent.clone(),
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
                ).into_response();
            }
        }
    }

    let entry = AuditEntry {
        timestamp: current_timestamp(),
        transaction_signature: signature,
        decision: Decision::Allowed,
        simulation_result: Some(result.clone()),
        intent: intent.clone(),
    };
    let _ = state.logger.log(entry);

    Json(result).into_response()
}

async fn get_logs(
    State(state): State<AppState>,
) -> impl IntoResponse {
    match state.logger.get_logs() {
        Ok(logs) => Json(logs).into_response(),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("Failed to retrieve logs: {err}"),
                block_id: None,
            }),
        ).into_response(),
    }
}

async fn override_block(
    State(state): State<AppState>,
    Json(request): Json<OverrideRequest>,
) -> impl IntoResponse {
    let mut pending_approvals = state.pending_approvals.write().await;
    let pending = match pending_approvals.remove(&request.block_id) {
        Some(p) => p,
        None => return (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Block ID not found".to_string(),
                block_id: None,
            }),
        ).into_response(),
    };

    let signature = pending.transaction.signatures.first().map(|s| s.to_string());

    match request.action {
        OverrideAction::Allow => {
            let entry = AuditEntry {
                timestamp: current_timestamp(),
                transaction_signature: signature,
                decision: Decision::Allowed,
                simulation_result: Some(pending.simulation_result.clone()),
                intent: pending.intent,
            };
            let _ = state.logger.log(entry);
            Json(pending.simulation_result).into_response()
        }
        OverrideAction::Reject => {
            let entry = AuditEntry {
                timestamp: current_timestamp(),
                transaction_signature: signature,
                decision: Decision::Blocked("Rejected by human override".to_string()),
                simulation_result: Some(pending.simulation_result),
                intent: pending.intent,
            };
            let _ = state.logger.log(entry);
            (
                StatusCode::FORBIDDEN,
                Json(ErrorResponse {
                    error: "Rejected by human override".to_string(),
                    block_id: None,
                }),
            ).into_response()
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
        .route("/policy", post(update_policy))
        .route("/override", post(override_block))
        .with_state(app_state)
}
