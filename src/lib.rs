use axum::{
    Json, Router,
    extract::State,
    http::StatusCode,
    routing::{get, post},
};
use base64::Engine as _;
use std::sync::Arc;
use tokio::sync::RwLock;

pub mod logger;
pub mod policy;
pub mod simulation;

use logger::{AuditEntry, AuditLogger, Decision, current_timestamp};
use policy::{Policy, PolicyEngine};
use simulation::{Simulate, SimulationResult};

#[derive(Clone)]
struct AppState {
    policy_engine: Arc<RwLock<PolicyEngine>>,
    simulator: Arc<dyn Simulate + Send + Sync>,
    logger: Arc<AuditLogger>,
}

#[derive(serde::Deserialize)]
struct SimulateRequest {
    transaction: String,
}

#[derive(serde::Deserialize)]
struct UpdatePolicyRequest {
    allowed_programs: Vec<String>,
}

#[derive(serde::Serialize)]
struct ErrorResponse {
    error: String,
}

async fn hello() -> &'static str {
    "Hello, world!"
}

async fn get_logs(
    State(state): State<AppState>,
) -> Result<Json<Vec<AuditEntry>>, (StatusCode, Json<ErrorResponse>)> {
    let logs = state.logger.get_logs().map_err(|err| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("Failed to retrieve logs: {err}"),
            }),
        )
    })?;
    Ok(Json(logs))
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
) -> Result<Json<SimulationResult>, (StatusCode, Json<ErrorResponse>)> {
    let tx_bytes = base64::engine::general_purpose::STANDARD
        .decode(request.transaction)
        .map_err(|err| {
            (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: format!("Invalid base64 transaction: {err}"),
                }),
            )
        })?;

    let tx: solana_sdk::transaction::Transaction =
        bincode::deserialize(&tx_bytes).map_err(|err| {
            (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: format!("Invalid transaction payload: {err}"),
                }),
            )
        })?;

    let signature = tx.signatures.first().map(|s| s.to_string());

    let policy_check = {
        let engine = state.policy_engine.read().await;
        engine.check_transaction(&tx)
    };

    if let Err(err) = &policy_check {
        let entry = AuditEntry {
            timestamp: current_timestamp(),
            transaction_signature: signature.clone(),
            decision: Decision::Blocked(err.clone()),
            simulation_result: None,
        };
        let _ = state.logger.log(entry);

        return Err((
            StatusCode::FORBIDDEN,
            Json(ErrorResponse { error: err.clone() }),
        ));
    }

    let simulator = state.simulator.clone();
    let result = tokio::task::spawn_blocking(move || simulator.simulate_transaction(&tx))
        .await
        .map_err(|err| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: format!("Simulation task failed: {err}"),
                }),
            )
        })?
        .map_err(|err| {
            (
                StatusCode::BAD_GATEWAY,
                Json(ErrorResponse {
                    error: format!("Simulation failed: {err}"),
                }),
            )
        })?;

    let entry = AuditEntry {
        timestamp: current_timestamp(),
        transaction_signature: signature,
        decision: Decision::Allowed,
        simulation_result: Some(result.clone()),
    };
    let _ = state.logger.log(entry);

    Ok(Json(result))
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
    };

    Router::new()
        .route("/", get(hello))
        .route("/simulate", post(simulate))
        .route("/logs", get(get_logs))
        .route("/policy", post(update_policy))
        .with_state(app_state)
}
