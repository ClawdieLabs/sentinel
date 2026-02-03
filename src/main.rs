use axum::{
    Json, Router,
    extract::State,
    http::StatusCode,
    routing::{get, post},
};
use base64::Engine as _;
use std::fs;
use std::sync::Arc;

mod policy;
mod simulation;

use policy::{Policy, PolicyEngine};
use simulation::{HeliusSimulator, Simulate, SimulationResult};
use tokio::signal;

#[derive(Clone)]
struct AppState {
    policy_engine: Arc<PolicyEngine>,
    simulator: Arc<HeliusSimulator>,
}

#[derive(serde::Deserialize)]
struct SimulateRequest {
    transaction: String,
}

#[derive(serde::Serialize)]
struct ErrorResponse {
    error: String,
}

async fn hello() -> &'static str {
    "Hello, world!"
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

    let tx: solana_sdk::transaction::Transaction = bincode::deserialize(&tx_bytes).map_err(
        |err| {
            (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: format!("Invalid transaction payload: {err}"),
                }),
            )
        },
    )?;

    state.policy_engine.check_transaction(&tx).map_err(|err| {
        (
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: err,
            }),
        )
    })?;

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

    Ok(Json(result))
}

async fn shutdown_signal() {
    let _ = signal::ctrl_c().await;
    eprintln!("shutdown signal received");
}

#[tokio::main]
async fn main() {
    let config_text = fs::read_to_string("config.toml").expect("read config.toml");
    let policy: Policy = toml::from_str(&config_text).expect("parse config.toml");
    let policy_engine = Arc::new(PolicyEngine::new(policy));
    let simulator = Arc::new(HeliusSimulator::new().expect("create Helius simulator"));
    let app_state = AppState {
        policy_engine,
        simulator,
    };

    let app = Router::new()
        .route("/", get(hello))
        .route("/simulate", post(simulate))
        .with_state(app_state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000")
        .await
        .expect("bind to port 3000");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .expect("server error");
}
