# Sentinel Guard 🛡️

**Trust your Agent, but Verify the Transaction.**

Sentinel is a high-performance Rust security middleware designed for autonomous AI agents on Solana. It acts as a firewall between an agent's logic and its wallet, ensuring that every transaction aligns with human-defined safety policies before it's signed and broadcast.

## 🚀 The Core Problem
AI Agents are non-deterministic and susceptible to prompt injection. An attacker could trick an agent into:
- Draining its wallet to a malicious address.
- Delegating token authority to an attacker.
- Interacting with unverified or malicious programs.

## 🛠️ The Solution
Sentinel intercepts transaction requests, simulates them in a controlled environment, and evaluates the results against a robust policy engine.

### Key Features
- **Deterministic Policy Engine:** Whitelist programs, rate-limit transactions, and set global spend caps.
- **Simulation-Based Verification:** Inspects actual state changes (balance drops, authority shifts) instead of just static instruction data.
- **Human-in-the-Loop Override:** Built-in web dashboard for manual approval of "suspicious" but potentially valid transactions.
- **Audit Logging:** Every decision is persisted to an embedded `sled` database for full transparency.

## 🏗️ Architecture
1. **The Interceptor (Axum):** A high-speed Rust proxy that looks like a Solana RPC.
2. **The Simulation Core:** Integrates with Helius Simulation API to forecast the outcome of every instruction.
3. **The Policy Engine:** Executes a multi-stage check (Static -> Simulation -> Behavioral).
4. **The Dashboard:** A real-time monitoring and intervention UI.

## 🚦 Getting Started

### Prerequisites
- Rust (2024 edition)
- Helius API Key (for simulation)

### Installation
```bash
git clone https://github.com/ClawdieRS/sentinelguard
cd sentinelguard
cp .env.example .env # Add your HELIUS_API_KEY
cargo build --release
```

### Configuration (`config.toml`)
```toml
max_sol_per_tx = 1
max_balance_drain_lamports = 100000000 # 0.1 SOL
rate_limit_per_minute = 10
allowed_programs = [
    "11111111111111111111111111111111", # System Program
    "TokenkSzhZwpDfbvXPB9SSct59MSBhGUMCfX2LzXBe", # Token Program
    "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4" # Jupiter v6
]
simulation_checks_enabled = true
```

## 📊 Dashboard
Once running, the Sentinel dashboard is available at `http://localhost:3000/dashboard`. 
It provides real-time alerts for policy violations and a one-click "Allow/Reject" interface for pending approvals.

---
Built with 🦀 for the Colosseum Hackathon by **ClawdieLabs**.
