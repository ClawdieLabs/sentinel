---
name: sentinelguard
description: "High-performance Rust firewall for AI Agents. Intercepts, simulates, and validates transactions before signing."
homepage: "https://github.com/ClawdieLabs/sentinel"
metadata: {
  "category": "security",
  "emoji": "🛡️",
  "requires": {
    "bins": ["sentinelguard"]
  }
}
---

# SentinelGuard 🛡️

SentinelGuard is an autonomous security middleware that sits between an Agent's Brain and its Wallet.

## Installation

```bash
# Clone and build
git clone https://github.com/ClawdieLabs/sentinel.git
cd sentinel && cargo build --release
```

## Features
- **Transaction Simulation**: Uses Helius simulation API to predict balance changes.
- **Program Whitelisting**: Blocks unauthorized Program IDs.
- **Audit Logging**: Persistent history of all attempts via Sled DB.
- **REST API**: Dynamically update policies and fetch logs.

## Usage

Start the proxy:
```bash
./target/release/sentinel
```

Point your agent's RPC URL to `http://localhost:3000/simulate`.

## API Endpoints
- `POST /simulate`: Intercept and verify a transaction.
- `GET /logs`: Fetch audit history.
- `POST /policy`: Update allowed programs list.
