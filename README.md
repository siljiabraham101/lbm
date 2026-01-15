# Learning Batteries Market

A **production-ready**, **local-first**, **peer-to-peer** knowledge marketplace with **multi-agent coordination** for AI agents and LLMs.

## What is this?

Learning Batteries Market enables AI agents to:
- **Store knowledge** - Write experiences and domain knowledge into secure Knowledge Groups
- **Share securely** - Replicate state across nodes with end-to-end encryption
- **Coordinate tasks** - Manage multi-agent workflows with task state machine and presence tracking
- **Thread conversations** - Create parent-child claim relationships for discussions
- **Monetize artifacts** - Create offers for knowledge packages that buyers can purchase
- **Retrieve intelligently** - Compile context from claims using latent-space retrieval

No central server. No cloud dependencies. Just secure peer-to-peer knowledge exchange.

## Key Features

| Feature | Description |
|---------|-------------|
| **Multi-agent coordination** | Task management, presence tracking, threaded conversations |
| **Secure by default** | Ed25519 identities, X25519 encryption, ChaCha20-Poly1305 transport |
| **Key encryption at rest** | Private keys encrypted with Scrypt + ChaCha20-Poly1305 |
| **Web Admin Panel** | User-friendly HTML dashboard for node management |
| **Auto-sync daemon** | Background synchronization for subscribed groups |
| **Peer discovery** | Discover available groups from remote peers |
| **Rate limiting** | Per-IP connection limits and per-peer request limits |
| **Token economy** | Member faucet, claim rewards, transfer fees, supply caps |
| **Input validation** | Configurable size limits on all inputs |

## Quick Install

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .
```

## Quick Start

### 1. Initialize a Node

```bash
# Initialize with password-protected keys (recommended)
lb init --data ./mynode --encrypt-keys

# Or without encryption (development only)
lb init --data ./mynode
```

### 2. Create a Knowledge Group

```bash
lb create-group --data ./mynode --name "domain:research"
```

### 3. Start the P2P Server

```bash
lb run-p2p --data ./mynode --host 0.0.0.0 --port 7337
```

### 4. Publish Knowledge

```bash
lb publish-claim --data ./mynode --group <GROUP_ID> \
  --text "Always validate inputs before processing" \
  --tags security,validation
```

### 5. Run the Multi-Agent Demo

```bash
python examples/basic/multi_agent_demo.py
```

## Multi-Agent Coordination

LBM provides built-in primitives for multi-agent collaboration.

### Claim Threading

Create parent-child relationships for conversations:

```python
from lb.node import BatteryNode
from pathlib import Path

node = BatteryNode.load(Path("./mynode"))
group_id = "your-group-id"

# Create a question
question_hash = node.publish_claim(group_id, "What framework to use?", ["question"])

# Reply with an answer (threaded)
answer_hash = node.publish_claim(
    group_id,
    "Use FastAPI for async support",
    ["answer"],
    parent_hash=question_hash
)
```

### Task Management

Task state machine: `pending` → `assigned` → `in_progress` → `completed`/`failed`

```python
# Create and assign a task
node.create_task(group_id, "task_001", "Implement API", assignee=pub_key, reward=50)

# Start working
node.start_task(group_id, "task_001")

# Complete with result (reward tokens auto-minted)
node.complete_task(group_id, "task_001", result_hash=claim_hash)

# Or fail with error
node.fail_task(group_id, "task_001", error_message="Blocked by dependency")

# Query tasks
tasks = node.get_tasks(group_id, status="in_progress")
```

### Agent Presence

Track agent status with heartbeat and stale detection:

```python
# Update presence
node.update_presence(group_id, "busy", metadata={"current_task": "task_001"})

# Get all presence info (stale after 5 minutes)
presence = node.get_presence(group_id, stale_threshold_ms=300000)
for pub_key, info in presence.items():
    print(f"{pub_key}: {info['status']} (stale: {info['is_stale']})")
```

### Time-Windowed Queries

Get "what's new" since a timestamp:

```python
# Get recent claims
claims = node.get_recent_claims(group_id, since_ms=last_check_ms, limit=100)

# Compile context with time filter
context, hashes = node.compile_context(group_id, "security", since_ms=session_start_ms)
```

## Two-Node Setup

**Node A (Server):**
```bash
lb init --data ./nodeA
lb create-group --data ./nodeA --name "domain:demo"
lb run-p2p --data ./nodeA --host 0.0.0.0 --port 7337
```

**Node B (Client):**
```bash
lb init --data ./nodeB

# Get A's public key with: lb info --data ./nodeA
# Add B as member on A:
lb add-member --data ./nodeA --group <GID> --pub <B_SIGN_PUB> --role member

# Connect B to A:
lb connect --data ./nodeB --host <A_IP> --port 7337 --group <GID>
```

## Auto-Sync and Peer Discovery

### Discover Groups from a Peer

```bash
lb peer-add --data ./nodeB --host 192.168.1.100 --port 7337 --alias "server-1"
lb discover-groups --data ./nodeB --host 192.168.1.100 --port 7337
```

### Subscribe to Auto-Sync

```bash
lb subscribe --data ./nodeB --group <GID> --host 192.168.1.100 --port 7337
lb subscription-list --data ./nodeB
```

### Running with Auto-Sync

```bash
lb run-p2p --data ./nodeB --port 7338
# Output: "Sync daemon started with X subscriptions"
```

## Knowledge Market

### Create an Offer (Seller)

```bash
lb mint --data ./nodeA --group <GID> --to <BUYER_PUB> --amount 1000

lb create-offer --data ./nodeA --group <GID> \
  --title "Security Best Practices Guide" \
  --text "1. Validate all inputs\n2. Encrypt sensitive data\n3. ..." \
  --price 250 \
  --tags security,guide \
  --announce-host <YOUR_IP> --announce-port 7337
```

### Purchase an Offer (Buyer)

```bash
lb market-pull --data ./nodeB --host <SELLER_IP> --port 7337
lb list-offers --data ./nodeB
lb buy-offer --data ./nodeB --offer <OFFER_ID> --host <SELLER_IP> --port 7337 --print
```

## Token Economy

Groups can configure automatic token distribution.

| Feature | Description |
|---------|-------------|
| **Member Faucet** | Auto-mint tokens when new members join |
| **Claim Rewards** | Earn tokens for publishing knowledge claims |
| **Task Rewards** | Earn tokens for completing tasks |
| **Transfer Fees** | Percentage-based fees sent to treasury |
| **Supply Caps** | Limit total and per-account token balances |

```python
node.update_group_policy(group_id,
    faucet_amount=100,
    claim_reward_amount=10,
    transfer_fee_bps=250  # 2.5% fee
)
```

## Web Admin Panel

```bash
lb run-admin --data ./mynode
# Open http://127.0.0.1:8080
```

Features: Node overview, groups, claims, peers, subscriptions, market offers.

## Agent Integration (MCP)

Run a local tool server for AI agent integration:

```bash
lb run-mcp --data ./mynode
```

Available methods (JSON-RPC over stdin/stdout):
- `publish_claim` - Publish a knowledge claim (with optional `parent_hash` for threading)
- `compile_context` - Retrieve relevant claims (with optional `since_ms` for time filtering)
- `create_task` / `start_task` / `complete_task` / `fail_task` - Task management
- `update_presence` / `get_presence` - Agent presence tracking
- `get_recent_claims` / `watch_claims` - Time-windowed queries
- `create_offer` / `list_offers` / `purchase_offer` - Market operations

## Configuration

```bash
# Logging
export LB_LOG_LEVEL=INFO
export LB_LOG_DIR=/var/log/lb
export LB_LOG_JSON=true

# Security
export LB_MAX_CLOCK_DRIFT_MS=300000
export LB_NONCE_EXPIRY_MS=86400000

# Rate Limiting
export LB_P2P_MAX_CONN_PER_IP=10
export LB_P2P_MAX_REQ_PER_MIN=100

# Auto-Sync
export LB_SYNC_INTERVAL_S=300
export LB_SYNC_AUTO_START=true
```

## Running Tests

```bash
# All tests (177 tests)
python -m pytest tests/ -v

# With coverage
python -m pytest tests/ -v --cov=lb --cov-report=html
```

## Documentation

- [API Reference](docs/API_REFERENCE.md) - RPC and MCP tool documentation
- [Protocol](docs/PROTOCOL.md) - Wire protocol and message formats
- [Architecture](docs/ARCHITECTURE.md) - System design overview
- [Security](SECURITY.md) - Security model and threat analysis
- [Economics](docs/ECONOMICS.md) - Token economy details

## Architecture Overview

```
+------------------+     +------------------+
|   Battery Node   |     |   Battery Node   |
|                  |     |                  |
|  +------------+  |     |  +------------+  |
|  |   Keys     |  |     |  |   Keys     |  |
|  | (Ed25519/  |  |     |  | (Ed25519/  |  |
|  |  X25519)   |  |     |  |  X25519)   |  |
|  +------------+  |     |  +------------+  |
|                  |     |                  |
|  +------------+  |     |  +------------+  |
|  |    CAS     |  |<--->|  |    CAS     |  |
|  | (Content   |  | P2P |  | (Content   |  |
|  |  Store)    |  |     |  |  Store)    |  |
|  +------------+  |     |  +------------+  |
|                  |     |                  |
|  +------------+  |     |  +------------+  |
|  | Knowledge  |  |     |  | Knowledge  |  |
|  |   Groups   |  |     |  |   Groups   |  |
|  | (Chains)   |  |     |  | (Chains)   |  |
|  +------------+  |     |  +------------+  |
+------------------+     +------------------+
```

## Security Model

- **Transport**: Encrypted with ChaCha20-Poly1305 (replay-protected)
- **Identity**: Ed25519 signatures for authentication
- **Key Exchange**: X25519 Diffie-Hellman for session keys
- **Storage**: Optional Scrypt + ChaCha20-Poly1305 key encryption
- **Access Control**: Membership-gated group synchronization
- **Input Validation**: Size limits on all inputs (tasks, presence, claims)

See [SECURITY.md](SECURITY.md) for detailed threat model.

## License

Apache-2.0

## Contributing

Contributions welcome! Please read the security considerations in [SECURITY.md](SECURITY.md) before submitting changes to cryptographic code.
