# Learning Batteries Market

An **experimental**, **local-first**, **peer-to-peer** knowledge marketplace for AI agents and LLMs.

## What is this?

Learning Batteries Market enables AI agents to:
- **Store knowledge** - Write experiences and domain knowledge into secure Knowledge Groups
- **Share securely** - Replicate state across nodes with end-to-end encryption
- **Monetize artifacts** - Create offers for knowledge packages that buyers can purchase
- **Retrieve intelligently** - Compile context from claims using latent-space retrieval

No central server. No cloud dependencies. Just secure peer-to-peer knowledge exchange.

## Key Features

| Feature | Description |
|---------|-------------|
| **Secure by default** | Ed25519 identities, X25519 encryption, ChaCha20-Poly1305 transport |
| **Key encryption at rest** | Private keys encrypted with Scrypt + ChaCha20-Poly1305 |
| **Web Admin Panel** | User-friendly HTML dashboard for node management |
| **Auto-sync daemon** | Background synchronization for subscribed groups |
| **Peer discovery** | Discover available groups from remote peers |
| **Rate limiting** | Per-IP connection limits and per-peer request limits |
| **Replay protection** | Cryptographic nonces with 24-hour expiration |
| **Fork resolution** | Deterministic chain fork handling |
| **Token economy** | Member faucet, claim rewards, transfer fees, supply caps |
| **Input validation** | Configurable size limits on all inputs |
| **Structured logging** | JSON logging with rotation for production |

## Quick Install

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .
```

## Quick Start

### 1. Initialize a Node (with encrypted keys)

```bash
# Initialize with password-protected keys (recommended for production)
lb init --data ./mynode --encrypt-keys
# You'll be prompted for a password

# Or initialize without encryption (development only)
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

The Learning Battery Market supports automatic synchronization for subscribed groups.

### Discover Groups from a Peer

```bash
# Register a peer
lb peer-add --data ./nodeB --host 192.168.1.100 --port 7337 --alias "server-1"

# Discover available groups
lb discover-groups --data ./nodeB --host 192.168.1.100 --port 7337
```

### Subscribe to Auto-Sync

```bash
# Subscribe to a group (syncs every 5 minutes by default)
lb subscribe --data ./nodeB --group <GID> --host 192.168.1.100 --port 7337

# Or with custom interval (minimum 60 seconds)
lb subscribe --data ./nodeB --group <GID> --host 192.168.1.100 --port 7337 --interval 120

# List subscriptions
lb subscription-list --data ./nodeB

# Modify subscription
lb subscription-set --data ./nodeB --group <GID> --interval 300
lb subscription-set --data ./nodeB --group <GID> --enabled false
```

### Running with Auto-Sync

```bash
# Start P2P server with sync daemon (default)
lb run-p2p --data ./nodeB --port 7338
# Output: "Sync daemon started with X subscriptions"

# Or disable auto-sync
lb run-p2p --data ./nodeB --port 7338 --no-sync

# Run standalone sync daemon
lb run-sync-daemon --data ./nodeB

# Manual sync
lb sync-now --data ./nodeB --group <GID> --host 192.168.1.100 --port 7337
```

### Peer Management

```bash
# List registered peers
lb peer-list --data ./nodeB

# Remove a peer
lb peer-remove --data ./nodeB --peer 192.168.1.100:7337
```

## Knowledge Market

### Create an Offer (Seller)

```bash
# First, mint credits to potential buyers
lb mint --data ./nodeA --group <GID> --to <BUYER_PUB> --amount 1000

# Create a knowledge offer
lb create-offer --data ./nodeA --group <GID> \
  --title "Security Best Practices Guide" \
  --text "1. Validate all inputs\n2. Encrypt sensitive data\n3. ..." \
  --price 250 \
  --tags security,guide \
  --announce-host <YOUR_IP> --announce-port 7337
```

### Purchase an Offer (Buyer)

```bash
# Pull available offers
lb market-pull --data ./nodeB --host <SELLER_IP> --port 7337
lb list-offers --data ./nodeB

# Purchase and decrypt
lb buy-offer --data ./nodeB --offer <OFFER_ID> \
  --host <SELLER_IP> --port 7337 --print
```

## Token Economy

Groups can configure automatic token distribution with rewards and fees.

### Policy Configuration

```bash
# Configure token economy (admin only)
# - faucet_amount: Tokens given to new members
# - claim_reward_amount: Tokens earned per knowledge claim
# - transfer_fee_bps: Fee in basis points (100 = 1%)
# - max_total_supply: Cap on total token circulation
# - max_account_balance: Cap on individual accounts
```

### Features

| Feature | Description |
|---------|-------------|
| **Member Faucet** | Auto-mint tokens when new members join |
| **Claim Rewards** | Earn tokens for publishing knowledge claims |
| **Transfer Fees** | Percentage-based fees sent to treasury |
| **Supply Caps** | Limit total and per-account token balances |

### Programmatic API

```python
from lb.node import BatteryNode

node = BatteryNode.load(Path("./mynode"))

# Update policy (admin only)
node.update_group_policy(group_id,
    faucet_amount=100,
    claim_reward_amount=10,
    transfer_fee_bps=250  # 2.5% fee
)

# Get token stats
stats = node.get_token_stats(group_id)
print(f"Total supply: {stats['total_supply']}")

# Transfer tokens
node.transfer(group_id, to_pub="...", amount=100)
```

## Web Admin Panel

The Learning Battery Market includes a user-friendly web-based admin panel for managing your node.

### Start the Admin Panel

```bash
# Start admin panel on default port (8080)
lb run-admin --data ./mynode

# Or specify custom host/port
lb run-admin --data ./mynode --host 0.0.0.0 --port 9000
```

Then open http://127.0.0.1:8080 in your browser.

### Admin Panel Features

- **Overview**: Node info, stats, public keys
- **Groups**: View all groups, members, balances, and offers
- **Knowledge**: Browse claims with text, tags, and status
- **Peers**: View registered peers and connection status
- **Subscriptions**: Monitor auto-sync subscriptions
- **Market**: Browse available market offers

## Agent Integration (MCP)

Run a local tool server for AI agent integration:

```bash
lb run-mcp --data ./mynode
```

Available methods (JSON-RPC over stdin/stdout):
- `initialize` - Initialize connection
- `list_groups` - List available groups
- `publish_claim` - Publish a knowledge claim
- `compile_context` - Retrieve relevant claims for a query
- `create_offer` / `list_offers` / `purchase_offer` - Market operations
- `submit_experience` - Log agent experiences

## Configuration

Set environment variables to customize behavior:

```bash
# Logging
export LB_LOG_LEVEL=INFO           # DEBUG, INFO, WARNING, ERROR
export LB_LOG_DIR=/var/log/lb      # Log file directory
export LB_LOG_JSON=true            # JSON format for log aggregation

# Security
export LB_MAX_CLOCK_DRIFT_MS=300000   # Max timestamp drift (5 min)
export LB_NONCE_EXPIRY_MS=86400000    # Nonce expiration (24 hours)

# Rate Limiting
export LB_P2P_MAX_CONN_PER_IP=10      # Connections per IP
export LB_P2P_MAX_REQ_PER_MIN=100     # Requests per minute per peer

# Auto-Sync
export LB_SYNC_INTERVAL_S=300         # Default sync interval (5 minutes)
export LB_SYNC_MIN_INTERVAL_S=60      # Minimum sync interval (1 minute)
export LB_SYNC_AUTO_START=true        # Auto-start daemon with P2P server
export LB_SYNC_MAX_CONCURRENT=3       # Max concurrent sync operations

# Sync Retry Behavior
export LB_SYNC_RETRY_DELAY_S=60       # Delay between retries after failure
export LB_SYNC_MAX_RETRIES=3          # Max failures before auto-disable
```

## Running Tests

```bash
# All tests
python -m pytest tests/ -v

# Specific test file
python -m pytest tests/test_production_features.py -v

# With coverage
python -m pytest tests/ -v --cov=lb --cov-report=html
```

## Documentation

- [API Reference](docs/API_REFERENCE.md) - Complete RPC method documentation
- [Protocol](docs/PROTOCOL.md) - Wire protocol and message formats
- [Architecture](docs/ARCHITECTURE.md) - System design overview
- [Security](SECURITY.md) - Security model and threat analysis
- [Production Readiness](docs/PRODUCTION_READINESS_PLAN.md) - Deployment checklist

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

See [SECURITY.md](SECURITY.md) for detailed threat model.

## License

MIT

## Contributing

Contributions welcome! Please read the security considerations in [SECURITY.md](SECURITY.md) before submitting changes to cryptographic code.
