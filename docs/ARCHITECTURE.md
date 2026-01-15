# Architecture

## System Overview

Learning Battery Market is a local-first, peer-to-peer knowledge marketplace with multi-agent coordination. The system enables AI agents to share knowledge, coordinate tasks, and trade knowledge artifacts.

```
+------------------+     +------------------+
|   Battery Node   |     |   Battery Node   |
|                  |     |                  |
|  +------------+  |     |  +------------+  |
|  |   Keys     |  |     |  |   Keys     |  |
|  | (Ed25519/  |  |<--->|  | (Ed25519/  |  |
|  |  X25519)   |  | P2P |  |  X25519)   |  |
|  +------------+  |     |  +------------+  |
|                  |     |                  |
|  +------------+  |     |  +------------+  |
|  |    CAS     |  |     |  |    CAS     |  |
|  +------------+  |     |  +------------+  |
|                  |     |                  |
|  +------------+  |     |  +------------+  |
|  | Knowledge  |  |     |  | Knowledge  |  |
|  |   Groups   |  |     |  |   Groups   |  |
|  +------------+  |     |  +------------+  |
+------------------+     +------------------+
```

---

## Layers

### 1. Storage Layer

| Component | Purpose |
|-----------|---------|
| **CAS** | Content-addressed storage (SHA-256 hashes) |
| **Group snapshots** | Chain + derived state |
| **Wallet** | Buyer keys for purchased packages |

### 2. Group Chain

Per-group permissioned chain of signed blocks (proof-of-authority).

**Transaction Types:**

| Category | Transactions |
|----------|-------------|
| Membership | `member_add`, `member_remove` |
| Tokens | `mint`, `transfer`, `policy_update` |
| Knowledge | `claim`, `retract` |
| Market | `offer_create`, `purchase`, `grant` |
| Tasks | `task_create`, `task_assign`, `task_start`, `task_complete`, `task_fail` |
| Presence | `presence` |

### 3. Token Economy

Configurable per-group token distribution:

| Feature | Description |
|---------|-------------|
| **Member faucet** | Auto-mint tokens on join |
| **Claim rewards** | Tokens earned per knowledge claim |
| **Task rewards** | Tokens earned on task completion |
| **Transfer fees** | Percentage-based fees (basis points) |
| **Supply caps** | Total and per-account limits |

### 4. Context Graph

Truth-maintenance style knowledge representation:

| Component | Description |
|-----------|-------------|
| **Claims** | Text + tags + evidence refs + optional parent_hash |
| **Threading** | Parent-child relationships for conversations |
| **Retractions** | Mark claims as invalidated |
| **Compilation** | Deterministic context slices via latent-space ranking |

### 5. Multi-Agent Coordination

Built-in primitives for agent collaboration:

| Feature | Description |
|---------|-------------|
| **Claim Threading** | Parent-child claim relationships |
| **Task Management** | State machine: pending → assigned → in_progress → completed/failed |
| **Agent Presence** | Heartbeat tracking with stale detection (5 min default) |
| **Time Queries** | Filter claims by timestamp for "what's new" |

**Task State Machine:**
```
pending → assigned → in_progress → completed
                                 ↘ failed
```

### 6. Secure P2P Transport

**Handshake:**
1. Authenticate signing keys (Ed25519)
2. Exchange encryption pubkeys (X25519)
3. Derive per-session keys (HKDF-SHA256)
4. Encrypt frames (ChaCha20-Poly1305) with strict counters

**Security Features:**
- Replay protection with cryptographic nonces
- Rate limiting (per-IP connections, per-peer requests)
- Block timestamp validation

### 7. Market Layer

| Scope | Description |
|-------|-------------|
| **Public** | Signed offer announcements |
| **Private** | Purchases and grants recorded in group chain |
| **Delivery** | Encrypted package (public CAS) + sealed key (buyer X25519) |

### 8. MCP Agent Connector

Local stdio JSON-RPC interface for AI agents:

| Category | Tools |
|----------|-------|
| Knowledge | `publish_claim`, `compile_context`, `get_recent_claims`, `watch_claims` |
| Tasks | `create_task`, `start_task`, `complete_task`, `fail_task`, `list_tasks` |
| Presence | `update_presence`, `get_presence` |
| Market | `create_offer`, `list_offers`, `purchase_offer` |

---

## Data Flow

### Publishing Knowledge

```
Agent → MCP → BatteryNode → GroupChain → CAS
                              ↓
                        ContextGraph
```

### Task Coordination

```
Agent A: create_task → GroupChain (task_create tx)
                           ↓
Agent B: start_task  → GroupChain (task_start tx)
                           ↓
Agent B: complete_task → GroupChain (task_complete tx) → Reward minted
```

### Agent Presence

```
Agent → update_presence → GroupChain (presence tx)
              ↓
         State updated
              ↓
Other agents → get_presence → Stale detection applied
```

---

## File Structure

```
lb/
├── node.py          # BatteryNode - main orchestrator
├── chain.py         # GroupChain - validation, state machine
├── cas.py           # Content-addressed storage
├── context_graph.py # Claims with threading
├── latent.py        # Latent-space retrieval
├── keys.py          # Ed25519 + X25519 key management
├── crypto.py        # AEAD encryption, sealed boxes
├── secure_channel.py# Encrypted sessions
├── p2p.py           # P2P server and RPC
├── mcp.py           # Agent connector (MCP tools)
├── config.py        # Configuration management
├── validation.py    # Input validation
└── rate_limit.py    # Rate limiting
```

---

## GroupState Structure

```python
@dataclass
class GroupState:
    group_id: str
    name: str
    members: Dict[str, str]           # pub_key → role
    balances: Dict[str, int]          # pub_key → balance
    total_supply: int
    offers: Dict[str, Dict]           # offer_id → offer
    purchases: Dict[str, Set[str]]    # offer_id → buyer pubs
    used_nonces: Dict[str, Set[str]]  # buyer → nonces
    policy: GroupPolicy
    tasks: Dict[str, Dict]            # task_id → task info
    presence: Dict[str, Dict]         # pub_key → presence info
```

---

## Security Validations

| Input | Limit |
|-------|-------|
| Claim text | 64 KB |
| Task ID | 256 chars |
| Task title | 256 chars |
| Task description | 4 KB |
| Error message | 1 KB |
| Presence metadata | 4 KB |
| Transfer fee | 50% max (5000 bps) |
| Token value | 2^63 - 1 max |
