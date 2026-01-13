# Learning Battery Market - API Reference

**Version**: 0.5.0

## Overview

The Learning Battery Market uses a custom RPC protocol over TCP with mutual authentication.
All communication is encrypted using ChaCha20-Poly1305 after a Noise-like handshake.

## Connection Flow

1. **TCP Connect**: Client connects to server `host:port`
2. **Handshake**: Noise NK pattern - client authenticates server, then server authenticates client
3. **RPC Calls**: JSON-RPC 2.0-style messages wrapped in length-prefixed frames
4. **Encryption**: All post-handshake messages are sealed with ChaCha20-Poly1305

## Request Format

```json
{
  "id": 1,
  "method": "method_name",
  "params": {
    "param1": "value1",
    "param2": "value2"
  }
}
```

## Response Format

```json
{
  "id": 1,
  "result": { ... },
  "error": null
}
```

## Error Response

```json
{
  "id": 1,
  "result": null,
  "error": {
    "code": "error_code",
    "message": "Human-readable error message"
  }
}
```

## Error Codes

| Code | Description |
|------|-------------|
| `not_found` | Resource not found (group, offer, object) |
| `forbidden` | Access denied (not a group member, buyer mismatch) |
| `bad_request` | Invalid request parameters |
| `rate_limited` | Rate limit exceeded |
| `rejected` | Transaction rejected by chain validation |
| `internal` | Internal server error |

---

## RPC Methods

### `ping`

Health check - verify server is responsive.

**Parameters**: None

**Response**:
```json
{
  "pong": true
}
```

---

### `health`

Detailed health check with node status.

**Parameters**: None

**Response**:
```json
{
  "status": "healthy",
  "node_id": "a1b2c3d4e5f6",
  "version": "0.2.0",
  "groups_count": 3,
  "offers_count": 15,
  "timestamp_ms": 1704067200000
}
```

---

### `node_info`

Get information about the connected node.

**Parameters**: None

**Response**:
```json
{
  "node_id": "a1b2c3d4e5f6",
  "sign_pub": "base64_encoded_ed25519_public_key",
  "enc_pub": "base64_encoded_x25519_public_key",
  "version": "0.2.0"
}
```

---

### `group_get_snapshot`

Get a group's chain snapshot. Requires group membership.

**Parameters**:
| Name | Type | Required | Description |
|------|------|----------|-------------|
| `group_id` | string | Yes | The group identifier |

**Response**:
```json
{
  "group_id": "group_abc123",
  "snapshot": {
    "genesis": { ... },
    "blocks": [ ... ],
    "state": {
      "group_id": "group_abc123",
      "name": "My Group",
      "members": { "pub_key": "admin", ... },
      "balances": { "pub_key": 1000, ... },
      "total_supply": 10000,
      "offers": { ... },
      "policy": {
        "name": "My Group",
        "currency": "KAT",
        "faucet_amount": 100,
        "claim_reward_amount": 10,
        "transfer_fee_bps": 250,
        "max_total_supply": 1000000,
        "max_account_balance": 10000
      }
    }
  }
}
```

**Errors**:
- `not_found`: Unknown group
- `forbidden`: Not a group member

---

### `cas_get`

Retrieve a content-addressed object by hash.

**Parameters**:
| Name | Type | Required | Description |
|------|------|----------|-------------|
| `hash` | string | Yes | SHA-256 hash of the object |

**Response**:
```json
{
  "hash": "sha256_hex_string",
  "data_b64": "base64_encoded_data",
  "meta": {
    "visibility": "public",
    "kind": "package",
    "group_id": "group_abc123",
    "created_ms": 1704067200000,
    "size": 1024
  }
}
```

**Errors**:
- `not_found`: Unknown object hash
- `forbidden`: Object visibility restricts access

**Access Control**:
- `public` objects: Accessible to anyone
- `group:<gid>` objects: Accessible only to group members

---

### `market_list_offers`

List all public offer announcements.

**Parameters**: None

**Response**:
```json
{
  "offers": [
    {
      "offer_id": "offer_abc123",
      "group_id": "group_xyz",
      "seller_sign_pub": "base64_ed25519_pub",
      "seller_enc_pub": "base64_x25519_pub",
      "host": "192.168.1.100",
      "port": 9001,
      "package_hash": "sha256_hex",
      "title": "ML Training Data",
      "tags": ["ml", "data", "training"],
      "price": 100,
      "currency": "KAT",
      "created_ms": 1704067200000,
      "expires_ms": 1704153600000,
      "sig": "base64_signature"
    }
  ]
}
```

---

### `market_announce_offers`

Announce new offers to the network. Signatures are verified.

**Parameters**:
| Name | Type | Required | Description |
|------|------|----------|-------------|
| `offers` | array | Yes | List of signed offer announcements |

**Request Example**:
```json
{
  "offers": [
    {
      "offer_id": "offer_abc123",
      "group_id": "group_xyz",
      "seller_sign_pub": "base64_ed25519_pub",
      "seller_enc_pub": "base64_x25519_pub",
      "host": "192.168.1.100",
      "port": 9001,
      "package_hash": "sha256_hex",
      "title": "ML Training Data",
      "tags": ["ml", "data"],
      "price": 100,
      "currency": "KAT",
      "created_ms": 1704067200000,
      "sig": "base64_signature"
    }
  ]
}
```

**Response**:
```json
{
  "imported": 1
}
```

**Notes**:
- Offers with invalid signatures are silently rejected
- Duplicate offers are ignored

---

### `market_purchase`

Purchase an offer from the seller.

**Parameters**:
| Name | Type | Required | Description |
|------|------|----------|-------------|
| `purchase_tx` | object | Yes | Signed purchase transaction |

**Purchase Transaction Format**:
```json
{
  "type": "purchase",
  "group_id": "group_xyz",
  "offer_id": "offer_abc123",
  "buyer": "buyer_sign_pub_b64",
  "buyer_enc_pub": "buyer_enc_pub_b64",
  "amount": 100,
  "nonce": "cryptographic_nonce_64_chars",
  "ts_ms": 1704067200000,
  "sig": "base64_signature"
}
```

**Response**:
```json
{
  "package_hash": "sha256_hex",
  "sealed_key": "base64_sealed_symmetric_key"
}
```

**Errors**:
- `forbidden`: Buyer identity mismatch with handshake
- `bad_request`: Missing or invalid fields
- `not_found`: Unknown group or offer
- `rejected`: Transaction rejected (insufficient balance, expired offer, replay attack)

**Security Notes**:
- `buyer` must match the authenticated peer identity from handshake
- `buyer_enc_pub` must match the peer's encryption public key
- `nonce` must be unique per buyer+offer pair (replay protection)
- Offer must not be expired

---

### `group_list_available`

Discover groups available on this peer. Used for group discovery before joining.

**Parameters**: None

**Response**:
```json
{
  "groups": [
    {
      "group_id": "group_abc123",
      "name": "research:ml",
      "currency": "KAT",
      "height": 42,
      "member_count": 5,
      "is_member": false,
      "offer_count": 3
    }
  ]
}
```

**Notes**:
- `is_member` indicates if the authenticated peer is a member of the group
- This method is public - no group membership required

---

### `peer_exchange`

Exchange peer information for gossip-based peer discovery.

**Parameters**:
| Name | Type | Required | Description |
|------|------|----------|-------------|
| `peers` | array | No | List of peer info to share |

**Request Example**:
```json
{
  "peers": [
    {
      "host": "192.168.1.50",
      "port": 7337,
      "node_id": "abc123def456",
      "sign_pub": "base64_ed25519_pub",
      "enc_pub": "base64_x25519_pub"
    }
  ]
}
```

**Response**:
```json
{
  "peers": [
    {
      "host": "10.0.0.100",
      "port": 7337,
      "node_id": "xyz789abc012",
      "sign_pub": "base64_ed25519_pub",
      "enc_pub": "base64_x25519_pub"
    }
  ]
}
```

**Notes**:
- Returns up to 50 known peers
- Facilitates decentralized peer discovery

---

### `sync_status`

Extended health check with per-group chain status. Used by sync daemon.

**Parameters**: None

**Response**:
```json
{
  "node_id": "a1b2c3d4e5f6",
  "sign_pub": "base64_ed25519_pub",
  "enc_pub": "base64_x25519_pub",
  "groups": {
    "group_abc123": {
      "height": 42,
      "head_hash": "sha256_hex_block_id"
    },
    "group_xyz789": {
      "height": 17,
      "head_hash": "sha256_hex_block_id"
    }
  },
  "timestamp_ms": 1704067200000
}
```

**Notes**:
- Used by sync daemon to determine if groups need synchronization
- Compare `height` and `head_hash` with local state

---

## Data Types

### Offer

```json
{
  "offer_id": "string (16 hex chars)",
  "group_id": "string",
  "seller": "base64_ed25519_pub",
  "package_hash": "sha256_hex",
  "title": "string (max 256 chars)",
  "description": "string (max 4096 chars)",
  "tags": ["string (max 64 chars)", ...],
  "price": 100,
  "currency": "KAT",
  "splits": [
    {"pub": "base64_pub", "bps": 10000}
  ],
  "parents": [],
  "active": true,
  "created_ms": 1704067200000,
  "expires_ms": 1704153600000
}
```

### Block

```json
{
  "group_id": "string",
  "height": 1,
  "prev_id": "sha256_hex",
  "block_id": "sha256_hex",
  "author": "base64_ed25519_pub",
  "sig": "base64_signature",
  "ts_ms": 1704067200000,
  "txs": [
    {"type": "claim", "artifact_hash": "sha256_hex", "ts_ms": 1704067200000}
  ]
}
```

### Transaction Types

| Type | Description | Required Fields |
|------|-------------|-----------------|
| `member_add` | Add group member | `pub`, `role`, `ts_ms` |
| `member_remove` | Remove member | `pub`, `ts_ms` |
| `mint` | Mint tokens | `to`, `amount`, `ts_ms` |
| `transfer` | Transfer tokens | `from`, `to`, `amount`, `ts_ms` |
| `claim` | Publish claim | `artifact_hash`, `ts_ms` |
| `retract` | Retract claim | `claim_hash`, `ts_ms` |
| `experience` | Submit experience | `artifact_hash`, `ts_ms` |
| `offer_create` | Create offer | `offer`, `ts_ms` |
| `offer_deactivate` | Deactivate offer | `offer_id`, `ts_ms` |
| `purchase` | Purchase offer | `offer_id`, `buyer`, `amount`, `nonce`, `ts_ms`, `sig` |
| `grant` | Grant access | `offer_id`, `buyer`, `package_hash`, `sealed_key`, `ts_ms` |
| `policy_update` | Update group policy | `updates` (dict), `ts_ms` |

---

## Rate Limiting

The server enforces rate limits to prevent abuse:

| Limit | Default | Description |
|-------|---------|-------------|
| Connections per IP | 10 | Maximum concurrent connections |
| Requests per minute | 100 | Per-peer request limit (sliding window) |
| Max tracked IPs | 1000 | Memory-bounded IP tracking |
| Max tracked keys | 10000 | Memory-bounded peer tracking |

Rate limiters use LRU eviction when memory bounds are reached.

When rate limited, the server responds with:
```json
{
  "error": {
    "code": "rate_limited",
    "message": "rate limit exceeded: 100/100 requests in 60.0s"
  }
}
```

---

## Authentication

All connections use mutual authentication:

1. **Client authenticates server**: Server proves identity with Ed25519 signature
2. **Server authenticates client**: Client proves identity with Ed25519 signature
3. **Session key**: X25519 Diffie-Hellman derives shared secret
4. **Encryption**: ChaCha20-Poly1305 AEAD for all messages

The authenticated peer identity (Ed25519 public key) is used for:
- Group membership verification
- Purchase transaction buyer validation
- Per-peer rate limiting

---

## CLI Commands

### Node Management
```bash
lb init --data ./mynode                    # Initialize a new node
lb info --data ./mynode                    # Show node info
```

### P2P Server
```bash
lb run-p2p --data ./mynode --port 7337     # Start P2P server with sync daemon
lb run-p2p --data ./mynode --no-sync       # Start without sync daemon
```

### Admin Panel
```bash
lb run-admin --data ./mynode               # Start web admin at http://127.0.0.1:8080
lb run-admin --data ./mynode --port 9000   # Custom port
lb run-admin --data ./mynode --host 0.0.0.0 --port 8080  # Expose to network
```

### Groups
```bash
lb create-group --data ./mynode --name "research:ml"
lb list-groups --data ./mynode
lb add-member --data ./mynode --group GID --pub PUB_KEY --role member
```

### Knowledge
```bash
lb publish-claim --data ./mynode --group GID --text "..." --tags tag1,tag2
lb compile-context --data ./mynode --group GID --query "search terms" --top-k 8
```

### Peer Management
```bash
lb peer-add --data ./mynode --host 192.168.1.100 --port 7337 --alias "server-1"
lb peer-list --data ./mynode
lb peer-remove --data ./mynode --peer 192.168.1.100:7337
```

### Group Discovery
```bash
lb discover-groups --data ./mynode --host 192.168.1.100 --port 7337
```

### Subscriptions (Auto-Sync)
```bash
lb subscribe --data ./mynode --group GID --host 192.168.1.100 --port 7337 --interval 300
lb unsubscribe --data ./mynode --group GID
lb subscription-list --data ./mynode
lb subscription-set --data ./mynode --group GID --interval 600
lb subscription-set --data ./mynode --group GID --enabled false
```

### Manual Sync
```bash
lb sync-now --data ./mynode --group GID --host 192.168.1.100 --port 7337
lb run-sync-daemon --data ./mynode         # Run standalone sync daemon
```

### Market
```bash
lb create-offer --data ./mynode --group GID --title "..." --text "..." --price 100
lb list-offers --data ./mynode
lb market-pull --data ./mynode --host 192.168.1.100 --port 7337
lb buy-offer --data ./mynode --offer OID --host 192.168.1.100 --port 7337 --print
```

---

## Version History

| Version | Changes |
|---------|---------|
| 0.5.0 | Token economy: member faucet, claim rewards, transfer fees, supply caps, `policy_update` transaction |
| 0.4.1 | Security fixes: CORS subdomain spoofing, connection race condition, sync daemon retry backoff |
| 0.4.0 | Auto-sync daemon, peer registry, subscription management, group discovery (`group_list_available`, `peer_exchange`, `sync_status`) |
| 0.3.0 | Security hardening: memory-bounded rate limiting, network timeouts, block timestamp validation |
| 0.2.0 | Added health endpoint, rate limiting, offer expiration, key encryption |
| 0.1.0 | Initial release |
