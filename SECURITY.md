# Security

Learning Batteries Market implements defense-in-depth security with multiple layers of protection.

## Security Features Summary

| Layer | Protection | Implementation |
|-------|------------|----------------|
| Transport | End-to-end encryption | ChaCha20-Poly1305 AEAD |
| Identity | Mutual authentication | Ed25519 signatures |
| Key Exchange | Forward secrecy | X25519 ECDH + HKDF |
| Storage | Key encryption at rest | Scrypt KDF + ChaCha20-Poly1305 |
| Replay | Transaction replay prevention | Cryptographic nonces (24h expiry) |
| DoS | Rate limiting | Per-IP connections, per-peer requests |
| Input | Validation | Size limits, format validation |

## Threat Model

### Assumptions

- Peers can be malicious
- Network traffic can be observed and modified (MITM)
- Clocks are not synchronized across nodes
- Disk storage may be compromised

### In Scope

- Unauthorized access to knowledge groups
- Replay attacks on purchase transactions
- Identity spoofing
- Message tampering
- Denial of service via resource exhaustion

### Out of Scope

- Side-channel attacks on cryptographic operations
- Physical access to running nodes
- Compromise of the underlying OS

## Cryptographic Design

### Transport Security

All P2P communication uses authenticated encryption:

1. **Handshake** (Noise NK-like pattern):
   - Client sends ephemeral X25519 public key
   - Server responds with signed ephemeral key
   - Both derive session keys via HKDF-SHA256

2. **Session Encryption**:
   - ChaCha20-Poly1305 AEAD
   - Monotonic counters prevent replay/reordering
   - Separate keys for send/receive directions

3. **Frame Format**:
   - 4-byte length prefix (max 16MB)
   - Encrypted payload with authentication tag

### Identity and Authentication

- **Node Identity**: Ed25519 signing keypair
- **Encryption Key**: X25519 keypair for sealed delivery
- **Signatures**: All blocks and critical transactions are signed
- **Verification**: Signatures checked before state mutation

### Key Storage

Private keys can be encrypted at rest:

```
+------------------+
| Encrypted Key    |
+------------------+
| Magic: "LBKEY01" |
| Salt: 32 bytes   |
| Nonce: 12 bytes  |
| Ciphertext       |
| Auth Tag         |
+------------------+
```

- **KDF**: Scrypt (N=2^17, r=8, p=1, 32-byte output)
- **Cipher**: ChaCha20-Poly1305

### Usage

```bash
# Initialize with encrypted keys
lb init --data ./mynode --encrypt-keys

# Encrypt existing keys
lb encrypt-keys --data ./mynode

# Change key password
lb change-password --data ./mynode
```

## Replay Protection

### Purchase Transaction Nonces

Every purchase transaction requires a unique nonce:

- Minimum 32 hex characters
- Must be unique per buyer+offer pair
- Tracked in chain state with timestamp
- Expires after 24 hours (configurable)

```python
# Nonce format: buyer_pub + offer_id -> nonce
nonce_key = f"{buyer_pub}:{offer_id}"
```

### Transport-Level Replay

- Monotonic counters on each direction
- Counter overflow causes session termination
- Out-of-order packets rejected

## Rate Limiting

### Connection Limits

- Max connections per IP (default: 10)
- Memory-bounded IP tracking (max 1000 IPs)
- Automatic eviction of stale entries

### Request Limits

- Sliding window rate limiter
- Default: 100 requests/minute per peer
- Memory-bounded key tracking (max 10,000 keys)
- LRU eviction when limit reached

### Rate Limit Response

```json
{
  "error": {
    "code": "rate_limited",
    "message": "rate limit exceeded: 100/100 requests in 60.0s"
  }
}
```

## Input Validation

All user inputs are validated:

| Input | Limit | Validation |
|-------|-------|------------|
| Claim text | 64 KB | UTF-8, no null bytes |
| Offer title | 256 chars | UTF-8, printable |
| Offer description | 4 KB | UTF-8 |
| Tags | 20 max, 64 chars each | Alphanumeric + dashes |
| Group name | 128 chars | Alphanumeric + colons/dashes/underscores |
| Nonce | 32+ chars | Hex characters |

## Token Economy Security

The token economy includes multiple security measures:

### Integer Overflow Protection

- MAX_TOKEN_VALUE = 2^63 - 1 (safe int64 limit)
- All token operations check for overflow
- Transfer amount + fee overflow check

### Policy Update Validation

- Only admins can update policy
- Empty updates rejected
- Unknown policy keys rejected
- Fee bounds enforced (0-5000 bps = 0-50%)
- Supply cap cannot be lowered below current supply

### Faucet and Rewards

- Faucet only for genuinely new members (not duplicates)
- Rewards and faucet respect supply caps
- Account balance caps enforced

### Transfer Fees

- Fee capped at 50% (5000 basis points)
- Sender must have balance >= amount + fee
- Fees sent to treasury account

## Fork Resolution

Deterministic fork resolution prevents chain divergence:

1. **Primary**: Chain height (longer chain wins)
2. **Secondary**: Unique author count (more authors wins)
3. **Tertiary**: Total work sum
4. **Tie-break**: Lexicographic block ID comparison

Fork events are logged for monitoring.

## Timestamp Validation

- Block timestamps must be within 5 minutes of current time
- Blocks cannot have timestamps before parent block
- Offer expiration uses block timestamp (not local time)
- Prevents backdating attacks

## Access Control

### Group Membership

- Membership stored in chain state
- Three roles: `admin`, `member`, `viewer`
- Only admins can add/remove members
- Membership checked before data access

### CAS Object Visibility

- `public`: Accessible to all authenticated peers
- `group:<gid>`: Accessible only to group members

## Operational Security

### Logging

- Structured logging with configurable levels
- Sensitive data (keys, passwords) never logged
- JSON format available for SIEM integration
- Log rotation: 10MB max, 5 backups

### Recommended Production Settings

```bash
# Stricter rate limits
export LB_P2P_MAX_CONN_PER_IP=5
export LB_P2P_MAX_REQ_PER_MIN=60

# Enable JSON logging
export LB_LOG_JSON=true
export LB_LOG_DIR=/var/log/lb

# Shorter nonce expiry for sensitive deployments
export LB_NONCE_EXPIRY_MS=3600000  # 1 hour
```

### Deployment Checklist

- [ ] Use encrypted keys (`--encrypt-keys`)
- [ ] Set strong key password
- [ ] Enable log rotation
- [ ] Configure rate limits
- [ ] Restrict file permissions (keys directory: 700)
- [ ] Monitor for fork events
- [ ] Set up alerting on error logs

## Known Limitations

### Not Implemented

1. **HTLC for purchases**: Buyer pays before receiving key; no refund mechanism
2. **Transactional state**: Multi-operation sequences not atomic
3. **Hardware key storage**: Keys in memory during operation

### Mitigations

- For HTLC: Use trusted sellers or implement application-level escrow
- For state atomicity: Single-threaded operation mode available
- For key storage: Consider OS-level memory protection (mlock)

## Vulnerability Reporting

If you discover a security vulnerability:

1. Do NOT open a public issue
2. Email security details privately
3. Include reproduction steps
4. Allow reasonable time for fix before disclosure

## Admin Panel Security

The web admin panel (`lb run-admin`) implements security measures:

### CORS Policy

- CORS restricted to localhost origins only
- Strict matching prevents subdomain spoofing (e.g., `localhost.evil.com`)
- Allowed origins: `http://localhost`, `http://127.0.0.1` (with any port)

### Recommendations

- Only run admin panel on `127.0.0.1` (default)
- Use firewall rules if exposing to network (`--host 0.0.0.0`)
- Consider reverse proxy with authentication for remote access

## Sync Daemon Resilience

The sync daemon includes protections against unresponsive peers:

- **Retry Backoff**: Linear backoff (`retry_delay × failure_count`)
- **Auto-Disable**: Subscription disabled after `max_retries` consecutive failures
- **Prevents DoS**: Stops hammering unresponsive peers

```bash
# Configure retry behavior
export LB_SYNC_RETRY_DELAY_S=60   # Delay between retries
export LB_SYNC_MAX_RETRIES=3      # Max failures before disable
```

## Security Updates

See [CHANGELOG.md](CHANGELOG.md) for security-related changes.

### Recent Fixes (v0.4.1)

- **CORS Subdomain Spoofing**: Fixed vulnerability allowing `localhost.evil.com` bypass
- **Connection Race Condition**: Fixed P2P connection slot leak on rate limiter error
- **Sync Daemon Backoff**: Added retry backoff to prevent peer hammering
