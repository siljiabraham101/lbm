# Architecture

## Layers

### 1) Storage
- CAS: content-addressed objects (sha256)
- Group snapshots: chain + derived state
- Wallet: buyer keys for purchased packages
- Ledger: append-only event log (optional)

### 2) Group chain
Per-group permissioned chain of signed blocks (proof-of-authority).
Tx types:
- genesis
- member_add / member_remove
- mint / transfer
- policy_update
- claim / retract
- offer_create / offer_revoke
- purchase
- grant

### 2.5) Token Economy
Configurable per-group token distribution:
- Member faucet (auto-mint on join)
- Claim rewards (tokens for knowledge)
- Transfer fees (basis points to treasury)
- Supply caps (total and per-account)

### 3) Context graph
Truth-maintenance flavored:
- claims (text + tags + evidence refs)
- retractions
Compilation produces deterministic context slices via latent-space ranking.

### 4) Secure P2P transport
Handshake:
- authenticate signing keys (Ed25519)
- exchange encryption pubkeys (X25519)
- derive per-session keys (HKDF-SHA256)
- encrypt frames (ChaCha20-Poly1305) with strict counters

### 5) Market layer
Public:
- offer announcements (signed)
Private:
- purchases and grants recorded in group chain
Delivery:
- encrypted package is public CAS object
- symmetric key is sealed to buyer X25519 pubkey

### 6) MCP-like local connector
Local stdio JSON-RPC interface for agents to:
- submit experience
- publish claims
- compile context
- create and purchase offers
