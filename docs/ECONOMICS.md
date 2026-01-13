# Economics (Token Dynamics)

Each knowledge group maintains an internal credit ledger with configurable token economics.

## Token Economy Features

### Member Faucet

New members automatically receive tokens when joining a group:

- Configured via `faucet_amount` in group policy
- Only granted to genuinely new members (not duplicates)
- Returning members (previously removed) receive faucet on rejoin
- Respects supply caps

### Claim Rewards

Knowledge contributors earn tokens for publishing claims:

- Configured via `claim_reward_amount` in group policy
- Block author receives reward for each claim transaction
- Incentivizes knowledge sharing
- Respects supply caps

### Transfer Fees

Transfers incur a percentage-based fee:

- Configured via `transfer_fee_bps` (basis points, 100 = 1%)
- Fee sent to treasury account (`__treasury__`)
- Maximum fee capped at 50% (5000 bps)
- Sender pays amount + fee

### Supply Caps

Token supply can be limited:

- `max_total_supply`: Cap on total tokens in circulation
- `max_account_balance`: Cap on individual account balance
- Supply cap can only be raised, never lowered below current supply
- Prevents minting/rewards when cap reached

## Policy Configuration

Admins can update policy via `policy_update` transaction:

```python
node.update_group_policy(group_id,
    faucet_amount=100,           # Tokens for new members
    claim_reward_amount=10,       # Tokens per claim
    transfer_fee_bps=250,         # 2.5% transfer fee
    max_total_supply=1_000_000,   # 1M token cap
    max_account_balance=10_000    # 10K per account cap
)
```

## Token Operations

### Minting

Credits can be minted by admins:

```python
{"type": "mint", "to": "pub_key", "amount": 100, "ts_ms": ...}
```

- Only admins can mint
- Respects `max_total_supply`
- Respects `max_account_balance` for recipient

### Transfers

```python
{"type": "transfer", "from": "pub_key", "to": "pub_key", "amount": 50, "ts_ms": ...}
```

- Sender must have balance >= amount + fee
- Fee (if any) sent to treasury
- Respects `max_account_balance` for recipient

## Offers and Purchases

An offer references an encrypted package. The seller defines:
- price
- splits (basis points) among recipients
- optional parent royalties (basis points to parent offer sellers)

On purchase:
- the buyer authorizes debiting their balance via a signature
- the chain applies distribution deterministically
- a sealed key is granted to the buyer (recorded on-chain)

## Total Supply Tracking

The group state tracks `total_supply`:

- Updated on mint, faucet, and claim rewards
- Used for supply cap enforcement
- Included in snapshots

## Security

- Integer overflow protection (MAX_TOKEN_VALUE = 2^63 - 1)
- Empty policy updates rejected
- Unknown policy keys rejected
- Transfer amount + fee overflow check

## Production Monetization

This repo provides the internal mechanics. Bridging to fiat is an integration:
- accept external payments
- mint credits to buyer pubkeys
- optionally redeem credits to off-chain payouts
