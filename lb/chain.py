from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from .canonical import canonical_json, sha256_hex, hash_obj
from .keys import b64d, b64e, verify_detached, load_sign_pub_raw, sign_detached
from .config import get_config


TREASURY = "__TREASURY__"


def _get_max_clock_drift_ms() -> int:
    """Get max clock drift from config."""
    return get_config().chain.max_clock_drift_ms


def _get_nonce_expiry_ms() -> int:
    """Get nonce expiry from config."""
    return get_config().chain.nonce_expiry_ms


def _get_min_nonce_length() -> int:
    """Get minimum nonce length from config."""
    return get_config().chain.min_nonce_length


def _get_max_block_size_bytes() -> int:
    """Get maximum block size from config."""
    return get_config().chain.max_block_size_bytes


def _get_max_txs_per_block() -> int:
    """Get maximum transactions per block from config."""
    return get_config().chain.max_txs_per_block


# Maximum token value to prevent integer overflow (safe int64 limit)
MAX_TOKEN_VALUE = 2**63 - 1


class ChainError(Exception):
    pass


def _can_mint(policy, total_supply: int, amount: int) -> bool:
    """Check if minting is allowed under supply caps.

    Args:
        policy: GroupPolicy object with max_total_supply
        total_supply: Current total supply
        amount: Amount to mint

    Returns:
        True if minting is allowed
    """
    if amount <= 0:
        return False
    if total_supply + amount > MAX_TOKEN_VALUE:
        return False
    if policy.max_total_supply is not None:
        if total_supply + amount > policy.max_total_supply:
            return False
    return True


def _check_account_cap(policy, current_balance: int, amount: int) -> bool:
    """Check if account can receive amount under account cap.

    Args:
        policy: GroupPolicy object with max_account_balance
        current_balance: Current account balance
        amount: Amount to add

    Returns:
        True if receiving is allowed
    """
    if policy.max_account_balance is None:
        return True
    new_balance = current_balance + amount
    if new_balance > MAX_TOKEN_VALUE:
        return False
    return new_balance <= policy.max_account_balance


@dataclass
class Offer:
    offer_id: str
    group_id: str
    seller: str  # seller signing pub (b64)
    package_hash: str
    title: str
    description: str
    tags: List[str]
    price: int
    currency: str
    splits: List[Dict[str, Any]]  # [{pub,bps}]
    parents: List[Dict[str, Any]]  # [{offer_id,bps}] -> pay parent seller
    active: bool = True
    created_ms: int = 0
    expires_ms: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "offer_id": self.offer_id,
            "group_id": self.group_id,
            "seller": self.seller,
            "package_hash": self.package_hash,
            "title": self.title,
            "description": self.description,
            "tags": list(self.tags),
            "price": int(self.price),
            "currency": self.currency,
            "splits": list(self.splits),
            "parents": list(self.parents),
            "active": bool(self.active),
            "created_ms": int(self.created_ms),
            "expires_ms": self.expires_ms,
        }

    @staticmethod
    def from_dict(d: Dict[str, Any]) -> "Offer":
        return Offer(
            offer_id=str(d["offer_id"]),
            group_id=str(d["group_id"]),
            seller=str(d["seller"]),
            package_hash=str(d["package_hash"]),
            title=str(d.get("title", "")),
            description=str(d.get("description", "")),
            tags=list(d.get("tags", [])),
            price=int(d.get("price", 0)),
            currency=str(d.get("currency", "KAT")),
            splits=list(d.get("splits", [])),
            parents=list(d.get("parents", [])),
            active=bool(d.get("active", True)),
            created_ms=int(d.get("created_ms", 0)),
            expires_ms=d.get("expires_ms"),
        )


@dataclass
class GroupPolicy:
    name: str
    currency: str = "KAT"
    # Token economy fields
    faucet_amount: int = 0           # Tokens minted to new members
    claim_reward_amount: int = 0     # Tokens earned per claim
    transfer_fee_bps: int = 0        # Transfer fee in basis points (100 = 1%)
    max_total_supply: Optional[int] = None   # None = unlimited
    max_account_balance: Optional[int] = None # None = unlimited


@dataclass
class GroupState:
    group_id: str
    policy: GroupPolicy
    admins: set[str]
    members: set[str]
    balances: Dict[str, int]
    offers: Dict[str, Offer]
    grants: Dict[str, Dict[str, Any]]  # key = f"{offer_id}:{buyer_pub}" -> grant dict
    processed_nonces: Dict[str, int]  # nonce_key -> timestamp_ms for replay prevention with expiry
    total_supply: int = 0  # Track total tokens in circulation
    tasks: Dict[str, Dict[str, Any]] = None  # task_id -> task data
    presence: Dict[str, Dict[str, Any]] = None  # pub -> presence data

    def __post_init__(self):
        if self.tasks is None:
            self.tasks = {}
        if self.presence is None:
            self.presence = {}

    def snapshot(self) -> Dict[str, Any]:
        return {
            "group_id": self.group_id,
            "policy": {
                "name": self.policy.name,
                "currency": self.policy.currency,
                "faucet_amount": self.policy.faucet_amount,
                "claim_reward_amount": self.policy.claim_reward_amount,
                "transfer_fee_bps": self.policy.transfer_fee_bps,
                "max_total_supply": self.policy.max_total_supply,
                "max_account_balance": self.policy.max_account_balance,
            },
            "admins": sorted(self.admins),
            "members": sorted(self.members),
            "balances": dict(self.balances),
            "offers": {oid: o.to_dict() for oid, o in self.offers.items()},
            "grants": dict(self.grants),
            "processed_nonces": dict(self.processed_nonces),
            "total_supply": self.total_supply,
            "tasks": dict(self.tasks),
            "presence": dict(self.presence),
        }

    def prune_expired_nonces(self, current_time_ms: int) -> int:
        """Remove nonces older than config nonce_expiry_ms. Returns count of pruned nonces."""
        cutoff = current_time_ms - _get_nonce_expiry_ms()
        expired = [k for k, ts in self.processed_nonces.items() if ts < cutoff]
        for k in expired:
            del self.processed_nonces[k]
        return len(expired)

    @staticmethod
    def from_snapshot(s: Dict[str, Any]) -> "GroupState":
        pol = s.get("policy", {}) or {}
        # Handle both old format (list) and new format (dict) for processed_nonces
        raw_nonces = s.get("processed_nonces", {})
        if isinstance(raw_nonces, list):
            # Migration from old format: assign current time to all nonces
            nonces = {k: int(time.time() * 1000) for k in raw_nonces}
        else:
            nonces = {k: int(v) for k, v in (raw_nonces or {}).items()}

        # Parse policy with all token economy fields (backward compatible defaults)
        policy = GroupPolicy(
            name=str(pol.get("name", "")),
            currency=str(pol.get("currency", "KAT")),
            faucet_amount=int(pol.get("faucet_amount", 0)),
            claim_reward_amount=int(pol.get("claim_reward_amount", 0)),
            transfer_fee_bps=int(pol.get("transfer_fee_bps", 0)),
            max_total_supply=pol.get("max_total_supply"),  # None or int
            max_account_balance=pol.get("max_account_balance"),  # None or int
        )

        state = GroupState(
            group_id=str(s["group_id"]),
            policy=policy,
            admins=set(s.get("admins", [])),
            members=set(s.get("members", [])),
            balances={k: int(v) for k, v in (s.get("balances", {}) or {}).items()},
            offers={oid: Offer.from_dict(od) for oid, od in (s.get("offers", {}) or {}).items()},
            grants=dict(s.get("grants", {}) or {}),
            processed_nonces=nonces,
            total_supply=int(s.get("total_supply", 0)),
            tasks=dict(s.get("tasks", {}) or {}),
            presence=dict(s.get("presence", {}) or {}),
        )
        # ensure treasury exists
        state.balances.setdefault(TREASURY, 0)
        return state


@dataclass
class Block:
    group_id: str
    height: int
    prev: Optional[str]
    ts_ms: int
    author: str  # author signing pub b64
    txs: List[Dict[str, Any]]
    block_id: str
    sig: str

    def header_dict(self) -> Dict[str, Any]:
        return {
            "group_id": self.group_id,
            "height": int(self.height),
            "prev": self.prev,
            "ts_ms": int(self.ts_ms),
            "author": self.author,
            "txs": self.txs,
        }

    def to_dict(self) -> Dict[str, Any]:
        return {**self.header_dict(), "block_id": self.block_id, "sig": self.sig}

    @staticmethod
    def from_dict(d: Dict[str, Any]) -> "Block":
        return Block(
            group_id=str(d["group_id"]),
            height=int(d["height"]),
            prev=d.get("prev"),
            ts_ms=int(d.get("ts_ms", 0)),
            author=str(d.get("author", "")),
            txs=list(d.get("txs", [])),
            block_id=str(d.get("block_id", "")),
            sig=str(d.get("sig", "")),
        )

    @staticmethod
    def make(group_id: str, height: int, prev: Optional[str], *, author_priv, author_pub_b64: str, txs: List[Dict[str, Any]], ts_ms: Optional[int] = None) -> "Block":
        if ts_ms is None:
            ts_ms = int(time.time() * 1000)
        header = {
            "group_id": group_id,
            "height": int(height),
            "prev": prev,
            "ts_ms": int(ts_ms),
            "author": author_pub_b64,
            "txs": txs,
        }
        header_bytes = canonical_json(header).encode("utf-8")
        block_id = sha256_hex(header_bytes)
        sig = b64e(sign_detached(author_priv, header_bytes))
        return Block(group_id=group_id, height=int(height), prev=prev, ts_ms=int(ts_ms), author=author_pub_b64, txs=txs, block_id=block_id, sig=sig)

    def verify_sig(self) -> None:
        try:
            pub = load_sign_pub_raw(b64d(self.author))
        except Exception as e:
            raise ChainError(f"bad block author pub: {e}")
        header_bytes = canonical_json(self.header_dict()).encode("utf-8")
        if sha256_hex(header_bytes) != self.block_id:
            raise ChainError("block_id mismatch")
        if not verify_detached(pub, header_bytes, b64d(self.sig)):
            raise ChainError("bad block signature")


def _require(cond: bool, msg: str) -> None:
    if not cond:
        raise ChainError(msg)


def _verify_tx_sig(tx: Dict[str, Any], pub_b64: str) -> None:
    sig = tx.get("sig")
    _require(isinstance(sig, str), "missing tx sig")
    body = dict(tx)
    body.pop("sig", None)
    msg = canonical_json(body).encode("utf-8")
    pub = load_sign_pub_raw(b64d(pub_b64))
    _require(verify_detached(pub, msg, b64d(sig)), "bad tx signature")


class Chain:
    def __init__(self, genesis: Block):
        genesis.verify_sig()
        if genesis.height != 0 or genesis.prev is not None:
            raise ChainError("invalid genesis header")
        self.blocks: List[Block] = [genesis]
        self.state = self._apply_from_scratch(self.blocks)

    @property
    def head(self) -> Block:
        return self.blocks[-1]

    def _apply_from_scratch(self, blocks: List[Block]) -> GroupState:
        # genesis must include genesis tx
        gtxs = blocks[0].txs
        if len(gtxs) != 1 or gtxs[0].get("type") != "genesis":
            raise ChainError("genesis must have one genesis tx")
        gtx = gtxs[0]
        gid = str(gtx["group_id"])
        pol = GroupPolicy(name=str(gtx.get("name", "")), currency=str(gtx.get("currency", "KAT")))
        creator = str(gtx["creator"])
        st = GroupState(group_id=gid, policy=pol, admins=set([creator]), members=set([creator]), balances={TREASURY: 0}, offers={}, grants={}, processed_nonces={})
        # apply subsequent blocks
        for b in blocks[1:]:
            for tx in b.txs:
                self._validate_tx(tx, b.author, st, block_ts_ms=b.ts_ms)
                self._apply_tx(tx, st, block_author=b.author)
        return st

    @staticmethod
    def make_genesis(group_name: str, *, group_id: Optional[str], creator_pub_b64: str, creator_priv, currency: str = "KAT") -> Block:
        ts = int(time.time() * 1000)
        tx = {
            "type": "genesis",
            "group_id": group_id or sha256_hex(f"{creator_pub_b64}|{group_name}|{ts}".encode("utf-8"))[:16],
            "name": group_name,
            "currency": currency,
            "creator": creator_pub_b64,
            "ts_ms": ts,
        }
        gid = tx["group_id"]
        return Block.make(gid, 0, None, author_priv=creator_priv, author_pub_b64=creator_pub_b64, txs=[tx], ts_ms=ts)

    def append(self, b: Block) -> None:
        b.verify_sig()
        _require(b.group_id == self.state.group_id, "wrong group_id")
        _require(b.height == self.head.height + 1, "wrong height")
        _require(b.prev == self.head.block_id, "wrong prev")

        # Block size validation
        max_txs = _get_max_txs_per_block()
        _require(len(b.txs) <= max_txs,
                 f"block has too many transactions ({len(b.txs)} > {max_txs})")

        # Validate serialized block size
        block_bytes = canonical_json(b.to_dict()).encode("utf-8")
        max_size = _get_max_block_size_bytes()
        _require(len(block_bytes) <= max_size,
                 f"block too large ({len(block_bytes)} > {max_size} bytes)")

        # Timestamp validation
        now_ms = int(time.time() * 1000)
        max_drift = _get_max_clock_drift_ms()
        _require(b.ts_ms <= now_ms + max_drift,
                 f"block timestamp too far in future (max drift {max_drift}ms)")
        _require(b.ts_ms >= self.head.ts_ms,
                 "block timestamp must not be before previous block")

        # validate txs sequentially against current state copy
        st = GroupState.from_snapshot(self.state.snapshot())
        for tx in b.txs:
            self._validate_tx(tx, b.author, st, block_ts_ms=b.ts_ms)
            self._apply_tx(tx, st, block_author=b.author)
        # commit
        self.blocks.append(b)
        self.state = st

    def _validate_tx(self, tx: Dict[str, Any], author_pub: str, st: GroupState, *, block_ts_ms: Optional[int] = None) -> None:
        """Validate a transaction.

        Args:
            tx: Transaction dictionary
            author_pub: Block author's public key
            st: Current group state
            block_ts_ms: Block timestamp for validation (uses current time if None)
        """
        t = tx.get("type")
        _require(isinstance(t, str), "tx missing type")
        # basic auth: block author must be a member for any state-changing tx (except purchase?)
        # We still require the block author to be member, since they are the sequencer/authority.
        _require(author_pub in st.members, "block author not a member")

        if t == "member_add":
            _require(author_pub in st.admins, "member_add requires admin")
            _require("pub" in tx and isinstance(tx["pub"], str), "member_add missing pub")
            role = tx.get("role", "member")
            _require(role in ("member", "admin"), "bad role")
            return
        if t == "member_remove":
            _require(author_pub in st.admins, "member_remove requires admin")
            _require("pub" in tx and isinstance(tx["pub"], str), "member_remove missing pub")
            return
        if t == "mint":
            _require(author_pub in st.admins, "mint requires admin")
            _require(isinstance(tx.get("to"), str), "mint missing to")
            _require(isinstance(tx.get("amount"), int) and tx["amount"] >= 0, "mint bad amount")
            amount = tx["amount"]
            to_addr = tx["to"]
            _require(amount <= MAX_TOKEN_VALUE, "mint amount too large")
            # Supply cap check
            if st.policy.max_total_supply is not None:
                _require(st.total_supply + amount <= st.policy.max_total_supply,
                         f"mint would exceed max_total_supply ({st.policy.max_total_supply})")
            # Account cap check
            if st.policy.max_account_balance is not None:
                new_bal = st.balances.get(to_addr, 0) + amount
                _require(new_bal <= st.policy.max_account_balance,
                         f"mint would exceed max_account_balance ({st.policy.max_account_balance})")
            # Overflow check
            _require(st.total_supply + amount <= MAX_TOKEN_VALUE, "mint would overflow total supply")
            return
        if t == "transfer":
            # Allow any member to transfer their tokens to another address
            _require(author_pub in st.members, "transfer requires member")
            from_addr = tx.get("from")
            to_addr = tx.get("to")
            amount = tx.get("amount")
            _require(isinstance(from_addr, str), "transfer missing from")
            _require(isinstance(to_addr, str), "transfer missing to")
            _require(from_addr != to_addr, "cannot transfer to self")
            _require(isinstance(amount, int) and amount > 0, "transfer bad amount")
            _require(amount <= MAX_TOKEN_VALUE, "transfer amount too large")
            # Sender must be the from address (can only transfer own tokens)
            _require(author_pub == from_addr, "can only transfer your own tokens")
            # Calculate fee (sender pays amount + fee)
            fee_bps = st.policy.transfer_fee_bps
            fee = (amount * fee_bps) // 10000
            total_debit = amount + fee
            # Overflow check for amount + fee
            _require(total_debit <= MAX_TOKEN_VALUE, "transfer total (amount + fee) too large")
            # Check sender has sufficient balance for amount + fee
            bal = int(st.balances.get(from_addr, 0))
            _require(bal >= total_debit, f"insufficient balance for transfer (need {total_debit}, have {bal})")
            # Check recipient can receive under account cap
            if st.policy.max_account_balance is not None:
                recipient_new_bal = st.balances.get(to_addr, 0) + amount
                _require(recipient_new_bal <= st.policy.max_account_balance,
                         f"transfer would exceed recipient max_account_balance")
            return
        if t == "claim":
            _require(author_pub in st.members, "claim requires member")
            _require(isinstance(tx.get("artifact_hash"), str), "claim missing artifact_hash")
            return
        if t == "experience":
            _require(author_pub in st.members, "experience requires member")
            _require(isinstance(tx.get("artifact_hash"), str), "experience missing artifact_hash")
            return
        if t == "retract":
            _require(author_pub in st.members, "retract requires member")
            _require(isinstance(tx.get("claim_hash"), str), "retract missing claim_hash")
            return
        if t == "offer_create":
            _require(author_pub in st.members, "offer_create requires member")
            _require(isinstance(tx.get("offer"), dict), "offer_create missing offer")
            offer = tx["offer"]
            _require(str(offer.get("group_id")) == st.group_id, "offer group mismatch")
            _require(isinstance(offer.get("offer_id"), str), "offer missing offer_id")
            _require(isinstance(offer.get("package_hash"), str), "offer missing package_hash")
            _require(isinstance(offer.get("price"), int) and offer["price"] >= 0, "offer bad price")
            return
        if t == "offer_revoke":
            _require(author_pub in st.members, "offer_revoke requires member")
            _require(isinstance(tx.get("offer_id"), str), "offer_revoke missing offer_id")
            return
        if t == "purchase":
            # buyer-authorized debit; buyer does not need to be a member, but must sign
            _require(isinstance(tx.get("offer_id"), str), "purchase missing offer_id")
            _require(isinstance(tx.get("buyer"), str), "purchase missing buyer")
            _require(isinstance(tx.get("amount"), int) and tx["amount"] >= 0, "purchase bad amount")
            # Validate nonce: must be string, minimum length for security, hex characters only
            nonce = tx.get("nonce")
            min_nonce_len = _get_min_nonce_length()
            _require(isinstance(nonce, str) and len(nonce) >= min_nonce_len,
                     f"purchase nonce must be at least {min_nonce_len} characters")
            _require(all(c in "0123456789abcdef" for c in nonce.lower()),
                     "purchase nonce must be hexadecimal")
            # Check for replay attack - nonce must be unique per buyer+offer combination
            nonce_key = f"{tx['buyer']}:{tx['offer_id']}:{nonce}"
            _require(nonce_key not in st.processed_nonces,
                     f"duplicate nonce for buyer/offer (replay attack blocked)")

            # Validate transaction timestamp
            # Use block timestamp as authoritative time (prevents clock skew issues)
            # For new blocks, block_ts_ms is already validated against local time
            tx_ts = tx.get("ts_ms", 0)
            _require(isinstance(tx_ts, int) and tx_ts > 0, "purchase missing valid timestamp")

            # Use block timestamp if available (historical validation), else local time (new tx)
            reference_time_ms = block_ts_ms if block_ts_ms is not None else int(time.time() * 1000)
            max_drift = _get_max_clock_drift_ms()
            nonce_expiry = _get_nonce_expiry_ms()

            # TX timestamp must be within acceptable range of block/current time
            _require(tx_ts <= reference_time_ms + max_drift,
                     "purchase timestamp too far in future")
            _require(tx_ts >= reference_time_ms - nonce_expiry,
                     "purchase timestamp too old (nonce expired)")

            _verify_tx_sig(tx, tx["buyer"])
            # amount must match offer price
            offer = st.offers.get(tx["offer_id"])
            _require(offer is not None and offer.active, "unknown or inactive offer")

            # Check offer expiration using BLOCK timestamp (authoritative time)
            # This prevents buyers from backdating transactions to bypass expiry
            if offer.expires_ms is not None:
                check_time = block_ts_ms if block_ts_ms is not None else int(time.time() * 1000)
                _require(check_time <= offer.expires_ms, "offer has expired")

            _require(tx["amount"] == offer.price, "amount must equal offer price")
            # buyer must have sufficient balance
            bal = int(st.balances.get(tx["buyer"], 0))
            _require(bal >= tx["amount"], "insufficient balance")
            return
        if t == "grant":
            _require(isinstance(tx.get("offer_id"), str), "grant missing offer_id")
            _require(isinstance(tx.get("buyer"), str), "grant missing buyer")
            _require(isinstance(tx.get("sealed_key"), dict), "grant missing sealed_key")
            offer = st.offers.get(tx["offer_id"])
            _require(offer is not None, "unknown offer")
            _require(author_pub == offer.seller or author_pub in st.admins, "grant must be from seller or admin")
            # ensure package matches offer
            _require(tx.get("package_hash") == offer.package_hash, "grant package mismatch")
            return
        if t == "policy_update":
            _require(author_pub in st.admins, "policy_update requires admin")
            updates = tx.get("updates", {})
            _require(isinstance(updates, dict), "policy_update missing updates")
            _require(len(updates) > 0, "policy_update has no updates")
            # Validate only known fields are being updated
            valid_keys = {"faucet_amount", "claim_reward_amount", "transfer_fee_bps",
                         "max_total_supply", "max_account_balance"}
            unknown_keys = set(updates.keys()) - valid_keys
            _require(len(unknown_keys) == 0, f"policy_update has unknown keys: {unknown_keys}")
            # Validate each field type and bounds
            if "faucet_amount" in updates:
                v = updates["faucet_amount"]
                _require(isinstance(v, int) and v >= 0, "invalid faucet_amount")
                _require(v <= MAX_TOKEN_VALUE, "faucet_amount too large")
            if "claim_reward_amount" in updates:
                v = updates["claim_reward_amount"]
                _require(isinstance(v, int) and v >= 0, "invalid claim_reward_amount")
                _require(v <= MAX_TOKEN_VALUE, "claim_reward_amount too large")
            if "transfer_fee_bps" in updates:
                v = updates["transfer_fee_bps"]
                _require(isinstance(v, int) and 0 <= v <= 5000, "transfer_fee_bps must be 0-5000")
            if "max_total_supply" in updates:
                v = updates["max_total_supply"]
                _require(v is None or (isinstance(v, int) and v > 0), "invalid max_total_supply")
                if v is not None:
                    _require(v >= st.total_supply, "max_total_supply cannot be below current supply")
                    _require(v <= MAX_TOKEN_VALUE, "max_total_supply too large")
            if "max_account_balance" in updates:
                v = updates["max_account_balance"]
                _require(v is None or (isinstance(v, int) and v > 0), "invalid max_account_balance")
                if v is not None:
                    _require(v <= MAX_TOKEN_VALUE, "max_account_balance too large")
            return

        # Task management transactions
        if t == "task_create":
            _require(author_pub in st.members, "task_create requires member")
            task_id = tx.get("task_id")
            _require(isinstance(task_id, str) and len(task_id) > 0, "task_create missing task_id")
            _require(len(task_id) <= 256, "task_id too long (max 256)")
            _require(task_id not in st.tasks, "task_id already exists")
            title = tx.get("title")
            _require(isinstance(title, str) and len(title) > 0, "task_create missing title")
            _require(len(title) <= 256, "task title too long (max 256)")
            if tx.get("description"):
                _require(len(tx["description"]) <= 4096, "task description too long (max 4096)")
            if tx.get("assignee"):
                _require(tx["assignee"] in st.members, "task assignee must be a member")
            if tx.get("reward"):
                reward = tx["reward"]
                _require(isinstance(reward, int) and reward >= 0, "invalid reward")
                _require(reward <= MAX_TOKEN_VALUE, "reward too large")
            return

        if t == "task_assign":
            _require(author_pub in st.members, "task_assign requires member")
            task_id = tx.get("task_id")
            _require(isinstance(task_id, str) and task_id in st.tasks, "unknown task_id")
            task = st.tasks[task_id]
            _require(task["status"] in ("pending", "assigned"), "task not assignable")
            assignee = tx.get("assignee")
            _require(isinstance(assignee, str), "task_assign missing assignee")
            _require(assignee in st.members, "task assignee must be a member")
            return

        if t == "task_start":
            _require(author_pub in st.members, "task_start requires member")
            task_id = tx.get("task_id")
            _require(isinstance(task_id, str) and task_id in st.tasks, "unknown task_id")
            task = st.tasks[task_id]
            _require(task["status"] == "assigned", "task must be assigned before starting")
            _require(task.get("assignee") == author_pub, "only assignee can start task")
            return

        if t == "task_complete":
            _require(author_pub in st.members, "task_complete requires member")
            task_id = tx.get("task_id")
            _require(isinstance(task_id, str) and task_id in st.tasks, "unknown task_id")
            task = st.tasks[task_id]
            _require(task["status"] == "in_progress", "task must be in_progress to complete")
            _require(task.get("assignee") == author_pub, "only assignee can complete task")
            return

        if t == "task_fail":
            _require(author_pub in st.members, "task_fail requires member")
            task_id = tx.get("task_id")
            _require(isinstance(task_id, str) and task_id in st.tasks, "unknown task_id")
            task = st.tasks[task_id]
            _require(task["status"] == "in_progress", "task must be in_progress to fail")
            _require(task.get("assignee") == author_pub, "only assignee can fail task")
            if tx.get("error_message"):
                _require(len(tx["error_message"]) <= 1024, "error_message too long (max 1024)")
            return

        # Agent presence/heartbeat
        if t == "presence":
            _require(author_pub in st.members, "presence requires member")
            status = tx.get("status", "active")
            _require(status in ("active", "idle", "busy", "offline"), "invalid presence status")
            # Limit metadata size to prevent abuse
            metadata = tx.get("metadata", {})
            if metadata:
                import json
                metadata_json = json.dumps(metadata)
                _require(len(metadata_json) <= 4096, "presence metadata too large (max 4KB)")
            return

        raise ChainError(f"unknown tx type {t}")

    def _apply_tx(self, tx: Dict[str, Any], st: GroupState, *, block_author: str = "") -> None:
        t = tx["type"]
        if t == "member_add":
            pub = tx["pub"]
            # Check if this is a NEW member (not re-adding existing)
            is_new_member = pub not in st.members
            st.members.add(pub)
            if tx.get("role") == "admin":
                st.admins.add(pub)
            st.balances.setdefault(pub, 0)
            # Member faucet: auto-mint to NEW members only
            faucet = st.policy.faucet_amount
            if faucet > 0 and is_new_member:
                if _can_mint(st.policy, st.total_supply, faucet):
                    if _check_account_cap(st.policy, st.balances.get(pub, 0), faucet):
                        st.balances[pub] = st.balances.get(pub, 0) + faucet
                        st.total_supply += faucet
            return
        if t == "member_remove":
            pub = tx["pub"]
            st.members.discard(pub)
            st.admins.discard(pub)
            return
        if t == "mint":
            to = tx["to"]
            amt = int(tx["amount"])
            st.balances[to] = int(st.balances.get(to, 0)) + amt
            st.total_supply += amt  # Track total supply
            return
        if t == "transfer":
            from_addr = tx["from"]
            to_addr = tx["to"]
            amt = int(tx["amount"])
            # Calculate fee
            fee_bps = st.policy.transfer_fee_bps
            fee = (amt * fee_bps) // 10000
            # Debit sender (amount + fee)
            st.balances[from_addr] = int(st.balances.get(from_addr, 0)) - amt - fee
            # Credit recipient
            st.balances[to_addr] = int(st.balances.get(to_addr, 0)) + amt
            # Credit treasury with fee
            if fee > 0:
                st.balances[TREASURY] = int(st.balances.get(TREASURY, 0)) + fee
            return
        if t == "claim":
            # chain does not store claim text; it's in CAS + context graph
            # Reward the claim author (block author)
            reward = st.policy.claim_reward_amount
            if reward > 0 and block_author:
                if _can_mint(st.policy, st.total_supply, reward):
                    if _check_account_cap(st.policy, st.balances.get(block_author, 0), reward):
                        st.balances[block_author] = st.balances.get(block_author, 0) + reward
                        st.total_supply += reward
            return
        if t == "experience":
            return
        if t == "retract":
            return
        if t == "offer_create":
            o = Offer.from_dict(tx["offer"])
            st.offers[o.offer_id] = o
            return
        if t == "offer_revoke":
            oid = tx["offer_id"]
            off = st.offers.get(oid)
            if off:
                off.active = False
            return
        if t == "purchase":
            offer = st.offers[tx["offer_id"]]
            buyer = tx["buyer"]
            amt = int(tx["amount"])
            # Record nonce with timestamp to prevent replay (enables expiry)
            nonce_key = f"{buyer}:{tx['offer_id']}:{tx['nonce']}"
            st.processed_nonces[nonce_key] = int(tx.get("ts_ms", time.time() * 1000))
            # Prune expired nonces periodically (every purchase)
            st.prune_expired_nonces(int(time.time() * 1000))
            # debit buyer
            st.balances[buyer] = int(st.balances.get(buyer, 0)) - amt
            # royalty to parents
            remaining = amt
            for pr in offer.parents:
                poid = pr.get("offer_id")
                bps = int(pr.get("bps", 0))
                if not poid or bps <= 0:
                    continue
                parent = st.offers.get(str(poid))
                if not parent:
                    continue
                pay = (amt * bps) // 10000
                if pay <= 0:
                    continue
                st.balances[parent.seller] = int(st.balances.get(parent.seller, 0)) + pay
                remaining -= pay
            if remaining < 0:
                remaining = 0
            # splits among recipients
            splits = offer.splits or [{"pub": offer.seller, "bps": 10000}]
            allocated = 0
            for sp in splits:
                pub = str(sp.get("pub", ""))
                bps = int(sp.get("bps", 0))
                if not pub or bps <= 0:
                    continue
                pay = (remaining * bps) // 10000
                if pay <= 0:
                    continue
                st.balances[pub] = int(st.balances.get(pub, 0)) + pay
                allocated += pay
            # remainder to treasury
            rem2 = remaining - allocated
            if rem2 > 0:
                st.balances[TREASURY] = int(st.balances.get(TREASURY, 0)) + rem2
            return
        if t == "grant":
            key = f"{tx['offer_id']}:{tx['buyer']}"
            st.grants[key] = {
                "offer_id": tx["offer_id"],
                "buyer": tx["buyer"],
                "package_hash": tx["package_hash"],
                "sealed_key": tx["sealed_key"],
                "ts_ms": int(tx.get("ts_ms", int(time.time() * 1000))),
            }
            return
        if t == "policy_update":
            updates = tx["updates"]
            # Apply each policy update
            if "faucet_amount" in updates:
                st.policy.faucet_amount = int(updates["faucet_amount"])
            if "claim_reward_amount" in updates:
                st.policy.claim_reward_amount = int(updates["claim_reward_amount"])
            if "transfer_fee_bps" in updates:
                st.policy.transfer_fee_bps = int(updates["transfer_fee_bps"])
            if "max_total_supply" in updates:
                st.policy.max_total_supply = updates["max_total_supply"]
            if "max_account_balance" in updates:
                st.policy.max_account_balance = updates["max_account_balance"]
            return

        # Task management
        if t == "task_create":
            task_id = tx["task_id"]
            assignee = tx.get("assignee")
            st.tasks[task_id] = {
                "task_id": task_id,
                "title": tx["title"],
                "description": tx.get("description", ""),
                "creator": block_author,
                "assignee": assignee,
                "status": "assigned" if assignee else "pending",
                "created_ms": tx.get("ts_ms", int(time.time() * 1000)),
                "due_ms": tx.get("due_ms"),
                "reward": tx.get("reward", 0),
            }
            return

        if t == "task_assign":
            task = st.tasks[tx["task_id"]]
            task["assignee"] = tx["assignee"]
            task["status"] = "assigned"
            task["assigned_ms"] = tx.get("ts_ms", int(time.time() * 1000))
            return

        if t == "task_start":
            task = st.tasks[tx["task_id"]]
            task["status"] = "in_progress"
            task["started_ms"] = tx.get("ts_ms", int(time.time() * 1000))
            return

        if t == "task_complete":
            task = st.tasks[tx["task_id"]]
            task["status"] = "completed"
            task["completed_ms"] = tx.get("ts_ms", int(time.time() * 1000))
            task["result_hash"] = tx.get("result_hash")
            # Mint reward to assignee
            reward = task.get("reward", 0)
            assignee = task.get("assignee")
            if reward > 0 and assignee:
                if _can_mint(st.policy, st.total_supply, reward):
                    if _check_account_cap(st.policy, st.balances.get(assignee, 0), reward):
                        st.balances[assignee] = st.balances.get(assignee, 0) + reward
                        st.total_supply += reward
            return

        if t == "task_fail":
            task = st.tasks[tx["task_id"]]
            task["status"] = "failed"
            task["failed_ms"] = tx.get("ts_ms", int(time.time() * 1000))
            task["error_message"] = tx.get("error_message", "")
            return

        # Agent presence/heartbeat
        if t == "presence":
            st.presence[block_author] = {
                "last_seen_ms": tx.get("ts_ms", int(time.time() * 1000)),
                "status": tx.get("status", "active"),
                "metadata": tx.get("metadata", {}),
            }
            return

        raise ChainError(f"cannot apply tx type {t}")

    def snapshot(self) -> Dict[str, Any]:
        return {
            "state": self.state.snapshot(),
            "blocks": [b.to_dict() for b in self.blocks],
        }

    @staticmethod
    def from_snapshot(s: Dict[str, Any]) -> "Chain":
        blocks = [Block.from_dict(b) for b in s.get("blocks", [])]
        if not blocks:
            raise ChainError("empty chain snapshot")
        ch = Chain(blocks[0])
        for b in blocks[1:]:
            ch.append(b)
        # trust snapshot state? recompute already did in append
        return ch
