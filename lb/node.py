from __future__ import annotations

import asyncio
import os
import time
import json
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .keys import gen_node_keys, NodeKeys, dump_sign_priv_raw, dump_enc_priv_raw, b64e, b64d, ensure_mode_600, load_sign_priv_raw, load_enc_priv_raw
from .fs import ensure_dir, atomic_write_json, read_json, atomic_write_bytes
from .cas import CAS, CasMeta
from .chain import Chain, Block, ChainError, Offer, TREASURY
from .context_graph import ContextGraph
from .group import Group
from .canonical import sha256_hex, canonical_json
from .crypto import encrypt_package, decrypt_package, seal_to_x25519, open_from_x25519, CryptoError
from .secure_channel import client_handshake, SecureSession
from .wire import read_frame, write_frame
from .logging_config import get_node_logger, Timer, log_operation
from .validation import (
    validate_group_name, validate_claim_text, validate_tags,
    validate_offer_title, validate_offer_description, validate_price,
    validate_amount, validate_public_key, validate_experience,
    ValidationError
)

logger = get_node_logger()


class NodeError(Exception):
    pass


def _now_ms() -> int:
    return int(time.time() * 1000)


def _node_id_from_pub(sign_pub_b64: str) -> str:
    return sha256_hex(sign_pub_b64.encode("utf-8"))[:12]


@dataclass
class OfferAnnouncement:
    offer_id: str
    group_id: str
    seller_sign_pub: str
    seller_enc_pub: str
    host: str
    port: int
    package_hash: str
    title: str
    tags: List[str]
    price: int
    currency: str
    created_ms: int
    sig: str
    expires_ms: Optional[int] = None

    def body(self) -> Dict[str, Any]:
        body = {
            "offer_id": self.offer_id,
            "group_id": self.group_id,
            "seller_sign_pub": self.seller_sign_pub,
            "seller_enc_pub": self.seller_enc_pub,
            "host": self.host,
            "port": int(self.port),
            "package_hash": self.package_hash,
            "title": self.title,
            "tags": list(self.tags),
            "price": int(self.price),
            "currency": self.currency,
            "created_ms": int(self.created_ms),
        }
        if self.expires_ms is not None:
            body["expires_ms"] = int(self.expires_ms)
        return body

    def to_dict(self) -> Dict[str, Any]:
        return {**self.body(), "sig": self.sig}

    @staticmethod
    def from_dict(d: Dict[str, Any]) -> "OfferAnnouncement":
        return OfferAnnouncement(
            offer_id=str(d["offer_id"]),
            group_id=str(d["group_id"]),
            seller_sign_pub=str(d["seller_sign_pub"]),
            seller_enc_pub=str(d["seller_enc_pub"]),
            host=str(d.get("host", "")),
            port=int(d.get("port", 0)),
            package_hash=str(d.get("package_hash", "")),
            title=str(d.get("title", "")),
            tags=list(d.get("tags", [])),
            price=int(d.get("price", 0)),
            currency=str(d.get("currency", "KAT")),
            created_ms=int(d.get("created_ms", 0)),
            sig=str(d.get("sig", "")),
            expires_ms=int(d["expires_ms"]) if d.get("expires_ms") is not None else None,
        )


class BatteryNode:
    def __init__(self, data_dir: Path, keys: NodeKeys):
        self.data_dir = Path(data_dir)
        self.keys = keys
        self.node_id = _node_id_from_pub(keys.sign_pub_b64)
        self.cas = CAS(self.data_dir / "cas")
        self.groups: Dict[str, Group] = {}
        self.offer_book: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.RLock()
        self._registry = None  # Lazy-loaded peer registry
        self._wal = None  # Lazy-loaded WAL
        self._recover_wal()  # Recover any incomplete transactions on startup
        self._load_groups()
        self._load_offer_book()

    # ---------- paths ----------

    @property
    def keys_dir(self) -> Path:
        return self.data_dir / "keys"

    @property
    def node_meta_path(self) -> Path:
        return self.data_dir / "node.json"

    @property
    def offer_book_path(self) -> Path:
        return self.data_dir / "market_offers.json"

    @property
    def groups_dir(self) -> Path:
        return self.data_dir / "groups"

    @property
    def wallet_dir(self) -> Path:
        return self.data_dir / "wallet"

    @property
    def wallet_keys_path(self) -> Path:
        return self.wallet_dir / "keys.json"

    @property
    def ledger_path(self) -> Path:
        return self.data_dir / "ledger" / "events.jsonl"

    # ---------- peer registry ----------

    @property
    def peer_registry(self):
        """Get or create the peer registry (lazy initialization, thread-safe)."""
        # Fast path: registry already initialized
        if self._registry is not None:
            return self._registry
        # Slow path: acquire lock and double-check
        with self._lock:
            if self._registry is None:
                from .registry import PeerRegistry
                self._registry = PeerRegistry(self.data_dir)
            return self._registry

    # ---------- WAL (Write-Ahead Log) ----------

    @property
    def wal_dir(self) -> Path:
        return self.data_dir / "wal"

    @property
    def wal(self):
        """Get or create the WAL (lazy initialization, thread-safe)."""
        if self._wal is not None:
            return self._wal
        with self._lock:
            if self._wal is None:
                from .wal import WriteAheadLog
                self._wal = WriteAheadLog(self.wal_dir)
            return self._wal

    def _recover_wal(self) -> None:
        """Recover any incomplete WAL transactions on startup."""
        if self.wal_dir.exists():
            from .wal import WriteAheadLog
            wal = WriteAheadLog(self.wal_dir)
            recovered = wal.recover()
            if recovered > 0:
                logger.info(f"Recovered {recovered} WAL transactions on startup")
            self._wal = wal

    # ---------- initialization ----------

    @staticmethod
    def init(data_dir: Path) -> "BatteryNode":
        data_dir = Path(data_dir)
        logger.info(f"Initializing new node at {data_dir}")

        ensure_dir(data_dir)
        ensure_dir(data_dir / "keys")
        ensure_dir(data_dir / "groups")
        ensure_dir(data_dir / "wallet")
        ensure_dir(data_dir / "ledger")

        keys = gen_node_keys()
        sign_path = data_dir / "keys" / "signing.key"
        enc_path = data_dir / "keys" / "encryption.key"

        atomic_write_bytes(sign_path, dump_sign_priv_raw(keys.sign_priv))
        atomic_write_bytes(enc_path, dump_enc_priv_raw(keys.enc_priv))
        ensure_mode_600(str(sign_path))
        ensure_mode_600(str(enc_path))

        meta = {
            "node_id": _node_id_from_pub(keys.sign_pub_b64),
            "sign_pub": keys.sign_pub_b64,
            "enc_pub": keys.enc_pub_b64,
            "created_ms": _now_ms(),
        }
        atomic_write_json(data_dir / "node.json", meta)
        atomic_write_json(data_dir / "market_offers.json", {})
        atomic_write_json(data_dir / "wallet" / "keys.json", {})

        node = BatteryNode.load(data_dir)
        logger.info(f"Node initialized: id={node.node_id}, sign_pub={keys.sign_pub_b64[:16]}...")
        return node

    @staticmethod
    def load(data_dir: Path, *, password: Optional[str] = None) -> "BatteryNode":
        """Load a BatteryNode from a data directory.

        Args:
            data_dir: Path to the node data directory
            password: Password for encrypted keys. If keys are encrypted and
                     password is not provided, will prompt interactively.

        Returns:
            Loaded BatteryNode instance

        Raises:
            NodeError: If node is not initialized or key files are missing
        """
        from .key_encryption import is_encrypted_key_file, load_keys, KeyEncryptionError

        data_dir = Path(data_dir)
        meta_path = data_dir / "node.json"
        if not meta_path.exists():
            raise NodeError("node not initialized (missing node.json). Run `lb init`.")
        sign_path = data_dir / "keys" / "signing.key"
        enc_path = data_dir / "keys" / "encryption.key"
        if not sign_path.exists() or not enc_path.exists():
            raise NodeError("missing key files")

        # Check if keys are encrypted
        if is_encrypted_key_file(sign_path) or is_encrypted_key_file(enc_path):
            if password is None:
                import getpass
                password = getpass.getpass("Enter key password: ")
            try:
                keys = load_keys(data_dir, password)
            except KeyEncryptionError as e:
                raise NodeError(f"failed to load encrypted keys: {e}") from e
        else:
            # Load unencrypted keys
            sign_priv = load_sign_priv_raw(sign_path.read_bytes())
            enc_priv = load_enc_priv_raw(enc_path.read_bytes())
            keys = NodeKeys(
                sign_priv=sign_priv,
                sign_pub=sign_priv.public_key(),
                enc_priv=enc_priv,
                enc_pub=enc_priv.public_key(),
            )
        return BatteryNode(data_dir, keys)

    # ---------- loading state ----------

    def _load_groups(self) -> None:
        ensure_dir(self.groups_dir)
        for p in self.groups_dir.iterdir():
            if p.is_dir() and (p / "chain.json").exists():
                g = Group.load(p)
                self.groups[g.group_id] = g

    def refresh_groups(self) -> List[str]:
        """Scan groups directory and load any new groups.
        
        Returns:
            List of newly loaded group IDs.
        """
        if not self.groups_dir.exists():
            return []
            
        new_groups_ids = []
        # Create a set of already loaded paths for O(1) lookup
        loaded_paths = {g.chain.path.resolve() for g in self.groups.values()}

        for p in self.groups_dir.iterdir():
            if not p.is_dir() or not (p / "chain.json").exists():
                continue
            
            if p.resolve() in loaded_paths:
                continue

            try:
                g = Group.load(p)
                # Check for ID collision just in case
                if g.group_id in self.groups:
                    continue

                self.groups[g.group_id] = g
                new_groups_ids.append(g.group_id)
                logger.info(f"Hot-loaded new group: {g.group_id} from {p.name}")
            except Exception as e:
                logger.error(f"Failed to hot-load group from {p.name}: {e}")
                
        return new_groups_ids


    def _load_offer_book(self) -> None:
        if self.offer_book_path.exists():
            self.offer_book = read_json(self.offer_book_path)
        else:
            self.offer_book = {}

    def _save_offer_book(self) -> None:
        atomic_write_json(self.offer_book_path, self.offer_book)

    def _wallet_keys(self) -> Dict[str, str]:
        ensure_dir(self.wallet_dir)
        if self.wallet_keys_path.exists():
            return read_json(self.wallet_keys_path)
        return {}

    def _save_wallet_keys(self, m: Dict[str, str]) -> None:
        ensure_dir(self.wallet_dir)
        atomic_write_json(self.wallet_keys_path, m)

    # ---------- ledger ----------

    def log_event(self, typ: str, payload: Dict[str, Any]) -> None:
        """Log an event to the ledger with fsync for durability."""
        ensure_dir(self.ledger_path.parent)
        evt = {"ts_ms": _now_ms(), "type": typ, "payload": payload}
        line = json.dumps(evt, ensure_ascii=False, sort_keys=True)
        with open(self.ledger_path, "a", encoding="utf-8") as f:
            f.write(line + "\n")
            f.flush()
            os.fsync(f.fileno())

    # ---------- group management ----------

    def create_group(self, name: str, *, group_id: Optional[str] = None, currency: str = "KAT") -> str:
        # Validate inputs
        name = validate_group_name(name)

        with self._lock:
            genesis = Chain.make_genesis(name, group_id=group_id, creator_pub_b64=self.keys.sign_pub_b64, creator_priv=self.keys.sign_priv, currency=currency)
            chain = Chain(genesis)
            gid = chain.state.group_id
            root = self.groups_dir / gid
            g = Group(group_id=gid, root=root, chain=chain, graph=ContextGraph())
            g.save()
            self.groups[gid] = g
            logger.info(f"Created group: id={gid}, name={name}")
            return gid

    def add_member(self, group_id: str, pub_b64: str, *, role: str = "member") -> None:
        with self._lock:
            g = self._require_group(group_id)
            tx = {"type": "member_add", "pub": pub_b64, "role": role, "ts_ms": _now_ms()}
            self._append_block(g, [tx])

    def remove_member(self, group_id: str, pub_b64: str) -> None:
        with self._lock:
            g = self._require_group(group_id)
            tx = {"type": "member_remove", "pub": pub_b64, "ts_ms": _now_ms()}
            self._append_block(g, [tx])

    def mint(self, group_id: str, to_pub: str, amount: int) -> None:
        with self._lock:
            g = self._require_group(group_id)
            tx = {"type": "mint", "to": to_pub, "amount": int(amount), "ts_ms": _now_ms()}
            self._append_block(g, [tx])

    def balance(self, group_id: str, pub: str) -> int:
        g = self._require_group(group_id)
        return int(g.chain.state.balances.get(pub, 0))

    def update_group_policy(self, group_id: str, **updates) -> None:
        """Update group token policy. Admin only.

        Args:
            group_id: Group to update
            **updates: Policy fields to update. Supported fields:
                - faucet_amount: int >= 0 (tokens for new members)
                - claim_reward_amount: int >= 0 (tokens per claim)
                - transfer_fee_bps: int 0-5000 (fee in basis points)
                - max_total_supply: int > 0 or None (supply cap)
                - max_account_balance: int > 0 or None (account cap)

        Raises:
            NodeError: If not admin or invalid update values
        """
        with self._lock:
            g = self._require_group(group_id)
            tx = {"type": "policy_update", "updates": updates, "ts_ms": _now_ms()}
            self._append_block(g, [tx])
            logger.info(f"Updated policy for group {group_id}: {updates}")

    def get_token_stats(self, group_id: str) -> Dict[str, Any]:
        """Get token statistics for a group.

        Args:
            group_id: Group to query

        Returns:
            Dict with token economy stats:
                - total_supply: Current total tokens in circulation
                - max_total_supply: Supply cap (None if unlimited)
                - treasury_balance: Tokens held by treasury
                - faucet_amount: Tokens given to new members
                - claim_reward_amount: Tokens earned per claim
                - transfer_fee_bps: Transfer fee in basis points
                - max_account_balance: Account cap (None if unlimited)
        """
        g = self._require_group(group_id)
        state = g.chain.state
        return {
            "total_supply": state.total_supply,
            "max_total_supply": state.policy.max_total_supply,
            "treasury_balance": state.balances.get(TREASURY, 0),
            "faucet_amount": state.policy.faucet_amount,
            "claim_reward_amount": state.policy.claim_reward_amount,
            "transfer_fee_bps": state.policy.transfer_fee_bps,
            "max_account_balance": state.policy.max_account_balance,
        }

    def transfer(self, group_id: str, to_pub: str, amount: int, *,
                 signer_keys: Optional[NodeKeys] = None) -> None:
        """Transfer tokens to another member.

        Args:
            group_id: Group where transfer occurs
            to_pub: Recipient's public key
            amount: Amount to transfer (must be > 0)
            signer_keys: Optional keys to sign with (for multi-agent scenarios).
                        The transfer will be from this key's identity.

        Note: Sender pays transfer fee if configured. Fee goes to treasury.
        """
        with self._lock:
            g = self._require_group(group_id)
            keys = signer_keys or self.keys
            tx = {
                "type": "transfer",
                "from": keys.sign_pub_b64,
                "to": to_pub,
                "amount": int(amount),
                "ts_ms": _now_ms(),
            }
            self._append_block(g, [tx], signer_keys=signer_keys)
            logger.debug(f"Transferred {amount} tokens to {to_pub[:16]}... in group {group_id}")

    # ---------- claims / context ----------

    def publish_claim(
        self, group_id: str, text: str, tags: List[str], *, parent_hash: Optional[str] = None,
        signer_keys: Optional[NodeKeys] = None
    ) -> str:
        """Publish a knowledge claim to a group.

        Args:
            group_id: Group to publish to
            text: Claim text content
            tags: List of tags for categorization
            parent_hash: Optional parent claim hash for threading/replies
            signer_keys: Optional keys to sign with (for multi-agent scenarios)

        Returns:
            Claim hash (content-addressed identifier)
        """
        # Validate inputs
        text = validate_claim_text(text)
        tags = validate_tags(tags)

        with self._lock:
            g = self._require_group(group_id)
            # Validate parent_hash if provided
            if parent_hash is not None:
                if parent_hash not in g.graph.claims:
                    raise NodeError(f"parent claim {parent_hash} not found")
            # store claim artifact
            claim_obj = {"v": 2, "text": text, "tags": tags, "created_ms": _now_ms()}
            if parent_hash is not None:
                claim_obj["parent_hash"] = parent_hash
            h = self.cas.put_json(claim_obj, CasMeta(visibility=f"group:{group_id}", kind="claim", group_id=group_id))
            # chain tx
            tx = {"type": "claim", "artifact_hash": h, "ts_ms": _now_ms()}
            self._append_block(g, [tx], signer_keys=signer_keys)
            # update graph
            g.graph.add_claim(h, text=text, tags=tags, evidence=[], parent_hash=parent_hash)
            g.save()
            self.log_event("claim", {"group_id": group_id, "claim_hash": h, "parent_hash": parent_hash})
            logger.debug(f"Published claim: hash={h[:16]}..., group={group_id}, parent={parent_hash}")
            return h

    def submit_experience(self, group_id: str, experience: Dict[str, Any]) -> str:
        """Stores an agent run / experience as a group-private artifact and commits it on-chain."""
        # Validate experience data
        experience = validate_experience(experience or {})

        with self._lock:
            g = self._require_group(group_id)
            exp_obj = {"v": 1, "created_ms": _now_ms(), **experience}
            h = self.cas.put_json(exp_obj, CasMeta(visibility=f"group:{group_id}", kind="experience", group_id=group_id))
            tx = {"type": "experience", "artifact_hash": h, "ts_ms": _now_ms()}
            self._append_block(g, [tx])
            g.save()
            self.log_event("experience", {"group_id": group_id, "experience_hash": h})
            return h

    def rebuild_group_graph(self, group_id: str) -> None:
        """Rebuilds the context graph deterministically from chain + CAS."""
        with self._lock:
            g = self._require_group(group_id)
            new_graph = ContextGraph()
            for b in g.chain.blocks:
                for tx in b.txs:
                    t = tx.get("type")
                    if t == "claim":
                        h = tx.get("artifact_hash")
                        if isinstance(h, str) and self.cas.has(h):
                            try:
                                obj = self.cas.get_json(h) or {}
                                new_graph.add_claim(
                                    h,
                                    text=str(obj.get("text", "")),
                                    tags=list(obj.get("tags", [])),
                                    evidence=list(obj.get("evidence", [])),
                                    created_ms=int(obj.get("created_ms", 0) or 0),
                                    parent_hash=obj.get("parent_hash"),
                                )
                            except Exception as e:
                                logger.warning(f"Failed to rebuild claim {h[:16]}...: {type(e).__name__}: {e}")
                                continue
                    elif t == "retract":
                        ch = tx.get("claim_hash")
                        if isinstance(ch, str):
                            new_graph.retract(ch)
            g.graph = new_graph
            g.save()

    async def pull_market_offers_from_peer(self, host: str, port: int, *, timeout: float = 30.0) -> int:
        """Fetches public offer announcements from a peer and imports them.

        Args:
            host: Peer host address
            port: Peer port
            timeout: Connection and operation timeout in seconds (default: 30s)
        """
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=timeout
            )
        except asyncio.TimeoutError:
            raise NodeError(f"Connection to {host}:{port} timed out")
        try:
            session = await client_handshake(reader, writer, self.keys)
            req = {"id": 1, "method": "market_list_offers", "params": {}}
            await write_frame(writer, session.seal(req))
            env = await read_frame(reader)
            resp = session.open(env)
            if resp.get("error"):
                raise NodeError(resp["error"].get("message", "market_list_offers failed"))
            offers = (resp.get("result", {}) or {}).get("offers", [])
            if not isinstance(offers, list):
                return 0
            n = self.import_offer_announcements(offers)
            return n
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    async def sync_group_from_peer(self, host: str, port: int, group_id: str, *, timeout: float = 60.0) -> bool:
        """Synchronizes a group snapshot and required artifacts from a peer.

        Args:
            host: Peer host address
            port: Peer port
            group_id: Group ID to sync
            timeout: Connection and operation timeout in seconds (default: 60s)
        """
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=timeout
            )
        except asyncio.TimeoutError:
            raise NodeError(f"Connection to {host}:{port} timed out")
        try:
            session = await client_handshake(reader, writer, self.keys)
            # request snapshot
            req = {"id": 1, "method": "group_get_snapshot", "params": {"group_id": group_id}}
            await write_frame(writer, session.seal(req))
            env = await read_frame(reader)
            resp = session.open(env)
            if resp.get("error"):
                raise NodeError(resp["error"].get("message", "group_get_snapshot failed"))
            snap = (resp.get("result") or {}).get("snapshot")
            if not isinstance(snap, dict):
                raise NodeError("empty snapshot")
            replaced = self.import_group_snapshot(snap)

            # fetch referenced artifacts (claims + experiences)
            g = self.groups[group_id]
            artifact_hashes: List[str] = []
            for b in g.chain.blocks:
                for tx in b.txs:
                    if tx.get("type") in ("claim", "experience"):
                        h = tx.get("artifact_hash")
                        if isinstance(h, str):
                            artifact_hashes.append(h)

            for h in artifact_hashes:
                if self.cas.has(h):
                    continue
                # fetch from peer
                req2 = {"id": 2, "method": "cas_get", "params": {"hash": h}}
                await write_frame(writer, session.seal(req2))
                env2 = await read_frame(reader)
                resp2 = session.open(env2)
                if resp2.get("error"):
                    err = resp2["error"]
                    logger.warning(f"Failed to fetch artifact {h[:16]}... from {host}:{port}: {err.get('code')}: {err.get('message')}")
                    continue
                r2 = resp2.get("result", {}) or {}
                data_b64 = r2.get("data_b64")
                meta_d = r2.get("meta") or {}
                if not isinstance(data_b64, str):
                    logger.warning(f"Invalid response for artifact {h[:16]}... from {host}:{port}: missing data_b64")
                    continue
                data = b64d(data_b64)
                # integrity check
                if sha256_hex(data) != h:
                    logger.error(f"Integrity check failed for artifact {h[:16]}... from {host}:{port}: hash mismatch")
                    continue
                meta = CasMeta.from_dict(meta_d) if hasattr(CasMeta, "from_dict") else CasMeta(visibility=f"group:{group_id}", kind="artifact", group_id=group_id)
                # force group visibility for group objects
                if meta.visibility != "public":
                    meta.visibility = f"group:{group_id}"
                    meta.group_id = group_id
                self.cas.put(data, meta)
                logger.debug(f"Fetched artifact {h[:16]}... from {host}:{port}")

            # rebuild graph
            self.rebuild_group_graph(group_id)
            self.log_event("sync_group", {"group_id": group_id, "host": host, "port": port, "replaced": replaced})
            return replaced
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    # ---------- peer and group discovery ----------

    async def discover_groups_from_peer(self, host: str, port: int) -> List[Dict[str, Any]]:
        """Discover available groups from a peer.

        Returns list of group info dicts with:
        - group_id, name, currency, height, member_count, is_member, offer_count
        """
        from .p2p import rpc_call
        result = await rpc_call(host, port, self, "group_list_available", {})
        return result.get("groups", [])

    async def register_peer(self, host: str, port: int, alias: Optional[str] = None):
        """Connect to a peer, get their info, and register them.

        Returns the registered Peer object.
        """
        from .p2p import rpc_call
        from .registry import Peer

        # Get peer info via sync_status RPC
        info = await rpc_call(host, port, self, "sync_status", {})

        peer = Peer(
            host=host,
            port=port,
            node_id=info["node_id"],
            sign_pub=info["sign_pub"],
            enc_pub=info["enc_pub"],
            alias=alias,
            last_seen_ms=_now_ms(),
            last_error=None,
            added_ms=_now_ms(),
        )

        self.peer_registry.add_peer(peer)
        self.log_event("peer_add", {"host": host, "port": port, "node_id": peer.node_id})
        return peer

    def subscribe_to_group(
        self,
        group_id: str,
        peer_host: str,
        peer_port: int,
        sync_interval_s: Optional[int] = None,
    ):
        """Subscribe to a group for auto-sync.

        Returns the Subscription object.
        """
        from .config import get_config
        from .registry import Subscription

        config = get_config()
        if sync_interval_s is None:
            sync_interval_s = config.sync.default_sync_interval_s

        # Enforce minimum interval
        sync_interval_s = max(sync_interval_s, config.sync.min_sync_interval_s)

        sub = Subscription(
            group_id=group_id,
            peer_host=peer_host,
            peer_port=peer_port,
            sync_interval_s=sync_interval_s,
            enabled=True,
            last_sync_ms=0,  # Force immediate sync
            last_error=None,
            auto_subscribe=False,
        )

        self.peer_registry.subscribe(sub)
        self.log_event("subscription_add", {"group_id": group_id, "peer": f"{peer_host}:{peer_port}"})
        return sub

    def retract_claim(self, group_id: str, claim_hash: str) -> None:
        with self._lock:
            g = self._require_group(group_id)
            tx = {"type": "retract", "claim_hash": claim_hash, "ts_ms": _now_ms()}
            self._append_block(g, [tx])
            g.graph.retract(claim_hash)
            g.save()
            self.log_event("retract", {"group_id": group_id, "claim_hash": claim_hash})

    def compile_context(
        self, group_id: str, query: str, *, top_k: int = 8, since_ms: Optional[int] = None
    ) -> Tuple[str, List[str]]:
        """Compile context from claims using similarity ranking.

        Args:
            group_id: Group to query
            query: Search query for similarity ranking
            top_k: Number of results to return
            since_ms: Only include claims created after this timestamp (optional)

        Returns:
            Tuple of (formatted context string, list of claim hashes)
        """
        g = self._require_group(group_id)
        slice_text, chosen = g.graph.compile(query, top_k=top_k, since_ms=since_ms)
        return slice_text, chosen

    def get_recent_claims(
        self, group_id: str, since_ms: int, *, limit: int = 100
    ) -> List[Dict[str, Any]]:
        """Get claims created after a timestamp.

        Args:
            group_id: Group to query
            since_ms: Only return claims created after this timestamp
            limit: Maximum number of claims to return

        Returns:
            List of claim dicts sorted by created_ms descending
        """
        g = self._require_group(group_id)
        claims = []
        for h, c in g.graph.claims.items():
            if not c.retracted and c.created_ms >= since_ms:
                claims.append({
                    "claim_hash": h,
                    "text": c.text,
                    "tags": list(c.tags),
                    "created_ms": c.created_ms,
                    "parent_hash": c.parent_hash,
                })
        # Sort by timestamp descending
        claims.sort(key=lambda x: x["created_ms"], reverse=True)
        return claims[:limit]

    # ---------- task management ----------

    def create_task(
        self,
        group_id: str,
        task_id: str,
        title: str,
        *,
        description: str = "",
        assignee: Optional[str] = None,
        due_ms: Optional[int] = None,
        reward: int = 0,
    ) -> str:
        """Create a new task.

        Args:
            group_id: Group where task is created
            task_id: Unique task identifier
            title: Task title
            description: Task description
            assignee: Optional assignee public key (auto-assigns if provided)
            due_ms: Optional deadline timestamp
            reward: Token reward on completion

        Returns:
            task_id
        """
        with self._lock:
            g = self._require_group(group_id)
            tx = {
                "type": "task_create",
                "task_id": task_id,
                "title": title,
                "description": description,
                "ts_ms": _now_ms(),
            }
            if assignee:
                tx["assignee"] = assignee
            if due_ms:
                tx["due_ms"] = due_ms
            if reward > 0:
                tx["reward"] = reward
            self._append_block(g, [tx])
            self.log_event("task_create", {"group_id": group_id, "task_id": task_id})
            logger.debug(f"Created task: id={task_id}, group={group_id}")
            return task_id

    def assign_task(self, group_id: str, task_id: str, assignee: str) -> None:
        """Assign a task to an agent.

        Args:
            group_id: Group containing the task
            task_id: Task to assign
            assignee: Agent public key to assign to
        """
        with self._lock:
            g = self._require_group(group_id)
            tx = {
                "type": "task_assign",
                "task_id": task_id,
                "assignee": assignee,
                "ts_ms": _now_ms(),
            }
            self._append_block(g, [tx])
            self.log_event("task_assign", {"group_id": group_id, "task_id": task_id, "assignee": assignee})

    def start_task(self, group_id: str, task_id: str, *,
                   signer_keys: Optional[NodeKeys] = None) -> None:
        """Mark task as started (assignee only).

        Args:
            group_id: Group containing the task
            task_id: Task to start
            signer_keys: Optional keys to sign with (for multi-agent scenarios)
        """
        with self._lock:
            g = self._require_group(group_id)
            tx = {"type": "task_start", "task_id": task_id, "ts_ms": _now_ms()}
            self._append_block(g, [tx], signer_keys=signer_keys)
            self.log_event("task_start", {"group_id": group_id, "task_id": task_id})

    def complete_task(
        self, group_id: str, task_id: str, *, result_hash: Optional[str] = None,
        signer_keys: Optional[NodeKeys] = None
    ) -> None:
        """Mark task as completed (assignee only).

        Args:
            group_id: Group containing the task
            task_id: Task to complete
            result_hash: Optional CAS hash of result artifact
            signer_keys: Optional keys to sign with (for multi-agent scenarios)
        """
        with self._lock:
            g = self._require_group(group_id)
            tx = {"type": "task_complete", "task_id": task_id, "ts_ms": _now_ms()}
            if result_hash:
                tx["result_hash"] = result_hash
            self._append_block(g, [tx], signer_keys=signer_keys)
            self.log_event("task_complete", {"group_id": group_id, "task_id": task_id, "result_hash": result_hash})

    def fail_task(
        self, group_id: str, task_id: str, *, error_message: str = "",
        signer_keys: Optional[NodeKeys] = None
    ) -> None:
        """Mark task as failed (assignee only).

        Args:
            group_id: Group containing the task
            task_id: Task that failed
            error_message: Optional error message
            signer_keys: Optional keys to sign with (for multi-agent scenarios)
        """
        with self._lock:
            g = self._require_group(group_id)
            tx = {
                "type": "task_fail",
                "task_id": task_id,
                "error_message": error_message,
                "ts_ms": _now_ms(),
            }
            self._append_block(g, [tx], signer_keys=signer_keys)
            self.log_event("task_fail", {"group_id": group_id, "task_id": task_id, "error_message": error_message})

    def get_tasks(
        self, group_id: str, *, status: Optional[str] = None, assignee: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Get tasks with optional filtering.

        Args:
            group_id: Group to query
            status: Filter by status (pending, assigned, in_progress, completed, failed)
            assignee: Filter by assignee public key

        Returns:
            List of task dicts
        """
        g = self._require_group(group_id)
        tasks = list(g.chain.state.tasks.values())
        if status:
            tasks = [t for t in tasks if t["status"] == status]
        if assignee:
            tasks = [t for t in tasks if t.get("assignee") == assignee]
        return tasks

    # ---------- agent presence ----------

    def update_presence(
        self, group_id: str, status: str = "active", *, metadata: Optional[Dict[str, Any]] = None,
        signer_keys: Optional[NodeKeys] = None
    ) -> None:
        """Update agent presence/heartbeat.

        Args:
            group_id: Group where agent is active
            status: Status (active, idle, busy, offline)
            metadata: Optional agent-specific metadata
            signer_keys: Optional keys to sign with (for multi-agent scenarios)
        """
        with self._lock:
            g = self._require_group(group_id)
            tx = {"type": "presence", "status": status, "ts_ms": _now_ms()}
            if metadata:
                tx["metadata"] = metadata
            self._append_block(g, [tx], signer_keys=signer_keys)
            logger.debug(f"Updated presence: status={status}, group={group_id}")

    def get_presence(
        self, group_id: str, *, stale_threshold_ms: int = 300000
    ) -> Dict[str, Dict[str, Any]]:
        """Get presence status of all agents.

        Args:
            group_id: Group to query
            stale_threshold_ms: Time after which agent is considered stale (default: 5 min)

        Returns:
            Dict of pub -> presence info with is_stale and age_ms
        """
        g = self._require_group(group_id)
        now = _now_ms()
        result = {}
        for pub, p in g.chain.state.presence.items():
            age_ms = now - p["last_seen_ms"]
            result[pub] = {
                **p,
                "is_stale": age_ms > stale_threshold_ms,
                "age_ms": age_ms,
            }
        return result

    # ---------- offers / market ----------

    def create_offer(
        self,
        group_id: str,
        *,
        title: str,
        text: str,
        price: int,
        tags: List[str],
        description: str = "",
        splits: Optional[List[Dict[str, Any]]] = None,
        parents: Optional[List[Dict[str, Any]]] = None,
        announce_host: str = "127.0.0.1",
        announce_port: int = 0,
        expires_in_ms: Optional[int] = None,
    ) -> Tuple[str, str]:
        """Creates an encrypted package offer and stores an announcement in the local offer book.

        Args:
            expires_in_ms: Optional expiration time in milliseconds from now.
                          If None, offer never expires.
        """
        # Validate inputs
        title = validate_offer_title(title)
        text = validate_claim_text(text)  # Reuse claim text validation for offer content
        description = validate_offer_description(description)
        price = validate_price(price)
        tags = validate_tags(tags)

        # Calculate expiration timestamp
        expires_ms = None
        if expires_in_ms is not None:
            if expires_in_ms <= 0:
                raise ValidationError("expires_in_ms", "must be positive")
            expires_ms = _now_ms() + expires_in_ms

        with self._lock:
            g = self._require_group(group_id)
            # package plaintext
            pkg = {
                "v": 1,
                "kind": "knowledge_package",
                "group_id": group_id,
                "title": title,
                "description": description,
                "tags": tags,
                "text": text,
                "created_ms": _now_ms(),
                "creator": self.keys.sign_pub_b64,
            }
            pkg_bytes = json.dumps(pkg, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
            aad = f"offer|{group_id}|{title}".encode("utf-8")
            env_bytes, sym_key = encrypt_package(pkg_bytes, aad=aad)
            package_hash = self.cas.put(env_bytes, CasMeta(visibility="public", kind="package", group_id=group_id))
            # deterministic offer id
            offer_id = sha256_hex(f"{group_id}|{package_hash}|{self.keys.sign_pub_b64}|{_now_ms()}".encode("utf-8"))[:16]
            offer = Offer(
                offer_id=offer_id,
                group_id=group_id,
                seller=self.keys.sign_pub_b64,
                package_hash=package_hash,
                title=title,
                description=description,
                tags=tags,
                price=int(price),
                currency=g.chain.state.policy.currency,
                splits=splits or [{"pub": self.keys.sign_pub_b64, "bps": 10000}],
                parents=parents or [],
                active=True,
                created_ms=_now_ms(),
                expires_ms=expires_ms,
            )
            tx = {"type": "offer_create", "offer": offer.to_dict(), "ts_ms": _now_ms()}
            self._append_block(g, [tx])
            g.save()

            # Create announcement + sign
            ann = self._make_offer_announcement(
                offer=offer,
                host=announce_host,
                port=int(announce_port),
                sym_key=sym_key,
            )
            # Store package key in seller wallet too (optional convenience)
            w = self._wallet_keys()
            w[package_hash] = b64e(sym_key)
            self._save_wallet_keys(w)

            self.offer_book[offer_id] = ann.to_dict()
            self._save_offer_book()
            self.log_event("offer_create", {"group_id": group_id, "offer_id": offer_id, "package_hash": package_hash, "price": price})
            return offer_id, package_hash

    def _make_offer_announcement(self, offer: Offer, *, host: str, port: int, sym_key: bytes) -> OfferAnnouncement:
        # signature is over the announcement body
        from .keys import sign_detached
        body = {
            "offer_id": offer.offer_id,
            "group_id": offer.group_id,
            "seller_sign_pub": self.keys.sign_pub_b64,
            "seller_enc_pub": self.keys.enc_pub_b64,
            "host": host,
            "port": int(port),
            "package_hash": offer.package_hash,
            "title": offer.title,
            "tags": offer.tags,
            "price": int(offer.price),
            "currency": offer.currency,
            "created_ms": int(offer.created_ms),
        }
        if offer.expires_ms is not None:
            body["expires_ms"] = int(offer.expires_ms)
        sig = sign_detached(self.keys.sign_priv, canonical_json(body).encode("utf-8"))
        return OfferAnnouncement(
            offer_id=offer.offer_id,
            group_id=offer.group_id,
            seller_sign_pub=self.keys.sign_pub_b64,
            seller_enc_pub=self.keys.enc_pub_b64,
            host=host,
            port=int(port),
            package_hash=offer.package_hash,
            title=offer.title,
            tags=offer.tags,
            price=offer.price,
            currency=offer.currency,
            created_ms=offer.created_ms,
            sig=b64e(sig),
            expires_ms=offer.expires_ms,
        )

    def list_offers(self) -> List[OfferAnnouncement]:
        """List all offer announcements in the offer book (thread-safe)."""
        out = []
        with self._lock:
            items = list(self.offer_book.items())
        for offer_id, d in sorted(items):
            try:
                out.append(OfferAnnouncement.from_dict(d))
            except Exception as e:
                logger.warning(f"Failed to parse offer announcement {offer_id}: {type(e).__name__}: {e}")
                continue
        return out

    def import_offer_announcements(self, anns: List[Dict[str, Any]], *, max_import: int = 1000) -> int:
        """Adds valid announcements to the offer book (thread-safe).

        Args:
            anns: List of offer announcement dictionaries
            max_import: Maximum number of offers to import (default: 1000)

        Returns:
            Number of offers imported
        """
        from .keys import verify_detached, load_sign_pub_raw

        # Limit input size to prevent DoS
        if len(anns) > max_import:
            logger.warning(f"Truncating offer import from {len(anns)} to {max_import}")
            anns = anns[:max_import]

        n = 0
        rejected = 0
        accepted = []

        for d in anns:
            try:
                ann = OfferAnnouncement.from_dict(d)
                body = ann.body()
                pub = load_sign_pub_raw(b64d(ann.seller_sign_pub))
                if not verify_detached(pub, canonical_json(body).encode("utf-8"), b64d(ann.sig)):
                    logger.debug(f"Rejected offer {ann.offer_id}: invalid signature")
                    rejected += 1
                    continue
                # accept
                accepted.append((ann.offer_id, ann.to_dict()))
                n += 1
            except Exception as e:
                logger.debug(f"Failed to parse offer announcement: {type(e).__name__}: {e}")
                rejected += 1
                continue

        # Update offer book with lock
        if accepted:
            with self._lock:
                for offer_id, offer_dict in accepted:
                    self.offer_book[offer_id] = offer_dict
                self._save_offer_book()

        if rejected:
            logger.debug(f"Rejected {rejected} invalid offer announcements")
        return n

    # ---------- purchase (buyer side) ----------

    async def purchase_offer_from_peer(self, *, host: str, port: int, offer_id: str, timeout: float = 30.0) -> Tuple[str, bytes]:
        """Purchases an offer from a remote node. Returns (package_hash, plaintext_bytes).

        Args:
            host: Seller host address
            port: Seller port
            offer_id: Offer ID to purchase
            timeout: Connection and operation timeout in seconds (default: 30s)
        """
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=timeout
            )
        except asyncio.TimeoutError:
            raise NodeError(f"Connection to {host}:{port} timed out")
        try:
            session = await client_handshake(reader, writer, self.keys)
            # create purchase tx
            req_tx = self._make_purchase_tx(offer_id)
            req = {"id": 1, "method": "market_purchase", "params": {"purchase_tx": req_tx}}
            await write_frame(writer, session.seal(req))
            env = await read_frame(reader)
            resp = session.open(env)
            if resp.get("id") != 1:
                raise NodeError("bad response id")
            if resp.get("error"):
                raise NodeError(resp["error"].get("message", "purchase failed"))
            result = resp.get("result", {}) or {}
            package_hash = str(result["package_hash"])
            sealed_key = result["sealed_key"]
            aad = result.get("aad_b64", "")
            aad_bytes = b64d(aad) if isinstance(aad, str) and aad else b""
            # decrypt symmetric key
            sym = open_from_x25519(self.keys.enc_priv, sealed_key, context=b"lb-package-key")
            # store in wallet
            w = self._wallet_keys()
            w[package_hash] = b64e(sym)
            self._save_wallet_keys(w)
            # fetch package bytes
            pkg_env = await self._fetch_cas_object(session, reader, writer, package_hash)
            pt = decrypt_package(pkg_env, key=sym, aad=aad_bytes if aad_bytes else None)
            self.log_event("purchase", {"offer_id": offer_id, "host": host, "port": port, "package_hash": package_hash})
            return package_hash, pt
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    async def _fetch_cas_object(self, session: SecureSession, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, h: str) -> bytes:
        req = {"id": 2, "method": "cas_get", "params": {"hash": h}}
        await write_frame(writer, session.seal(req))
        env = await read_frame(reader)
        resp = session.open(env)
        if resp.get("id") != 2:
            raise NodeError("bad response id")
        if resp.get("error"):
            raise NodeError(resp["error"].get("message", "cas_get failed"))
        b64 = resp["result"]["data_b64"]
        return b64d(b64)

    def _make_purchase_tx(self, offer_id: str) -> Dict[str, Any]:
        # Use local offer book for amount/currency
        ann_d = self.offer_book.get(offer_id)
        if not ann_d:
            raise NodeError("unknown offer id in local offer book (run market-pull)")
        ann = OfferAnnouncement.from_dict(ann_d)
        # Generate cryptographically strong nonce (full SHA256 = 64 hex chars = 256 bits)
        nonce = sha256_hex(os.urandom(32))
        body = {
            "type": "purchase",
            "group_id": ann.group_id,
            "offer_id": offer_id,
            "buyer": self.keys.sign_pub_b64,
            "buyer_enc_pub": self.keys.enc_pub_b64,
            "amount": int(ann.price),
            "nonce": nonce,
            "ts_ms": _now_ms(),
        }
        from .keys import sign_detached
        sig = sign_detached(self.keys.sign_priv, canonical_json(body).encode("utf-8"))
        body["sig"] = b64e(sig)
        return body

    # ---------- internal helpers ----------

    def _require_group(self, group_id: str) -> Group:
        g = self.groups.get(group_id)
        if not g:
            raise NodeError(f"unknown group_id {group_id}")
        return g

    def _append_block(self, g: Group, txs: List[Dict[str, Any]], *,
                      signer_keys: Optional[NodeKeys] = None) -> Block:
        """Append a block to the group chain.

        Args:
            g: The group to append to
            txs: List of transactions
            signer_keys: Optional keys to sign the block with. If not provided,
                        uses the node's default keys. This allows agents to sign
                        blocks with their own identity.

        Uses WAL (Write-Ahead Log) for atomic persistence of chain + graph state.
        """
        keys = signer_keys or self.keys
        b = Block.make(
            g.chain.state.group_id,
            g.chain.head.height + 1,
            g.chain.head.block_id,
            author_priv=keys.sign_priv,
            author_pub_b64=keys.sign_pub_b64,
            txs=txs,
        )
        g.chain.append(b)
        # Use WAL for atomic multi-file persistence
        with self.wal.transaction() as tx:
            g.save(wal_tx=tx)
        return b

    # ---------- group snapshot import/export ----------

    def export_group_snapshot(self, group_id: str) -> Dict[str, Any]:
        g = self._require_group(group_id)
        return g.chain.snapshot()

    def import_group_snapshot(self, snapshot: Dict[str, Any]) -> bool:
        """Imports group snapshot if it's better than local. Returns True if replaced.

        Fork resolution strategy:
        1. If no local chain exists, accept the incoming chain
        2. If incoming chain extends local chain (same prefix), accept it
        3. If chains diverge (fork), use weighted comparison:
           - Prefer longer chain (more work)
           - On tie, prefer chain with more unique authors (more decentralized)
           - On tie, prefer chain with lower cumulative hash (deterministic)
        4. Log warnings when forks are detected
        """
        chain = Chain.from_snapshot(snapshot)
        gid = chain.state.group_id
        with self._lock:
            local = self.groups.get(gid)
            if local is None:
                root = self.groups_dir / gid
                g = Group(group_id=gid, root=root, chain=chain, graph=ContextGraph())
                g.save()
                self.groups[gid] = g
                return True

            # Check if incoming chain extends local (no conflict)
            if self._chain_extends(local.chain, chain):
                local.chain = chain
                local.save()
                return True

            # Check if local extends incoming (incoming is stale)
            if self._chain_extends(chain, local.chain):
                return False

            # Fork detected - use weighted comparison
            local_score = self._chain_score(local.chain)
            incoming_score = self._chain_score(chain)

            logger.warning(
                f"Fork detected in group {gid}: local_height={local.chain.head.height}, "
                f"incoming_height={chain.head.height}, local_score={local_score}, "
                f"incoming_score={incoming_score}"
            )

            self.log_event("fork_detected", {
                "group_id": gid,
                "local_height": local.chain.head.height,
                "incoming_height": chain.head.height,
                "local_score": local_score,
                "incoming_score": incoming_score,
            })

            if incoming_score > local_score:
                logger.info(f"Accepting incoming chain for group {gid} (higher score)")
                local.chain = chain
                local.save()
                return True
            logger.info(f"Keeping local chain for group {gid} (higher or equal score)")
            return False

    def _chain_extends(self, base: Chain, candidate: Chain) -> bool:
        """Check if candidate chain extends base chain (shares same prefix)."""
        if candidate.head.height <= base.head.height:
            return False
        # Check that all base blocks are in candidate
        for i, b in enumerate(base.blocks):
            if i >= len(candidate.blocks):
                return False
            if candidate.blocks[i].block_id != b.block_id:
                return False
        return True

    def _chain_score(self, chain: Chain) -> Tuple[int, int, int, str]:
        """Calculate chain score for fork resolution.

        Returns tuple for comparison: (height, unique_authors, total_work, block_id)
        Higher is better. Block ID comparison is lexicographic (deterministic tie-break).

        Scoring rationale:
        1. Longer chain = more work committed
        2. More unique authors = more decentralized (harder to forge)
        3. Total work = sum of block heights (rewards consistent building)
        4. Block ID = deterministic tie-break when all else equal
        """
        unique_authors = len(set(b.author for b in chain.blocks))
        # Total work approximation: sum of heights (penalizes gaps)
        total_work = sum(b.height for b in chain.blocks)
        # Use block_id directly for deterministic comparison (lexicographic on hex)
        return (chain.head.height, unique_authors, total_work, chain.head.block_id)
