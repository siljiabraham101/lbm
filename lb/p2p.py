from __future__ import annotations

import asyncio
import time
from typing import Any, Dict, Optional, List

from .node import BatteryNode
from .discovery import DiscoveryService
from .secure_channel import server_handshake, client_handshake, HandshakeError, SecureSession
from .wire import read_frame, write_frame
from .keys import b64e, b64d
from .crypto import seal_to_x25519
from . import __version__
from .logging_config import get_p2p_logger
from .rate_limit import get_rate_limiter
from .config import get_config
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey

logger = get_p2p_logger()

# Default timeouts
DEFAULT_READ_TIMEOUT = 30.0  # seconds
DEFAULT_IDLE_TIMEOUT = 300.0  # 5 minutes for idle connections

JsonDict = Dict[str, Any]


class RPCError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


def _err(code: str, message: str) -> Dict[str, Any]:
    return {"code": code, "message": message}


class P2PServer:
    def __init__(self, node: BatteryNode):
        self.node = node
        self._server: Optional[asyncio.AbstractServer] = None
        self._shutdown_event: Optional[asyncio.Event] = None
        self._active_connections: int = 0
        self._connections_lock = asyncio.Lock()
        self._discovery: Optional[DiscoveryService] = None

    async def start(self, host: str, port: int) -> None:
        self._shutdown_event = asyncio.Event()
        self._server = await asyncio.start_server(self._handle, host, port)
        addr = self._server.sockets[0].getsockname() if self._server.sockets else (host, port)
        logger.info(f"P2P server started on {addr[0]}:{addr[1]}")

        # Start Discovery
        config = get_config()
        if config.discovery.enabled:
            self._discovery = DiscoveryService(self.node, port)
            await self._discovery.start()

    async def serve_forever(self) -> None:
        if self._server is None:
            raise RuntimeError("server not started")
        async with self._server:
            await self._server.serve_forever()

    async def stop(self, timeout: float = 5.0) -> None:
        """Gracefully stop the server.

        Args:
            timeout: Maximum time to wait for connections to close
        """
        if self._server is None:
            return

        logger.info("Initiating graceful shutdown...")

        # Stop Discovery
        if self._discovery:
            await self._discovery.stop()
            self._discovery = None

        # Stop accepting new connections
        self._server.close()
        await self._server.wait_closed()

        # Wait for active connections to finish (with timeout)
        if self._shutdown_event:
            self._shutdown_event.set()

        start = time.time()
        while time.time() - start < timeout:
            async with self._connections_lock:
                if self._active_connections == 0:
                    break
            await asyncio.sleep(0.1)

        async with self._connections_lock:
            if self._active_connections > 0:
                logger.warning(f"Shutdown timeout: {self._active_connections} connections still active")
            else:
                logger.info("All connections closed gracefully")

        self._server = None

    @property
    def is_running(self) -> bool:
        return self._server is not None and self._server.is_serving()

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer_addr = writer.get_extra_info("peername", ("unknown", 0))
        peer_ip = peer_addr[0] if isinstance(peer_addr, tuple) else str(peer_addr)
        logger.debug(f"New connection from {peer_addr}")

        # Track connection
        async with self._connections_lock:
            self._active_connections += 1

        # Get timeouts from config
        config = get_config()
        read_timeout = config.p2p.read_timeout_s
        idle_timeout = config.p2p.idle_timeout_s

        # Track if connection slot was acquired (for proper cleanup)
        connection_acquired = False
        session: Optional[SecureSession] = None
        peer_sign: Optional[str] = None

        # Rate limit: check connection limit per IP
        rate_limiter = get_rate_limiter()
        try:
            conn_result = await rate_limiter.check_connection(peer_ip)
        except Exception as e:
            logger.warning(f"Rate limiter error for {peer_ip}: {e}")
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
            return

        if not conn_result.allowed:
            logger.warning(f"Connection rejected from {peer_ip}: {conn_result.reason}")
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
            return

        # Connection slot acquired - must release in finally block
        connection_acquired = True

        try:
            # Handshake with timeout
            try:
                session = await asyncio.wait_for(
                    server_handshake(reader, writer, self.node.keys),
                    timeout=read_timeout
                )
            except asyncio.TimeoutError:
                logger.warning(f"Handshake timeout from {peer_addr}")
                return
            except Exception as e:
                logger.warning(f"Handshake failed from {peer_addr}: {e}")
                return

            peer_sign = session.peer_sign_pub
            logger.info(f"Authenticated peer {peer_sign[:16]}... from {peer_addr}")

            # Main request loop
            while True:
                try:
                    # Read with idle timeout
                    env = await asyncio.wait_for(read_frame(reader), timeout=idle_timeout)
                except asyncio.TimeoutError:
                    logger.debug(f"Client {peer_sign[:16]}... idle timeout ({idle_timeout}s)")
                    break
                except asyncio.IncompleteReadError:
                    logger.debug(f"Client {peer_sign[:16]}... disconnected (incomplete read)")
                    break
                except ConnectionResetError:
                    logger.debug(f"Client {peer_sign[:16]}... connection reset")
                    break
                except Exception as e:
                    logger.warning(f"Error reading from {peer_sign[:16]}...: {type(e).__name__}: {e}")
                    break
                try:
                    req = session.open(env)
                except Exception as e:
                    logger.warning(f"Failed to decrypt message from {peer_sign[:16]}...: {e}")
                    break

                # Rate limit: check request rate per peer
                req_result = await rate_limiter.check_request(peer_sign)
                if not req_result.allowed:
                    logger.warning(f"Request rate limit exceeded for {peer_sign[:16]}...: {req_result.reason}")
                    resp = {"id": req.get("id"), "result": None, "error": _err("rate_limited", req_result.reason)}
                    try:
                        await write_frame(writer, session.seal(resp))
                    except Exception:
                        break
                    continue

                rid = req.get("id")
                method = req.get("method")
                params = req.get("params") or {}
                resp: Dict[str, Any] = {"id": rid, "result": None, "error": None}

                try:
                    if method == "ping":
                        resp["result"] = {"pong": True}
                    elif method == "health":
                        # Health check endpoint
                        resp["result"] = {
                            "status": "healthy",
                            "node_id": self.node.node_id,
                            "version": __version__,
                            "groups_count": len(self.node.groups),
                            "offers_count": len(self.node.offer_book),
                            "timestamp_ms": int(time.time() * 1000),
                        }
                    elif method == "node_info":
                        resp["result"] = {
                            "node_id": self.node.node_id,
                            "sign_pub": self.node.keys.sign_pub_b64,
                            "enc_pub": self.node.keys.enc_pub_b64,
                            "version": __version__,
                        }
                    elif method == "group_get_snapshot":
                        gid = params.get("group_id")
                        if not isinstance(gid, str) or gid not in self.node.groups:
                            raise RPCError("not_found", "unknown group")
                        g = self.node.groups[gid]
                        # TOCTOU fix: verify membership at specific chain state if provided
                        at_head = params.get("at_head")  # Optional chain head for TOCTOU prevention
                        if at_head is not None and g.chain.head.block_id != at_head:
                            raise RPCError("stale_state", f"chain advanced, current head: {g.chain.head.block_id}")
                        if peer_sign not in g.chain.state.members:
                            raise RPCError("forbidden", "not a group member")
                        resp["result"] = {"group_id": gid, "snapshot": g.chain.snapshot(), "head": g.chain.head.block_id}
                    elif method == "cas_get":
                        h = params.get("hash")
                        if not isinstance(h, str):
                            raise RPCError("bad_request", "missing hash")
                        meta = self.node.cas.meta(h)
                        if meta is None:
                            raise RPCError("not_found", "unknown object")
                        if meta.visibility == "public":
                            data = self.node.cas.get(h)
                            resp["result"] = {"hash": h, "data_b64": b64e(data), "meta": meta.to_dict()}
                        elif meta.visibility.startswith("group:"):
                            # Parse group visibility carefully
                            parts = meta.visibility.split(":", 1)
                            if len(parts) != 2 or not parts[1]:
                                raise RPCError("forbidden", "malformed visibility")
                            gid = parts[1]
                            g = self.node.groups.get(gid)
                            if g is None:
                                raise RPCError("forbidden", "not authorized for object")
                            # TOCTOU fix: verify membership at specific chain state if provided
                            at_head = params.get("at_head")
                            if at_head is not None and g.chain.head.block_id != at_head:
                                raise RPCError("stale_state", f"chain advanced, current head: {g.chain.head.block_id}")
                            if peer_sign not in g.chain.state.members:
                                raise RPCError("forbidden", "not authorized for object")
                            data = self.node.cas.get(h)
                            resp["result"] = {"hash": h, "data_b64": b64e(data), "meta": meta.to_dict(), "head": g.chain.head.block_id}
                        else:
                            raise RPCError("forbidden", "unknown visibility")
                    elif method == "market_list_offers":
                        resp["result"] = {"offers": list(self.node.offer_book.values())}
                    elif method == "market_announce_offers":
                        offers = params.get("offers", [])
                        if not isinstance(offers, list):
                            raise RPCError("bad_request", "offers must be list")
                        n = self.node.import_offer_announcements(offers)  # signature-checked
                        resp["result"] = {"imported": n}
                    elif method == "market_purchase":
                        purchase_tx = params.get("purchase_tx")
                        if not isinstance(purchase_tx, dict):
                            raise RPCError("bad_request", "missing purchase_tx")
                        # enforce that tx buyer matches handshake identity
                        if purchase_tx.get("buyer") != peer_sign:
                            raise RPCError("forbidden", "buyer mismatch")
                        if purchase_tx.get("buyer_enc_pub") != session.peer_enc_pub:
                            raise RPCError("forbidden", "buyer enc_pub mismatch")
                        offer_id = purchase_tx.get("offer_id")
                        group_id = purchase_tx.get("group_id")
                        if not isinstance(offer_id, str) or not isinstance(group_id, str):
                            raise RPCError("bad_request", "purchase_tx must include offer_id and group_id")
                        g = self.node.groups.get(group_id)
                        if g is None:
                            raise RPCError("not_found", "unknown group")
                        offer = g.chain.state.offers.get(offer_id)
                        if offer is None or not offer.active:
                            raise RPCError("not_found", "unknown or inactive offer")

                        # seller must have the symmetric key
                        w = self.node._wallet_keys()  # internal wallet store
                        sym_b64 = w.get(offer.package_hash)
                        if not sym_b64:
                            raise RPCError("internal", "seller missing package key in wallet")

                        sym = b64d(sym_b64)

                        # seal key to buyer
                        buyer_enc = X25519PublicKey.from_public_bytes(b64d(session.peer_enc_pub))
                        sealed = seal_to_x25519(buyer_enc, sym, context=b"lb-package-key")

                        grant_tx = {
                            "type": "grant",
                            "offer_id": offer_id,
                            "buyer": peer_sign,
                            "package_hash": offer.package_hash,
                            "sealed_key": sealed,
                            "ts_ms": int(time.time() * 1000),
                        }

                        # append block with purchase and grant
                        try:
                            self.node._append_block(g, [purchase_tx, grant_tx])
                        except Exception as e:
                            raise RPCError("rejected", str(e))

                        # Compute AAD (must match what was used during encryption)
                        aad = f"offer|{offer.group_id}|{offer.title}".encode("utf-8")

                        # return sealed key + package hash + aad
                        resp["result"] = {
                            "package_hash": offer.package_hash,
                            "sealed_key": sealed,
                            "aad_b64": b64e(aad),
                        }
                    elif method == "group_list_available":
                        # Discovery: list groups available on this node
                        groups_info = []
                        for gid, g in self.node.groups.items():
                            state = g.chain.state
                            info = {
                                "group_id": gid,
                                "name": state.policy.name,
                                "currency": state.policy.currency,
                                "height": g.chain.head.height,
                                "member_count": len(state.members),
                                "is_member": peer_sign in state.members,
                                "offer_count": len(state.offers),
                            }
                            groups_info.append(info)
                        resp["result"] = {"groups": groups_info}
                    elif method == "peer_exchange":
                        # Exchange peer information (gossip foundation)
                        incoming_peers = params.get("peers", [])
                        if not isinstance(incoming_peers, list):
                            raise RPCError("bad_request", "peers must be list")
                        # Return our known peers (limited to 50)
                        our_peers = []
                        if hasattr(self.node, 'peer_registry') and self.node.peer_registry:
                            for p in self.node.peer_registry.list_peers()[:50]:
                                our_peers.append({
                                    "host": p.host,
                                    "port": p.port,
                                    "node_id": p.node_id,
                                    "sign_pub": p.sign_pub,
                                    "enc_pub": p.enc_pub,
                                })
                        resp["result"] = {"peers": our_peers}
                    elif method == "sync_status":
                        # Extended health check for sync daemon use
                        resp["result"] = {
                            "node_id": self.node.node_id,
                            "sign_pub": self.node.keys.sign_pub_b64,
                            "enc_pub": self.node.keys.enc_pub_b64,
                            "groups": {
                                gid: {
                                    "height": g.chain.head.height,
                                    "head_hash": g.chain.head.block_id,
                                }
                                for gid, g in self.node.groups.items()
                            },
                            "timestamp_ms": int(time.time() * 1000),
                        }
                    else:
                        raise RPCError("not_found", f"unknown method {method}")
                except RPCError as e:
                    logger.warning(f"RPC error for {method} from {peer_sign[:16]}...: {e.code}: {e.message}")
                    resp["error"] = _err(e.code, e.message)
                except Exception as e:
                    logger.error(f"Internal error for {method} from {peer_sign[:16]}...: {e}", exc_info=True)
                    resp["error"] = _err("internal", "internal server error")

                try:
                    await write_frame(writer, session.seal(resp))
                except BrokenPipeError:
                    logger.debug(f"Client {peer_sign[:16]}... connection broken (write)")
                    break
                except Exception as e:
                    logger.warning(f"Error writing to {peer_sign[:16]}...: {type(e).__name__}: {e}")
                    break
        finally:
            # Always release connection slot when done
            if connection_acquired:
                await rate_limiter.release_connection(peer_ip)

            # Decrement active connection count
            async with self._connections_lock:
                self._active_connections -= 1

            # Close connection
            log_id = peer_sign[:16] if peer_sign else peer_ip
            logger.debug(f"Closing connection to {log_id}...")
            try:
                writer.close()
                await writer.wait_closed()
            except Exception as e:
                logger.debug(f"Error closing connection to {log_id}: {e}")


async def rpc_call(host: str, port: int, node: BatteryNode, method: str, params: Optional[Dict[str, Any]] = None, *, req_id: int = 1) -> Dict[str, Any]:
    """Make an RPC call to a remote node.

    Args:
        host: Remote host address
        port: Remote port
        node: Local node for authentication
        method: RPC method name
        params: Optional method parameters
        req_id: Request ID

    Returns:
        RPC result dictionary

    Raises:
        RPCError: If the RPC call fails
        ConnectionError: If connection fails
    """
    logger.debug(f"RPC call to {host}:{port} method={method}")
    try:
        reader, writer = await asyncio.open_connection(host, port)
    except OSError as e:
        logger.error(f"Failed to connect to {host}:{port}: {e}")
        raise ConnectionError(f"Failed to connect to {host}:{port}: {e}") from e

    try:
        session = await client_handshake(reader, writer, node.keys)
        req = {"id": req_id, "method": method, "params": params or {}}
        await write_frame(writer, session.seal(req))
        env = await read_frame(reader)
        resp = session.open(env)
        if resp.get("error"):
            err = resp["error"]
            logger.warning(f"RPC error from {host}:{port}: {err.get('code')}: {err.get('message')}")
            raise RPCError(err.get("code", "error"), err.get("message", "error"))
        logger.debug(f"RPC call to {host}:{port} method={method} succeeded")
        return resp.get("result") or {}
    except RPCError:
        raise
    except Exception as e:
        logger.error(f"RPC call to {host}:{port} failed: {type(e).__name__}: {e}")
        raise
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception as e:
            logger.debug(f"Error closing connection to {host}:{port}: {e}")
