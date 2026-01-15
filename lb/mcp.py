"""
MCP (Model Context Protocol) interface for Learning Battery Market.

This module provides a JSON-RPC over stdin/stdout interface for AI agent
integration. It allows agents to publish claims, query context, manage tasks,
and interact with the knowledge market.

IMPORTANT: Single Identity Limitation
=====================================
The MCP interface operates with the identity of the node it's connected to.
All operations (claims, tasks, presence) are signed by the node's key.

For multi-agent scenarios where each agent needs a distinct identity:
- Use the Python API directly with the `signer_keys` parameter
- Generate per-agent keys via `gen_node_keys()`
- Pass agent keys to methods like `publish_claim()`, `start_task()`, etc.

Example multi-agent setup (Python API):
    from lb.keys import gen_node_keys
    from lb.node import BatteryNode

    node = BatteryNode.load(data_dir)
    agent_keys = gen_node_keys()
    node.add_member(group_id, agent_keys.sign_pub_b64, role="member")
    node.publish_claim(group_id, "content", ["tags"], signer_keys=agent_keys)

The MCP interface is best suited for:
- Single-agent integrations
- Centralized coordinator patterns where one identity manages all operations
"""
from __future__ import annotations

import asyncio
import base64
import json
import sys
from typing import Any, Dict, List

from . import __version__
from .node import BatteryNode, NodeError


class MCPParamError(Exception):
    """Error for missing or invalid MCP parameters."""
    def __init__(self, field: str, message: str = "is required"):
        self.field = field
        super().__init__(f"{field} {message}")


def _require(params: Dict[str, Any], field: str) -> Any:
    """Get a required parameter, raising MCPParamError if missing."""
    if field not in params:
        raise MCPParamError(field)
    return params[field]


def _require_str(params: Dict[str, Any], field: str) -> str:
    """Get a required string parameter."""
    value = _require(params, field)
    if not isinstance(value, str):
        raise MCPParamError(field, "must be a string")
    return value


def _require_int(params: Dict[str, Any], field: str) -> int:
    """Get a required integer parameter."""
    value = _require(params, field)
    try:
        return int(value)
    except (ValueError, TypeError):
        raise MCPParamError(field, "must be an integer")


def _ok(rid: Any, result: Any) -> None:
    sys.stdout.write(json.dumps({"id": rid, "result": result, "error": None}, ensure_ascii=False) + "\n")
    sys.stdout.flush()


def _err(rid: Any, code: str, message: str) -> None:
    sys.stdout.write(json.dumps({"id": rid, "result": None, "error": {"code": code, "message": message}}, ensure_ascii=False) + "\n")
    sys.stdout.flush()


def run_mcp(data_dir: str) -> None:
    node = BatteryNode.load(data_dir)

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except Exception as e:
            _err(None, "bad_json", str(e))
            continue

        rid = req.get("id")
        method = req.get("method")
        params = req.get("params") or {}

        try:
            if method == "initialize":
                _ok(rid, {"node_id": node.node_id, "sign_pub": node.keys.sign_pub_b64, "enc_pub": node.keys.enc_pub_b64, "version": __version__})
            elif method == "list_groups":
                gs = []
                for gid, g in node.groups.items():
                    gs.append({"group_id": gid, "name": g.chain.state.policy.name, "currency": g.chain.state.policy.currency})
                _ok(rid, {"groups": gs})
            elif method == "publish_claim":
                gid = params["group_id"]
                text = params["text"]
                tags = list(params.get("tags", []))
                parent_hash = params.get("parent_hash")  # Optional threading
                h = node.publish_claim(gid, text, tags, parent_hash=parent_hash)
                _ok(rid, {"claim_hash": h})
            elif method == "retract_claim":
                node.retract_claim(params["group_id"], params["claim_hash"])
                _ok(rid, {"ok": True})
            elif method == "submit_experience":
                gid = params["group_id"]
                exp = params.get("experience", {}) or {}
                h = node.submit_experience(gid, exp)
                _ok(rid, {"experience_hash": h})
            elif method == "compile_context":
                gid = params["group_id"]
                q = params["query"]
                top_k = int(params.get("top_k", 8))
                since_ms = params.get("since_ms")  # Optional time filter
                if since_ms is not None:
                    since_ms = int(since_ms)
                text, chosen = node.compile_context(gid, q, top_k=top_k, since_ms=since_ms)
                _ok(rid, {"context": text, "claim_hashes": chosen})
            elif method == "create_offer":
                gid = params["group_id"]
                title = params["title"]
                text = params["text"]
                price = int(params["price"])
                tags = list(params.get("tags", []))
                host = str(params.get("announce_host", "127.0.0.1"))
                port = int(params.get("announce_port", 0))
                offer_id, package_hash = node.create_offer(gid, title=title, text=text, price=price, tags=tags, announce_host=host, announce_port=port)
                _ok(rid, {"offer_id": offer_id, "package_hash": package_hash})
            elif method == "list_offers":
                _ok(rid, {"offers": [o.to_dict() for o in node.list_offers()]})
            elif method == "market_pull":
                host = params["host"]
                port = int(params["port"])
                n = asyncio.run(node.pull_market_offers_from_peer(host, port))
                _ok(rid, {"imported": n})
            elif method == "sync_group":
                host = params["host"]
                port = int(params["port"])
                gid = params["group_id"]
                replaced = asyncio.run(node.sync_group_from_peer(host, port, gid))
                _ok(rid, {"replaced": replaced})
            elif method == "purchase_offer":
                host = params["host"]
                port = int(params["port"])
                offer_id = params["offer_id"]
                package_hash, pt = asyncio.run(node.purchase_offer_from_peer(host=host, port=port, offer_id=offer_id))
                # attempt to decode json package
                try:
                    pkg = json.loads(pt.decode("utf-8"))
                except Exception:
                    pkg = {"raw_b64": base64.b64encode(pt).decode("ascii")}
                _ok(rid, {"package_hash": package_hash, "package": pkg})

            # ========== Task Management ==========
            elif method == "create_task":
                gid = _require_str(params, "group_id")
                task_id = _require_str(params, "task_id")
                title = _require_str(params, "title")
                description = params.get("description", "")
                assignee = params.get("assignee")
                due_ms = int(params["due_ms"]) if params.get("due_ms") else None
                reward = int(params.get("reward", 0))
                node.create_task(gid, task_id, title, description=description, assignee=assignee, due_ms=due_ms, reward=reward)
                _ok(rid, {"task_id": task_id})

            elif method == "assign_task":
                gid = _require_str(params, "group_id")
                task_id = _require_str(params, "task_id")
                assignee = _require_str(params, "assignee")
                node.assign_task(gid, task_id, assignee)
                _ok(rid, {"ok": True})

            elif method == "start_task":
                gid = _require_str(params, "group_id")
                task_id = _require_str(params, "task_id")
                node.start_task(gid, task_id)
                _ok(rid, {"ok": True})

            elif method == "complete_task":
                gid = _require_str(params, "group_id")
                task_id = _require_str(params, "task_id")
                result_hash = params.get("result_hash")
                node.complete_task(gid, task_id, result_hash=result_hash)
                _ok(rid, {"ok": True})

            elif method == "fail_task":
                gid = _require_str(params, "group_id")
                task_id = _require_str(params, "task_id")
                error_message = params.get("error_message", "")
                node.fail_task(gid, task_id, error_message=error_message)
                _ok(rid, {"ok": True})

            elif method == "list_tasks":
                gid = _require_str(params, "group_id")
                status = params.get("status")
                assignee = params.get("assignee")
                tasks = node.get_tasks(gid, status=status, assignee=assignee)
                _ok(rid, {"tasks": tasks})

            # ========== Agent Presence ==========
            elif method == "update_presence":
                gid = _require_str(params, "group_id")
                status = params.get("status", "active")
                metadata = params.get("metadata")
                node.update_presence(gid, status, metadata=metadata)
                _ok(rid, {"ok": True})

            elif method == "get_presence":
                gid = _require_str(params, "group_id")
                stale_threshold_ms = int(params.get("stale_threshold_ms", 300000))
                presence = node.get_presence(gid, stale_threshold_ms=stale_threshold_ms)
                _ok(rid, {"presence": presence})

            # ========== Time-Windowed Queries ==========
            elif method == "get_recent_claims":
                gid = _require_str(params, "group_id")
                since_ms = _require_int(params, "since_ms")
                limit = int(params.get("limit", 100))
                claims = node.get_recent_claims(gid, since_ms, limit=limit)
                _ok(rid, {"claims": claims, "count": len(claims)})

            elif method == "watch_claims":
                # Polling-based subscription: returns claims since cursor
                gid = _require_str(params, "group_id")
                last_seen_ms = _require_int(params, "last_seen_ms")
                limit = int(params.get("limit", 50))
                claims = node.get_recent_claims(gid, last_seen_ms, limit=limit)
                # Return next cursor for pagination
                next_cursor = max((c["created_ms"] for c in claims), default=last_seen_ms) + 1 if claims else last_seen_ms
                _ok(rid, {"claims": claims, "next_cursor": next_cursor})

            elif method == "get_group_state":
                gid = _require_str(params, "group_id")
                g = node.groups.get(gid)
                if not g:
                    raise NodeError(f"unknown group_id {gid}")
                state = g.chain.state
                _ok(rid, {
                    "group_id": gid,
                    "height": g.chain.head.height,
                    "head_block_id": g.chain.head.block_id,
                    "last_block_ts_ms": g.chain.head.ts_ms,
                    "member_count": len(state.members),
                    "task_count": len(state.tasks),
                    "presence_count": len(state.presence),
                    "total_supply": state.total_supply,
                })

            else:
                _err(rid, "not_found", f"unknown method {method}")
        except MCPParamError as e:
            _err(rid, "bad_request", str(e))
        except KeyError as e:
            _err(rid, "bad_request", f"missing field {e}")
        except NodeError as e:
            _err(rid, "node_error", str(e))
        except Exception as e:
            _err(rid, "internal", str(e))
