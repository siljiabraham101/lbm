"""
MCP (Model Context Protocol) interface for Learning Battery Market.

This module implements a standard MCP server over request/response JSON-RPC (stdin/stdout).
It allows AI agents (like Claude Code) to interact with the LBM node as a set of tools.

See: https://modelcontextprotocol.io/
"""
from __future__ import annotations

import asyncio
import base64
import json
import os
import sys
import hashlib
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Callable

from . import __version__
from .node import BatteryNode, NodeError
from .logging_config import get_logger

logger = get_logger("lb.mcp")

# MCP Protocol Version
MCP_PROTOCOL_VERSION = "2024-11-05"

class MCPParamError(Exception):
    """Error for missing or invalid MCP parameters."""
    def __init__(self, field: str, message: str = "is required"):
        self.field = field
        super().__init__(f"{field} {message}")


def _ok(rid: Any, result: Any) -> None:
    """Send a successful JSON-RPC response."""
    if rid is None: return  # Notification, no response
    sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": rid, "result": result}, ensure_ascii=False) + "\n")
    sys.stdout.flush()


def _err(rid: Any, code: int, message: str, data: Any = None) -> None:
    """Send a JSON-RPC error response."""
    if rid is None: return  # Notification, no response
    err = {"code": code, "message": message}
    if data:
        err["data"] = data
    sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": rid, "error": err}, ensure_ascii=False) + "\n")
    sys.stdout.flush()


def _detect_lbm_repo(working_dir: Optional[str] = None) -> Optional[Path]:
    """Detect .lbm/ directory in working directory or current directory."""
    check_dirs = []
    if working_dir:
        check_dirs.append(Path(working_dir).resolve())
    check_dirs.append(Path.cwd())
    if env_repo := os.environ.get("LBM_REPO_PATH"):
        check_dirs.append(Path(env_repo).resolve())

    for d in check_dirs:
        lbm_dir = d / ".lbm"
        if lbm_dir.exists() and (lbm_dir / "config.json").exists():
            return d
    return None


def _load_node_for_mcp(
    data_dir: str,
    working_dir: Optional[str] = None,
    agent_name: Optional[str] = None,
) -> tuple:
    """Load node for MCP, with optional GitHub integration."""
    repo_path = _detect_lbm_repo(working_dir)

    if repo_path:
        try:
            from .github_integration import (
                is_lbm_initialized,
                load_lbm_config,
                get_or_create_node,
                register_agent,
            )
            if is_lbm_initialized(repo_path):
                config = load_lbm_config(repo_path)
                node = get_or_create_node(repo_path)
                config_info = {
                    "github_integration": True,
                    "github_repo": config.github_repo,
                    "group_id": config.group_id,
                    "group_name": config.group_name,
                }
                logger.info(f"MCP using GitHub-integrated node for {config.github_repo}")
                
                # Auto-register agent if enabled
                if config.agent_auto_register and agent_name:
                    try:
                        agent_info = register_agent(repo_path, agent_name, agent_type="mcp")
                        config_info["agent_registered"] = True
                        logger.info(f"Auto-registered MCP agent: {agent_name}")
                    except Exception as e:
                        logger.warning(f"Failed to auto-register agent: {e}")
                return node, config_info
        except Exception as e:
            logger.warning(f"Failed to load GitHub-integrated node: {e}")

    node = BatteryNode.load(data_dir)
    return node, None


# --- Tools Definition ---

TOOLS = [
    {
        "name": "publish_claim",
        "description": "Publish knowledge, ideas, or observations to the knowledge graph. Use this to save important information.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "group_id": {"type": "string", "description": "The Group ID to publish to"},
                "text": {"type": "string", "description": "The content of the claim"},
                "tags": {"type": "array", "items": {"type": "string"}, "description": "Tags for classification"},
                "parent_hash": {"type": "string", "description": "Optional hash of a parent claim to thread this under"}
            },
            "required": ["group_id", "text"]
        }
    },
    {
        "name": "compile_context",
        "description": "Retrieve relevant knowledge from the graph based on a query. Use this to answer questions using stored knowledge.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "group_id": {"type": "string", "description": "The Group ID to query"},
                "query": {"type": "string", "description": "The search query"},
                "top_k": {"type": "integer", "description": "Number of results to return (default 8)"},
                "since_ms": {"type": "integer", "description": "Only return claims newer than this timestamp (ms)"}
            },
            "required": ["group_id", "query"]
        }
    },
    {
        "name": "list_groups",
        "description": "List all knowledge groups this node is a member of.",
        "inputSchema": {
            "type": "object",
            "properties": {},
        }
    },
    {
        "name": "create_task",
        "description": "Create a new task in the system.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "group_id": {"type": "string"},
                "title": {"type": "string"},
                "description": {"type": "string"},
                "assignee": {"type": "string", "description": "Public key of assignee (optional)"},
                "reward": {"type": "integer", "description": "Token reward amount"}
            },
            "required": ["group_id", "title"]
        }
    },
    {
        "name": "list_tasks",
        "description": "List tasks in a group, optionally filtered by status or assignee.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "group_id": {"type": "string"},
                "status": {"type": "string", "enum": ["pending", "assigned", "in_progress", "completed", "failed"]},
                "assignee": {"type": "string"}
            },
            "required": ["group_id"]
        }
    },
    {
        "name": "complete_task",
        "description": "Mark a task as completed, optionally linking to a result claim.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "group_id": {"type": "string"},
                "task_id": {"type": "string"},
                "result_hash": {"type": "string", "description": "Hash of the claim containing the result"}
            },
            "required": ["group_id", "task_id"]
        }
    },
    {
        "name": "get_recent_claims",
        "description": "Get a list of the most recent claims in a group.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "group_id": {"type": "string"},
                "limit": {"type": "integer", "description": "Max claims to return (default 20)"}
            },
            "required": ["group_id"]
        }
    },
    {
        "name": "record_thought",
        "description": "CRITICAL: You MUST use this tool to log your internal reasoning process (goal, hypothesis, observation, reflection) before providing a final answer. This creates a permanent thought stream.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "group_id": {"type": "string", "description": "Group ID to store the thought stream"},
                "content": {"type": "string", "description": " The thought content"},
                "thought_type": {"type": "string", "enum": ["goal", "hypothesis", "action", "observation", "reflection"], "default": "reflection"},
                "context_id": {"type": "string", "description": "Optional session ID to link thoughts. If not provided, one is generated per agent session."}
            },
            "required": ["group_id", "content"]
        }
    }
]

# --- Prompts Definition ---

PROMPTS = [
    {
        "name": "thought_stream",
        "description": "Activates the friction-less reasoning capture mode. Injects system instructions for the Thought Stream Protocol.",
        "arguments": [
            {
                "name": "group_id",
                "description": "The Group ID to store thought logs in (default: myaimemory)",
                "required": False
            }
        ]
    }
]

# Simple in-memory session tracking for thought streams
_thought_sessions: Dict[str, str] = {}  # agent_name -> current_context_id

def handle_tool_call(node: BatteryNode, name: str, args: Dict[str, Any]) -> Any:
    """Execute the tool logic."""
    
    if name == "publish_claim":
        gid = args["group_id"]
        # Auto-subscribe if not subscribed? No, explicit subscription preferred.
        if gid not in node.groups:
             raise NodeError(f"Node is not a member of group {gid}")
             
        h = node.publish_claim(
            gid, 
            args["text"], 
            args.get("tags", []), 
            parent_hash=args.get("parent_hash")
        )
        return {"claim_hash": h, "status": "published"}

    elif name == "record_thought":
        gid = args["group_id"]
        if gid not in node.groups:
             raise NodeError(f"Node is not a member of group {gid}")

        # Manage tags automatically
        ttype = args.get("thought_type", "reflection")
        tags = ["#thought", f"#{ttype}"]
        
        # Link to session
        # We don't have agent_name easily available here in handle_tool_call signature
        # But we can pass context_id if the client provided it, or just use a generic one
        cid = args.get("context_id")
        if cid:
            tags.append(f"ctx:{cid}")
            
        params = {
            "type": ttype,
            "content": args["content"],
            "ts": int(time.time() * 1000)
        }
        
        # Publish as a structured claim (JSON string as text for now)
        text_payload = json.dumps(params)
        
        h = node.publish_claim(gid, text_payload, tags)
        logger.debug(f"Recorded thought: {ttype} in {gid}")
        return {"claim_hash": h, "status": "recorded"}

    elif name == "compile_context":
        gid = args["group_id"]
        text, hashes = node.compile_context(
            gid, 
            args["query"], 
            top_k=args.get("top_k", 8),
            since_ms=args.get("since_ms")
        )
        return {"context": text, "source_claims": hashes}

    elif name == "list_groups":
        groups = []
        for gid, g in node.groups.items():
            groups.append({
                "group_id": gid, 
                "name": g.chain.state.policy.name,
                "head_height": g.chain.head.height
            })
        return {"groups": groups}

    elif name == "create_task":
        # Generate random task ID if not provided (MCP doesn't strictly need one from user)
        # But node.create_task requires one. Let's start with a random one.
        task_id = hashlib.sha256(os.urandom(32)).hexdigest()[:16]
        node.create_task(
            args["group_id"], 
            task_id, 
            args["title"], 
            description=args.get("description", ""),
            assignee=args.get("assignee"), 
            reward=args.get("reward", 0)
        )
        return {"task_id": task_id, "status": "created"}

    elif name == "list_tasks":
        tasks = node.get_tasks(
            args["group_id"], 
            status=args.get("status"), 
            assignee=args.get("assignee")
        )
        return {"tasks": tasks}

    elif name == "complete_task":
        node.complete_task(
            args["group_id"], 
            args["task_id"], 
            result_hash=args.get("result_hash")
        )
        return {"status": "completed"}

    elif name == "get_recent_claims":
        claims = node.get_recent_claims(
            args["group_id"], 
            since_ms=0, 
            limit=args.get("limit", 20)
        )
        return {"claims": claims}

    raise ValueError(f"Unknown tool: {name}")


def run_mcp(
    data_dir: str,
    working_dir: Optional[str] = None,
    agent_name: Optional[str] = None,
) -> None:
    """Run the MCP loop."""
    if not agent_name:
        agent_name = f"mcp-{os.getpid()}"

    node, config_info = _load_node_for_mcp(data_dir, working_dir, agent_name)

    # Main Loop
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        
        try:
            req = json.loads(line)
        except json.JSONDecodeError:
            _err(None, -32700, "Parse error")
            continue

        rid = req.get("id")
        method = req.get("method")
        params = req.get("params", {})

        try:
            # --- MCP Handshake ---
            if method == "initialize":
                response = {
                    "protocolVersion": MCP_PROTOCOL_VERSION,
                    "capabilities": {
                        "tools": {},    # We provide tools
                        "prompts": {},  # We provide prompts
                    },
                    "serverInfo": {
                        "name": "lbm-mcp-server",
                        "version": __version__
                    }
                }
                _ok(rid, response)

            elif method == "notifications/initialized":
                # Client acknowledging initialization
                # No response needed for notifications
                pass

            # --- Tool Discovery ---
            elif method == "tools/list":
                _ok(rid, {"tools": TOOLS})

            # --- Tool Execution ---
            elif method == "tools/call":
                name = params.get("name")
                args = params.get("arguments", {})
                
                try:
                    result = handle_tool_call(node, name, args)
                    _ok(rid, {"content": [{"type": "text", "text": json.dumps(result, ensure_ascii=False)}]})
                except Exception as e:
                    # Tool errors should be returned as text content usually, or specific error codes
                    # MCP spec allows isUserError property
                    _ok(rid, {
                        "isError": True,
                        "content": [{"type": "text", "text": f"Error executing {name}: {str(e)}"}]
                    })

            # --- Prompt Discovery ---
            elif method == "prompts/list":
                _ok(rid, {"prompts": PROMPTS})

            elif method == "prompts/get":
                pname = params.get("name")
                pargs = params.get("arguments", {})
                
                if pname == "thought_stream":
                    gid = pargs.get("group_id", "myaimemory")
                    # Construct the PromptMessage
                    # MCP Prompt structure: { "description": "...", "messages": [ { "role": "user", "content": { "type": "text", "text": "..." } } ] }
                    # Wait, prompts/get returns GetPromptResult which has `messages` and `description` (optional).
                    
                    sys_prompt = f"""# LBM THOUGHT STREAM PROTOCOL
You are connected to a Personal Knowledge Mesh via MCP.
Your goal is to capture your reasoning process PERMANENTLY without user intervention.

**CRITICAL RULE:**
Before providing ANY final answer or performing a complex task, you MUST use the `record_thought` tool to log your internal state.

Use `group_id` = "{gid}" (or the relevant project group).

**Thinking Types:**
- `goal`: What are you trying to achieve?
- `hypothesis`: How do you plan to solve it?
- `action`: What tool are you finding/using?
- `observation`: What did you find?
- `reflection`: Did it work? What did you learn?
"""
                    _ok(rid, {
                        "messages": [
                            {
                                "role": "user", 
                                "content": {"type": "text", "text": sys_prompt} 
                            }
                        ]
                    })
                else:
                    _err(rid, -32601, f"Prompt not found: {pname}")

            # --- Ping/Std methods ---
            elif method == "ping":
                _ok(rid, {})

            else:
                _err(rid, -32601, f"Method not found: {method}")

        except Exception as e:
            logger.exception(f"Internal error processing {method}")
            _err(rid, -32603, f"Internal error: {str(e)}")
