"""
LBM Coordinator - Distributed Knowledge Sharing for Agents

This module provides the LBM integration layer for agent coordination.
Agents share knowledge through claims, query context before decisions,
and earn tokens for contributing valuable insights.

Architecture:
- Single coordinator node owns the knowledge chain
- Agents are registered as members with unique identities
- Claims are published by the coordinator on behalf of agents
- No fork resolution needed - single source of truth

Enhanced Features (v2):
- Claim threading for conversations via parent_hash
- Task management with state machine (pending → assigned → in_progress → completed/failed)
- Agent presence tracking with stale detection
- Time-windowed queries for "what's new" functionality
"""

import json
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from lb.node import BatteryNode
from lb.keys import NodeKeys, gen_node_keys


@dataclass
class AgentIdentity:
    """Represents an agent's identity in the LBM network."""
    name: str
    role: str
    pub_key: str
    balance: int = 0
    status: str = "active"  # active, idle, busy, offline


@dataclass
class KnowledgeClaim:
    """A piece of knowledge shared by an agent."""
    agent_name: str
    claim_type: str  # decision, code, review, insight, question, answer
    content: str
    tags: List[str]
    claim_hash: str
    parent_hash: Optional[str] = None  # For threaded conversations
    timestamp: datetime = field(default_factory=datetime.now)
    created_ms: int = field(default_factory=lambda: int(time.time() * 1000))


@dataclass
class AgentTask:
    """A task assigned to an agent."""
    task_id: str
    title: str
    description: str
    creator: str
    assignee: Optional[str]
    status: str  # pending, assigned, in_progress, completed, failed
    reward: int
    created_ms: int
    started_ms: Optional[int] = None
    completed_ms: Optional[int] = None
    result_hash: Optional[str] = None
    error_message: Optional[str] = None


class LBMCoordinator:
    """
    Coordinates knowledge sharing between agents using LBM.

    Uses a single-node architecture for simplicity:
    - One coordinator node manages the knowledge chain
    - Agents are registered as members with their own keys
    - Claims are tagged with agent names for attribution
    - No multi-node sync or fork resolution needed

    Features:
    - Shared knowledge base across all agents
    - Token economy for incentivizing contributions
    - Context retrieval for informed decision making
    - Persistent learning across sessions
    """

    def __init__(
        self,
        data_dir: Path,
        project_name: str = "agentic-playground",
        *,
        faucet_amount: int = 100,
        claim_reward: int = 10,
        transfer_fee_bps: int = 100,  # 1%
    ):
        """
        Initialize the LBM coordinator.

        Args:
            data_dir: Directory for LBM data
            project_name: Name of the project/group
            faucet_amount: Tokens given to new agents
            claim_reward: Tokens earned per knowledge claim
            transfer_fee_bps: Transfer fee in basis points
        """
        self.data_dir = Path(data_dir)
        self.project_name = project_name
        self.faucet_amount = faucet_amount
        self.claim_reward = claim_reward
        self.transfer_fee_bps = transfer_fee_bps

        self._node: Optional[BatteryNode] = None
        self._group_id: Optional[str] = None
        self._agents: Dict[str, AgentIdentity] = {}
        self._agent_keys: Dict[str, NodeKeys] = {}  # For future per-agent signing

    @property
    def node(self) -> BatteryNode:
        """Get the coordinator's node, initializing if needed."""
        if self._node is None:
            self._initialize()
        return self._node

    @property
    def group_id(self) -> str:
        """Get the project group ID."""
        if self._group_id is None:
            self._initialize()
        return self._group_id

    def _initialize(self) -> None:
        """Initialize or load the LBM node and project group."""
        node_dir = self.data_dir / "coordinator"
        node_json = node_dir / "node.json"

        if node_json.exists():
            self._node = BatteryNode.load(node_dir)
            # Find existing group
            for gid, g in self._node.groups.items():
                if g.chain.state.policy.name == self.project_name:
                    self._group_id = gid
                    break
        else:
            self._node = BatteryNode.init(node_dir)

        # Create group if not exists
        if self._group_id is None:
            self._group_id = self._node.create_group(self.project_name)
            # Configure token economy
            self._node.update_group_policy(
                self._group_id,
                faucet_amount=self.faucet_amount,
                claim_reward_amount=self.claim_reward,
                transfer_fee_bps=self.transfer_fee_bps,
            )

    def register_agent(self, name: str, role: str) -> AgentIdentity:
        """
        Register a new agent in the coordination network.

        Args:
            name: Agent's unique name
            role: Agent's role (architect, developer, reviewer, etc.)

        Returns:
            AgentIdentity with the agent's credentials
        """
        if name in self._agents:
            return self._agents[name]

        # Generate a unique key for this agent
        agent_keys = gen_node_keys()
        pub_key = agent_keys.sign_pub_b64
        self._agent_keys[name] = agent_keys

        # Add agent as member (they'll receive faucet tokens)
        try:
            self.node.add_member(self.group_id, pub_key, role="member")
        except Exception:
            pass  # Already a member

        # Get balance from group state
        g = self.node.groups.get(self.group_id)
        balance = g.chain.state.balances.get(pub_key, 0) if g else 0

        identity = AgentIdentity(
            name=name,
            role=role,
            pub_key=pub_key,
            balance=balance,
        )
        self._agents[name] = identity
        return identity

    def share_knowledge(
        self,
        agent_name: str,
        content: str,
        claim_type: str = "insight",
        tags: Optional[List[str]] = None,
        parent_hash: Optional[str] = None,
    ) -> KnowledgeClaim:
        """
        Share knowledge from an agent to the network.

        Args:
            agent_name: Name of the agent sharing
            content: The knowledge content
            claim_type: Type of claim (decision, code, review, insight, etc.)
            tags: Tags for categorization
            parent_hash: Optional parent claim hash for threaded conversations

        Returns:
            KnowledgeClaim with the claim details
        """
        if agent_name not in self._agents:
            raise ValueError(f"Unknown agent: {agent_name}")

        agent = self._agents[agent_name]

        # Format content with agent metadata
        full_content = f"[{agent_name}:{claim_type}] {content}"
        all_tags = [agent.role, claim_type, f"author:{agent_name}"] + (tags or [])

        # Publish claim with agent's own key (for proper reward attribution)
        # Use parent_hash for threaded conversations
        agent_keys = self._agent_keys.get(agent_name)
        claim_hash = self.node.publish_claim(
            self.group_id,
            text=full_content,
            tags=all_tags,
            parent_hash=parent_hash,
            signer_keys=agent_keys,
        )

        claim = KnowledgeClaim(
            agent_name=agent_name,
            claim_type=claim_type,
            content=content,
            tags=all_tags,
            claim_hash=claim_hash,
            parent_hash=parent_hash,
        )

        return claim

    def reply_to_claim(
        self,
        agent_name: str,
        parent_hash: str,
        content: str,
        claim_type: str = "answer",
        tags: Optional[List[str]] = None,
    ) -> KnowledgeClaim:
        """
        Reply to an existing claim (threaded conversation).

        Args:
            agent_name: Name of the agent replying
            parent_hash: Hash of the claim being replied to
            content: The reply content
            claim_type: Type of claim (answer, followup, etc.)
            tags: Additional tags

        Returns:
            KnowledgeClaim with the reply details
        """
        return self.share_knowledge(
            agent_name=agent_name,
            content=content,
            claim_type=claim_type,
            tags=tags,
            parent_hash=parent_hash,
        )

    def query_knowledge(
        self,
        agent_name: str,
        query: str,
        top_k: int = 8,
        since_ms: Optional[int] = None,
    ) -> Tuple[str, List[str]]:
        """
        Query the knowledge base for relevant context.

        Args:
            agent_name: Name of the querying agent
            query: Search query
            top_k: Number of results
            since_ms: Only include claims created after this timestamp (optional)

        Returns:
            Tuple of (compiled_context, claim_hashes)
        """
        if agent_name not in self._agents:
            raise ValueError(f"Unknown agent: {agent_name}")

        # Query from coordinator node (single source of truth)
        return self.node.compile_context(self.group_id, query, top_k=top_k, since_ms=since_ms)

    def get_recent_claims(
        self,
        since_ms: int,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """
        Get recent claims since a timestamp.

        Args:
            since_ms: Only include claims created after this timestamp
            limit: Maximum number of claims to return

        Returns:
            List of claim dictionaries with metadata
        """
        return self.node.get_recent_claims(self.group_id, since_ms, limit=limit)

    def watch_for_updates(
        self,
        last_seen_ms: int,
        limit: int = 50,
    ) -> Tuple[List[Dict[str, Any]], int]:
        """
        Watch for new claims since last check (polling-based subscription).

        Args:
            last_seen_ms: Timestamp of last seen claim
            limit: Maximum number of claims to return

        Returns:
            Tuple of (claims, next_cursor_ms)
        """
        claims = self.node.get_recent_claims(self.group_id, last_seen_ms, limit=limit)
        next_cursor = max((c["created_ms"] for c in claims), default=last_seen_ms) + 1 if claims else last_seen_ms
        return claims, next_cursor

    def get_agent_balance(self, agent_name: str) -> int:
        """Get an agent's token balance."""
        if agent_name not in self._agents:
            return 0

        pub_key = self._agents[agent_name].pub_key
        g = self.node.groups.get(self.group_id)
        return g.chain.state.balances.get(pub_key, 0) if g else 0

    def transfer_tokens(
        self,
        from_agent: str,
        to_agent: str,
        amount: int,
    ) -> bool:
        """
        Transfer tokens between agents.

        Args:
            from_agent: Sending agent (tokens will be transferred FROM this agent)
            to_agent: Receiving agent
            amount: Amount to transfer

        Returns:
            True if successful
        """
        if from_agent not in self._agents:
            raise ValueError(f"Unknown agent: {from_agent}")
        if to_agent not in self._agents:
            raise ValueError(f"Unknown agent: {to_agent}")

        to_pub = self._agents[to_agent].pub_key
        from_keys = self._agent_keys.get(from_agent)

        # Transfer using the sending agent's keys for proper identity attribution
        self.node.transfer(self.group_id, to_pub, amount, signer_keys=from_keys)
        return True

    # =========================================================================
    # Task Management
    # =========================================================================

    def create_task(
        self,
        creator_name: str,
        task_id: str,
        title: str,
        description: str = "",
        assignee_name: Optional[str] = None,
        reward: int = 0,
    ) -> AgentTask:
        """
        Create a new task for agents.

        Args:
            creator_name: Name of the agent creating the task
            task_id: Unique task identifier
            title: Task title
            description: Task description
            assignee_name: Optional agent to assign immediately
            reward: Tokens to reward on completion

        Returns:
            AgentTask with task details
        """
        if creator_name not in self._agents:
            raise ValueError(f"Unknown agent: {creator_name}")

        assignee_pub = None
        if assignee_name:
            if assignee_name not in self._agents:
                raise ValueError(f"Unknown assignee: {assignee_name}")
            assignee_pub = self._agents[assignee_name].pub_key

        self.node.create_task(
            self.group_id,
            task_id=task_id,
            title=title,
            description=description,
            assignee=assignee_pub,
            reward=reward,
        )

        tasks = self.node.get_tasks(self.group_id, status=None)
        for t in tasks:
            if t["task_id"] == task_id:
                return AgentTask(
                    task_id=t["task_id"],
                    title=t["title"],
                    description=t.get("description", ""),
                    creator=creator_name,
                    assignee=assignee_name,
                    status=t["status"],
                    reward=t.get("reward", 0),
                    created_ms=t.get("created_ms", 0),
                )

        raise ValueError(f"Task creation failed for {task_id}")

    def assign_task(
        self,
        task_id: str,
        assignee_name: str,
    ) -> None:
        """
        Assign a task to an agent.

        Args:
            task_id: Task to assign
            assignee_name: Agent to assign to
        """
        if assignee_name not in self._agents:
            raise ValueError(f"Unknown agent: {assignee_name}")

        assignee_pub = self._agents[assignee_name].pub_key
        self.node.assign_task(self.group_id, task_id, assignee_pub)

    def start_task(self, agent_name: str, task_id: str) -> None:
        """
        Mark a task as started (in_progress).

        Args:
            agent_name: Agent starting the task (must be assignee)
            task_id: Task to start
        """
        if agent_name not in self._agents:
            raise ValueError(f"Unknown agent: {agent_name}")
        agent_keys = self._agent_keys.get(agent_name)
        self.node.start_task(self.group_id, task_id, signer_keys=agent_keys)

    def complete_task(
        self,
        agent_name: str,
        task_id: str,
        result_hash: Optional[str] = None,
    ) -> None:
        """
        Mark a task as completed.

        Args:
            agent_name: Agent completing the task (must be assignee)
            task_id: Task to complete
            result_hash: Optional hash of result artifact
        """
        if agent_name not in self._agents:
            raise ValueError(f"Unknown agent: {agent_name}")
        agent_keys = self._agent_keys.get(agent_name)
        self.node.complete_task(self.group_id, task_id, result_hash=result_hash, signer_keys=agent_keys)

    def fail_task(
        self,
        agent_name: str,
        task_id: str,
        error_message: str = "",
    ) -> None:
        """
        Mark a task as failed.

        Args:
            agent_name: Agent failing the task (must be assignee)
            task_id: Task that failed
            error_message: Reason for failure
        """
        if agent_name not in self._agents:
            raise ValueError(f"Unknown agent: {agent_name}")
        agent_keys = self._agent_keys.get(agent_name)
        self.node.fail_task(self.group_id, task_id, error_message=error_message, signer_keys=agent_keys)

    def get_tasks(
        self,
        status: Optional[str] = None,
        assignee_name: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        Get tasks with optional filtering.

        Args:
            status: Filter by status (pending, assigned, in_progress, completed, failed)
            assignee_name: Filter by assignee agent name

        Returns:
            List of task dictionaries
        """
        assignee_pub = None
        if assignee_name:
            if assignee_name not in self._agents:
                raise ValueError(f"Unknown agent: {assignee_name}")
            assignee_pub = self._agents[assignee_name].pub_key

        tasks = self.node.get_tasks(self.group_id, status=status, assignee=assignee_pub)

        # Enrich with agent names
        pub_to_name = {a.pub_key: name for name, a in self._agents.items()}
        for t in tasks:
            if t.get("assignee") and t["assignee"] in pub_to_name:
                t["assignee_name"] = pub_to_name[t["assignee"]]
            if t.get("creator") and t["creator"] in pub_to_name:
                t["creator_name"] = pub_to_name[t["creator"]]

        return tasks

    def get_agent_tasks(self, agent_name: str) -> List[Dict[str, Any]]:
        """Get all tasks assigned to an agent."""
        return self.get_tasks(assignee_name=agent_name)

    # =========================================================================
    # Agent Presence
    # =========================================================================

    def update_presence(
        self,
        agent_name: str,
        status: str = "active",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Update an agent's presence status.

        Args:
            agent_name: Agent to update
            status: Status (active, idle, busy, offline)
            metadata: Optional metadata (e.g., current task, capabilities)
        """
        if agent_name not in self._agents:
            raise ValueError(f"Unknown agent: {agent_name}")

        self._agents[agent_name].status = status
        agent_keys = self._agent_keys.get(agent_name)
        self.node.update_presence(self.group_id, status, metadata=metadata, signer_keys=agent_keys)

    def get_presence(
        self,
        stale_threshold_ms: int = 300000,
    ) -> Dict[str, Dict[str, Any]]:
        """
        Get presence status of all agents.

        Args:
            stale_threshold_ms: Consider agents stale after this time (default 5 min)

        Returns:
            Dict of pub_key -> presence info
        """
        presence = self.node.get_presence(self.group_id, stale_threshold_ms=stale_threshold_ms)

        # Enrich with agent names
        pub_to_name = {a.pub_key: name for name, a in self._agents.items()}
        enriched = {}
        for pub_key, info in presence.items():
            if pub_key in pub_to_name:
                info["agent_name"] = pub_to_name[pub_key]
            enriched[pub_key] = info

        return enriched

    def get_active_agents(
        self,
        stale_threshold_ms: int = 300000,
    ) -> List[str]:
        """
        Get list of currently active (non-stale) agents.

        Args:
            stale_threshold_ms: Consider agents stale after this time

        Returns:
            List of active agent names
        """
        presence = self.get_presence(stale_threshold_ms=stale_threshold_ms)
        active = []
        for pub_key, info in presence.items():
            if not info.get("is_stale", True) and info.get("status") != "offline":
                if "agent_name" in info:
                    active.append(info["agent_name"])
        return active

    def get_stats(self) -> Dict[str, Any]:
        """Get coordination statistics."""
        g = self.node.groups.get(self.group_id)
        if not g:
            return {}

        state = g.chain.state
        stats = self.node.get_token_stats(self.group_id)

        # Count claims
        claim_count = sum(
            1 for block in g.chain.blocks
            for tx in block.txs
            if tx.get("type") == "claim"
        )

        # Count tasks by status
        all_tasks = self.get_tasks()
        task_stats = {
            "total": len(all_tasks),
            "pending": sum(1 for t in all_tasks if t["status"] == "pending"),
            "assigned": sum(1 for t in all_tasks if t["status"] == "assigned"),
            "in_progress": sum(1 for t in all_tasks if t["status"] == "in_progress"),
            "completed": sum(1 for t in all_tasks if t["status"] == "completed"),
            "failed": sum(1 for t in all_tasks if t["status"] == "failed"),
        }

        # Get presence info
        presence = self.get_presence()
        active_agents = self.get_active_agents()

        return {
            "project_name": self.project_name,
            "group_id": self.group_id,
            "chain_height": g.chain.head.height,
            "total_supply": stats["total_supply"],
            "treasury_balance": stats["treasury_balance"],
            "claim_count": claim_count,
            "agent_count": len(self._agents),
            "active_agent_count": len(active_agents),
            "tasks": task_stats,
            "agents": {
                name: {
                    "role": agent.role,
                    "status": agent.status,
                    "balance": self.get_agent_balance(name),
                }
                for name, agent in self._agents.items()
            },
            "policy": {
                "faucet_amount": state.policy.faucet_amount,
                "claim_reward": state.policy.claim_reward_amount,
                "transfer_fee_bps": state.policy.transfer_fee_bps,
            },
        }

    def get_all_claims(self) -> List[Dict[str, Any]]:
        """Get all knowledge claims in the network."""
        g = self.node.groups.get(self.group_id)
        if not g:
            return []

        claims = []
        for block in g.chain.blocks:
            for tx in block.txs:
                if tx.get("type") == "claim":
                    try:
                        artifact = self.node.cas.get_json(tx["artifact_hash"])
                        claims.append({
                            "hash": tx["artifact_hash"],
                            "text": artifact.get("text", ""),
                            "tags": artifact.get("tags", []),
                            "block_height": block.height,
                            "author": block.author[:12] + "...",
                            "timestamp_ms": block.ts_ms,
                        })
                    except Exception:
                        pass
        return claims

    def save_state(self) -> None:
        """Persist all state to disk."""
        # State is automatically persisted by LBM nodes
        pass

    def export_learnings(self, output_file: Path) -> None:
        """
        Export all learnings to a JSON file for backup/analysis.

        Args:
            output_file: Path to output JSON file
        """
        data = {
            "exported_at": datetime.now().isoformat(),
            "stats": self.get_stats(),
            "claims": self.get_all_claims(),
        }
        output_file.write_text(json.dumps(data, indent=2, default=str))

    def import_learnings(self, input_file: Path) -> int:
        """
        Import learnings from a backup file.

        Args:
            input_file: Path to JSON file

        Returns:
            Number of claims imported
        """
        data = json.loads(input_file.read_text())
        count = 0
        for claim in data.get("claims", []):
            # Re-publish claims (they'll be deduplicated by hash)
            try:
                self.node.publish_claim(
                    self.group_id,
                    text=claim["text"],
                    tags=claim["tags"],
                )
                count += 1
            except Exception:
                pass
        return count
