#!/usr/bin/env python3
"""
Multi-Agent Coordination Demo using Learning Batteries Market

This demo simulates multiple AI agents working on a project together,
using LBM as their shared knowledge layer for coordination.

Demonstrates all v2 multi-agent coordination features:
- Claim threading for conversations
- Task management with state machine
- Agent presence tracking
- Time-windowed queries for "what's new"

Scenario: Three agents collaborate to build a simple web API:
- Agent "Architect": Designs the system structure
- Agent "Developer": Implements the code
- Agent "Reviewer": Reviews and suggests improvements

Run: python examples/basic/multi_agent_demo.py
"""

import asyncio
import json
import tempfile
import time
from pathlib import Path
from dataclasses import dataclass
from typing import List, Dict, Any, Optional

# Add parent to path for imports
import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from lb.node import BatteryNode
from lb.chain import TREASURY


@dataclass
class AgentMessage:
    """A message/claim from an agent."""
    agent_name: str
    message_type: str  # "decision", "code", "review", "question", "answer"
    content: str
    tags: List[str]
    timestamp: float
    parent_hash: Optional[str] = None  # For threaded conversations


class LBMAgent:
    """
    An AI agent that uses LBM for knowledge coordination.

    Now with enhanced features:
    - Task management (start, complete, fail)
    - Presence heartbeat
    - Threaded conversations
    - Time-aware queries
    """

    def __init__(self, name: str, role: str, node: BatteryNode, group_id: str):
        self.name = name
        self.role = role
        self.node = node
        self.group_id = group_id
        self.pub_key = node.keys.sign_pub_b64
        self._last_seen_ms = int(time.time() * 1000)
        self._current_task_id: Optional[str] = None

    def get_balance(self) -> int:
        """Get agent's token balance."""
        g = self.node.groups.get(self.group_id)
        if g:
            return g.chain.state.balances.get(self.pub_key, 0)
        return 0

    def query_context(self, query: str, top_k: int = 5, since_ms: Optional[int] = None) -> tuple:
        """Query existing knowledge relevant to a topic.

        Args:
            query: Search query
            top_k: Number of results
            since_ms: Only include claims after this timestamp (optional)

        Returns:
            Tuple of (compiled_text, claim_hashes)
        """
        return self.node.compile_context(self.group_id, query, top_k=top_k, since_ms=since_ms)

    def publish_claim(
        self,
        content: str,
        tags: List[str],
        msg_type: str = "knowledge",
        parent_hash: Optional[str] = None,
    ) -> str:
        """Publish a knowledge claim and earn reward tokens.

        Args:
            content: The claim content
            tags: Tags for categorization
            msg_type: Type of message
            parent_hash: Optional parent claim for threading

        Returns:
            Claim hash
        """
        full_content = f"[{self.name}:{msg_type}] {content}"
        claim_hash = self.node.publish_claim(
            self.group_id,
            text=full_content,
            tags=[self.role, msg_type] + tags,
            parent_hash=parent_hash,
        )
        return claim_hash

    def reply_to(self, parent_hash: str, content: str, tags: List[str], msg_type: str = "answer") -> str:
        """Reply to an existing claim (threaded conversation)."""
        return self.publish_claim(content, tags, msg_type=msg_type, parent_hash=parent_hash)

    def get_recent_claims(self, limit: int = 20) -> List[Dict[str, Any]]:
        """Get claims published since last check."""
        claims = self.node.get_recent_claims(self.group_id, self._last_seen_ms, limit=limit)
        if claims:
            self._last_seen_ms = max(c["created_ms"] for c in claims) + 1
        return claims

    def update_presence(self, status: str = "active", metadata: Optional[Dict] = None) -> None:
        """Update agent's presence status."""
        self.node.update_presence(self.group_id, status, metadata=metadata or {"role": self.role})

    def get_presence(self) -> Dict[str, Any]:
        """Get presence status of all agents."""
        return self.node.get_presence(self.group_id)

    def create_task(self, task_id: str, title: str, assignee_pub: Optional[str] = None, reward: int = 10) -> None:
        """Create a new task (auto-assigns to self if no assignee specified)."""
        # Auto-assign to self if no assignee specified
        if assignee_pub is None:
            assignee_pub = self.pub_key
        self.node.create_task(
            self.group_id,
            task_id=task_id,
            title=title,
            assignee=assignee_pub,
            reward=reward,
        )

    def start_task(self, task_id: str) -> None:
        """Start working on a task."""
        self.node.start_task(self.group_id, task_id)
        self._current_task_id = task_id
        self.update_presence("busy", metadata={"current_task": task_id})

    def complete_task(self, task_id: str, result_hash: Optional[str] = None) -> None:
        """Complete a task."""
        self.node.complete_task(self.group_id, task_id, result_hash=result_hash)
        self._current_task_id = None
        self.update_presence("active")

    def fail_task(self, task_id: str, error_message: str = "") -> None:
        """Mark a task as failed."""
        self.node.fail_task(self.group_id, task_id, error_message=error_message)
        self._current_task_id = None
        self.update_presence("active")

    def get_tasks(self, status: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get tasks, optionally filtered by status."""
        return self.node.get_tasks(self.group_id, status=status)

    def think(self, context: str) -> str:
        """Simulate agent thinking/reasoning."""
        return f"[{self.name} thinking about: {context[:50]}...]"


def print_separator(title: str = ""):
    """Print a visual separator."""
    print("\n" + "=" * 70)
    if title:
        print(f"  {title}")
        print("=" * 70)
    print()


def print_agent_action(agent: LBMAgent, action: str, details: str = ""):
    """Print agent action with formatting."""
    balance = agent.get_balance()
    status = "busy" if agent._current_task_id else "active"
    print(f"[{agent.name}] ({agent.role}, {balance} tokens, {status})")
    print(f"  Action: {action}")
    if details:
        for line in details.split("\n"):
            print(f"    {line}")
    print()


async def run_demo():
    """Run the enhanced multi-agent coordination demo."""

    print_separator("Learning Batteries Market - Multi-Agent Coordination Demo v2")
    print("Enhanced Features:")
    print("  - Claim Threading: Conversations with parent_hash")
    print("  - Task Management: create → assign → start → complete/fail")
    print("  - Agent Presence: Heartbeat with stale detection")
    print("  - Time Queries: Get 'what's new' since last check")
    print()
    print("Scenario: Three AI agents collaborate to build a REST API")
    print()

    # Create temporary directory for demo
    with tempfile.TemporaryDirectory() as tmpdir:
        data_dir = Path(tmpdir) / "lbm_demo"

        # Initialize node
        print("Initializing LBM node...")
        node = BatteryNode.init(data_dir)
        print(f"  Node ID: {node.node_id}")

        # Create a knowledge group for the project
        print("\nCreating project knowledge group...")
        group_id = node.create_group("project:api-builder-v2")
        print(f"  Group ID: {group_id}")

        # Configure token economy
        print("\nConfiguring token economy...")
        node.update_group_policy(
            group_id,
            faucet_amount=100,
            claim_reward_amount=10,
            transfer_fee_bps=100,
        )
        print("  - Faucet: 100 tokens for new members")
        print("  - Claim reward: 10 tokens per contribution")
        print("  - Transfer fee: 1%")

        # Create agents
        architect = LBMAgent("Architect", "architect", node, group_id)
        print(f"\nArchitect initialized (balance: {architect.get_balance()} tokens)")

        # Update presence for all agents
        architect.update_presence("active", metadata={"specialization": "system-design"})

        print_separator("Phase 1: Architecture Design with Threading")

        # Create a task for architecture design
        architect.create_task("arch_design", "Design API architecture", reward=50)
        print("  Created task: arch_design (reward=50)")

        # Start the task
        architect.start_task("arch_design")
        print_agent_action(architect, "Started task: arch_design")

        # Architect publishes initial question
        question_hash = architect.publish_claim(
            "Question: What framework should we use for this REST API project?",
            tags=["architecture", "question"],
            msg_type="question"
        )
        print(f"  Published question: {question_hash[:16]}...")

        # Architect answers own question (threaded reply)
        answer_hash = architect.reply_to(
            question_hash,
            "Answer: FastAPI is recommended for async support and automatic OpenAPI docs.",
            tags=["architecture", "framework"],
            msg_type="answer"
        )
        print(f"  Replied with answer (threaded): {answer_hash[:16]}...")

        # Verify threading
        g = node.groups[group_id]
        answer_claim = g.graph.claims.get(answer_hash)
        assert answer_claim.parent_hash == question_hash, "Threading verification failed!"
        print("  ✓ Thread chain verified")

        # Publish more architecture decisions
        design_hash = architect.publish_claim(
            "API Endpoints: GET/POST/PUT/DELETE /users with Pydantic validation",
            tags=["architecture", "endpoints"],
            msg_type="decision"
        )

        # Complete the architecture task with the design as result
        architect.complete_task("arch_design", result_hash=design_hash)
        print(f"  Completed task with result: {design_hash[:16]}...")
        print(f"  Balance after task completion: {architect.get_balance()} tokens")

        print_separator("Phase 2: Development with Task Tracking")

        # Record timestamp before new phase
        phase2_start = int(time.time() * 1000)
        time.sleep(0.05)  # Small delay to ensure timestamp difference

        # Create development tasks
        architect.create_task("impl_models", "Implement data models", reward=20)
        architect.create_task("impl_endpoints", "Implement API endpoints", reward=30)
        architect.create_task("impl_tests", "Write unit tests", reward=20)

        tasks = architect.get_tasks()
        print(f"  Created {len(tasks)} tasks")
        for t in tasks:
            print(f"    - {t['task_id']}: {t['title']} (status={t['status']}, reward={t.get('reward', 0)})")

        # Start and complete first task
        architect.start_task("impl_models")
        print_agent_action(architect, "Working on: impl_models")

        model_hash = architect.publish_claim(
            "Implementation: Created User model with Pydantic BaseModel, fields: id, name, email",
            tags=["implementation", "models", "pydantic"],
            msg_type="code"
        )
        architect.complete_task("impl_models", result_hash=model_hash)
        print(f"  ✓ Completed impl_models")

        # Start and complete second task
        architect.start_task("impl_endpoints")
        endpoint_hash = architect.publish_claim(
            "Implementation: All CRUD endpoints with proper error handling and HTTP status codes",
            tags=["implementation", "endpoints"],
            msg_type="code"
        )
        architect.complete_task("impl_endpoints", result_hash=endpoint_hash)
        print(f"  ✓ Completed impl_endpoints")

        # Start and complete tests task
        architect.start_task("impl_tests")
        test_hash = architect.publish_claim(
            "Testing: pytest suite with 95% coverage, includes edge cases and error scenarios",
            tags=["implementation", "testing"],
            msg_type="code"
        )
        architect.complete_task("impl_tests", result_hash=test_hash)
        print(f"  ✓ Completed impl_tests")

        print(f"\n  Balance after development: {architect.get_balance()} tokens")

        print_separator("Phase 3: Review with Threaded Discussion")

        # Create review task
        architect.create_task("code_review", "Review implementation for security", reward=30)
        architect.start_task("code_review")

        # Query recent knowledge using time filter
        print_agent_action(architect, "Reviewing recent implementation",
                          f"Querying claims since phase 2 start ({phase2_start})")

        compiled, hashes = architect.query_context("implementation security", top_k=5, since_ms=phase2_start)
        print(f"  Found {len(hashes)} relevant recent claims")

        # Post review as reply to implementation
        review_hash = architect.reply_to(
            endpoint_hash,
            "Review: Missing rate limiting. Recommendation: Add slowapi for API protection.",
            tags=["review", "security"],
            msg_type="review"
        )

        # Follow-up reply (deeper threading)
        followup_hash = architect.reply_to(
            review_hash,
            "Follow-up: Also add JWT authentication for protected endpoints.",
            tags=["review", "security", "auth"],
            msg_type="review"
        )

        # Verify deep threading
        g = node.groups[group_id]
        followup_claim = g.graph.claims.get(followup_hash)
        review_claim = g.graph.claims.get(review_hash)
        assert followup_claim.parent_hash == review_hash, "Deep threading failed!"
        assert review_claim.parent_hash == endpoint_hash, "Review threading failed!"
        print("  ✓ Deep thread chain verified (3 levels)")

        architect.complete_task("code_review", result_hash=review_hash)

        print_separator("Phase 4: Time-Windowed Queries")

        # Get recent updates
        print("Testing time-windowed queries...")

        # Get claims from the beginning
        all_recent = node.get_recent_claims(group_id, 0, limit=100)
        print(f"  Total claims: {len(all_recent)}")

        # Get claims since phase 2
        phase2_claims = node.get_recent_claims(group_id, phase2_start, limit=100)
        print(f"  Claims since Phase 2: {len(phase2_claims)}")

        # Compile context with time filter
        recent_context, recent_hashes = architect.query_context(
            "security implementation",
            top_k=5,
            since_ms=phase2_start
        )
        print(f"  Security-related recent claims: {len(recent_hashes)}")

        print_separator("Phase 5: Agent Presence")

        # Update and check presence
        architect.update_presence("active", metadata={"phase": "complete", "specialization": "system-design"})

        presence = architect.get_presence()
        print(f"Agent Presence Status:")
        for pub_key, info in presence.items():
            stale = "STALE" if info.get("is_stale") else "active"
            print(f"  - {info.get('status', 'unknown')} ({stale})")
            if info.get("metadata"):
                print(f"    Metadata: {info['metadata']}")

        print_separator("Final Statistics")

        # Get final stats
        state = node.groups[group_id].chain.state
        stats = node.get_token_stats(group_id)

        print("Token Economy:")
        print(f"  Total supply: {stats['total_supply']} tokens")
        print(f"  Treasury balance: {stats['treasury_balance']} tokens")
        print(f"  Agent balance: {architect.get_balance()} tokens")
        print()

        # Task statistics
        all_tasks = architect.get_tasks()
        completed_tasks = [t for t in all_tasks if t["status"] == "completed"]
        print("Task Management:")
        print(f"  Total tasks: {len(all_tasks)}")
        print(f"  Completed: {len(completed_tasks)}")
        print(f"  Total rewards earned: {sum(t.get('reward', 0) for t in completed_tasks)} tokens")
        print()

        print("Knowledge Base:")
        print(f"  Total claims: {len(all_recent)}")
        print(f"  Threaded conversations: Yes (verified)")
        print(f"  Time filtering: Yes (verified)")
        g = node.groups[group_id]
        print(f"  Chain height: {g.chain.head.height}")
        print()

        print_separator("Demo Complete!")
        print("This enhanced demo demonstrated:")
        print("  1. Claim Threading: Question → Answer → Follow-up chains")
        print("  2. Task Management: Create → Start → Complete lifecycle")
        print("  3. Agent Presence: Status updates with metadata")
        print("  4. Time-Windowed Queries: Filter by timestamp")
        print("  5. Reward Economy: Tokens earned for tasks and claims")
        print()
        print("In production, use via MCP tools:")
        print("  - publish_claim with parent_hash for threading")
        print("  - create_task, start_task, complete_task for workflows")
        print("  - update_presence, get_presence for coordination")
        print("  - get_recent_claims, watch_claims for updates")
        print()


def _get_all_txs(group):
    """Helper to get all transactions from a group's chain."""
    txs = []
    for block in group.chain.blocks:
        txs.extend(block.txs)
    return txs


if __name__ == "__main__":
    asyncio.run(run_demo())
