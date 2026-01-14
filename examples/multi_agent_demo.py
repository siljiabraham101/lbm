#!/usr/bin/env python3
"""
Multi-Agent Coordination Demo using Learning Batteries Market

This demo simulates multiple AI agents working on a project together,
using LBM as their shared knowledge layer for coordination.

Scenario: Three agents collaborate to build a simple web API:
- Agent "Architect": Designs the system structure
- Agent "Developer": Implements the code
- Agent "Reviewer": Reviews and suggests improvements

Each agent:
1. Queries existing knowledge before making decisions
2. Publishes their work and decisions as claims
3. Earns tokens for contributing knowledge
4. Can see what other agents have done

Run: python examples/multi_agent_demo.py
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
sys.path.insert(0, str(Path(__file__).parent.parent))

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


class LBMAgent:
    """
    An AI agent that uses LBM for knowledge coordination.

    In a real scenario, this would wrap an LLM API call.
    For the demo, we simulate agent behavior.
    """

    def __init__(self, name: str, role: str, node: BatteryNode, group_id: str):
        self.name = name
        self.role = role
        self.node = node
        self.group_id = group_id
        self.pub_key = node.keys.sign_pub_b64

    def get_balance(self) -> int:
        """Get agent's token balance."""
        g = self.node.groups.get(self.group_id)
        if g:
            return g.chain.state.balances.get(self.pub_key, 0)
        return 0

    def query_context(self, query: str, top_k: int = 5) -> tuple:
        """Query existing knowledge relevant to a topic.

        Returns:
            Tuple of (compiled_text, claim_hashes)
        """
        slice_text, claim_hashes = self.node.compile_context(self.group_id, query, top_k=top_k)
        return slice_text, claim_hashes

    def publish_claim(self, content: str, tags: List[str], msg_type: str = "knowledge") -> str:
        """Publish a knowledge claim and earn reward tokens."""
        # Format: include agent name and type in the claim
        full_content = f"[{self.name}:{msg_type}] {content}"
        claim_hash = self.node.publish_claim(
            self.group_id,
            text=full_content,
            tags=[self.role, msg_type] + tags
        )
        return claim_hash

    def think(self, context: str) -> str:
        """
        Simulate agent thinking/reasoning.
        In real usage, this would call an LLM API.
        """
        # This is where you'd integrate with Claude API, OpenAI, etc.
        return f"[{self.name} thinking about: {context[:50]}...]"


def print_separator(title: str = ""):
    """Print a visual separator."""
    print("\n" + "=" * 60)
    if title:
        print(f"  {title}")
        print("=" * 60)
    print()


def print_agent_action(agent: LBMAgent, action: str, details: str = ""):
    """Print agent action with formatting."""
    balance = agent.get_balance()
    print(f"[{agent.name}] ({agent.role}, {balance} tokens)")
    print(f"  Action: {action}")
    if details:
        for line in details.split("\n"):
            print(f"    {line}")
    print()


async def run_demo():
    """Run the multi-agent coordination demo."""

    print_separator("Learning Batteries Market - Multi-Agent Coordination Demo")
    print("Scenario: Three AI agents collaborate to build a REST API")
    print("They share knowledge through LBM and earn tokens for contributions.\n")

    # Create temporary directory for demo
    with tempfile.TemporaryDirectory() as tmpdir:
        data_dir = Path(tmpdir) / "lbm_demo"

        # Initialize node
        print("Initializing LBM node...")
        node = BatteryNode.init(data_dir)
        print(f"  Node ID: {node.node_id}")

        # Create a knowledge group for the project
        print("\nCreating project knowledge group...")
        group_id = node.create_group("project:api-builder")
        print(f"  Group ID: {group_id}")

        # Configure token economy
        print("\nConfiguring token economy...")
        node.update_group_policy(
            group_id,
            faucet_amount=100,        # New agents get 100 tokens
            claim_reward_amount=10,   # 10 tokens per knowledge claim
            transfer_fee_bps=100,     # 1% transfer fee to treasury
        )
        print("  - Faucet: 100 tokens for new members")
        print("  - Claim reward: 10 tokens per contribution")
        print("  - Transfer fee: 1%")

        # Get token stats
        stats = node.get_token_stats(group_id)
        print(f"\nInitial token stats:")
        print(f"  Total supply: {stats['total_supply']}")

        # The node owner is the first agent (Architect)
        architect = LBMAgent("Architect", "architect", node, group_id)
        print(f"\nArchitect agent initialized (balance: {architect.get_balance()} tokens)")

        # For demo purposes, we'll simulate other agents by having them
        # publish through the same node (in real usage, each would have their own node)
        # We'll mint tokens to simulate their faucet

        print_separator("Phase 1: Architecture Design")

        # Architect publishes system design
        print_agent_action(architect, "Publishing system architecture")

        architect.publish_claim(
            "System Architecture Decision: We will build a REST API using FastAPI framework. "
            "Reasons: 1) Async support for better performance, 2) Automatic OpenAPI docs, "
            "3) Type hints for better code quality.",
            tags=["architecture", "framework", "fastapi"],
            msg_type="decision"
        )

        architect.publish_claim(
            "API Endpoints Design: "
            "GET /users - List all users, "
            "POST /users - Create user, "
            "GET /users/{id} - Get user by ID, "
            "PUT /users/{id} - Update user, "
            "DELETE /users/{id} - Delete user",
            tags=["architecture", "endpoints", "rest"],
            msg_type="design"
        )

        architect.publish_claim(
            "Data Model: User entity with fields: id (int), name (str), email (str), "
            "created_at (datetime). Use Pydantic for validation.",
            tags=["architecture", "data-model", "pydantic"],
            msg_type="design"
        )

        # Check architect's balance after publishing
        print(f"  Architect balance after contributions: {architect.get_balance()} tokens")

        print_separator("Phase 2: Development")

        # Developer queries for context before coding
        print_agent_action(architect, "Developer queries existing knowledge",
                          "Query: 'API framework and endpoints'")

        compiled_text, claim_hashes = architect.query_context("API framework endpoints design")
        print(f"  Found {len(claim_hashes)} relevant knowledge items:")
        # Show snippet of compiled context
        for i, line in enumerate(compiled_text.split("\n")[:3], 1):
            if line.strip():
                print(f"    {i}. {line[:70]}...")
        print()

        # Developer publishes implementation
        print_agent_action(architect, "Developer publishes implementation")

        architect.publish_claim(
            "Implementation: Created main.py with FastAPI app. "
            "Added User model using Pydantic BaseModel. "
            "Implemented all CRUD endpoints as per architecture.",
            tags=["implementation", "code", "fastapi"],
            msg_type="code"
        )

        architect.publish_claim(
            "Implementation Detail: Added input validation using Pydantic. "
            "Email field uses EmailStr type for automatic validation. "
            "All endpoints return proper HTTP status codes.",
            tags=["implementation", "validation", "pydantic"],
            msg_type="code"
        )

        architect.publish_claim(
            "Testing: Created test_api.py with pytest. "
            "Tests cover: user creation, retrieval, update, deletion, "
            "and error cases (404 for missing users, 422 for invalid input).",
            tags=["implementation", "testing", "pytest"],
            msg_type="code"
        )

        print(f"  Balance after development phase: {architect.get_balance()} tokens")

        print_separator("Phase 3: Code Review")

        # Reviewer queries all knowledge
        print_agent_action(architect, "Reviewer queries implementation details",
                          "Query: 'implementation validation security'")

        compiled_text, claim_hashes = architect.query_context("implementation validation security")
        print(f"  Found {len(claim_hashes)} items to review")
        print()

        # Reviewer publishes feedback
        print_agent_action(architect, "Reviewer publishes review findings")

        architect.publish_claim(
            "Review Finding: Missing rate limiting on endpoints. "
            "Recommendation: Add slowapi for rate limiting to prevent abuse.",
            tags=["review", "security", "rate-limiting"],
            msg_type="review"
        )

        architect.publish_claim(
            "Review Finding: No authentication implemented. "
            "Recommendation: Add JWT-based auth using python-jose. "
            "Protect write endpoints (POST, PUT, DELETE).",
            tags=["review", "security", "authentication"],
            msg_type="review"
        )

        architect.publish_claim(
            "Review Approval: Code structure is clean and follows best practices. "
            "Type hints are used consistently. Tests have good coverage.",
            tags=["review", "approval", "quality"],
            msg_type="review"
        )

        print(f"  Balance after review phase: {architect.get_balance()} tokens")

        print_separator("Phase 4: Knowledge Compilation")

        # Compile all project knowledge
        print("Compiling project knowledge summary...")
        print()

        # Query different aspects
        queries = [
            ("Architecture decisions", "architecture decision framework"),
            ("Implementation details", "implementation code endpoints"),
            ("Review findings", "review security recommendation"),
        ]

        for title, query in queries:
            print(f"  {title}:")
            compiled_text, claim_hashes = architect.query_context(query, top_k=3)
            # Show first few lines of compiled context
            lines = [l for l in compiled_text.split("\n") if l.strip()][:3]
            for line in lines:
                # Extract the main content
                if "]" in line:
                    line = line.split("]", 1)[1].strip()
                print(f"    - {line[:70]}...")
            print()

        print_separator("Final Statistics")

        # Get final token stats
        stats = node.get_token_stats(group_id)
        g = node.groups[group_id]
        state = g.chain.state

        print("Token Economy:")
        print(f"  Total supply: {stats['total_supply']} tokens")
        print(f"  Treasury balance: {stats['treasury_balance']} tokens")
        print(f"  Agent balance: {architect.get_balance()} tokens")
        print()

        print("Knowledge Base:")
        # Count claims
        claim_count = sum(1 for tx in _get_all_txs(g) if tx.get("type") == "claim")
        print(f"  Total claims published: {claim_count}")
        print(f"  Chain height: {g.chain.head.height}")
        print()

        print("Group Policy:")
        print(f"  Faucet amount: {state.policy.faucet_amount} tokens")
        print(f"  Claim reward: {state.policy.claim_reward_amount} tokens")
        print(f"  Transfer fee: {state.policy.transfer_fee_bps / 100}%")
        print()

        print_separator("Demo Complete!")
        print("This demo showed how AI agents can:")
        print("  1. Share knowledge through a distributed ledger")
        print("  2. Query existing knowledge before making decisions")
        print("  3. Earn tokens for contributing valuable knowledge")
        print("  4. Build a shared understanding of a project")
        print()
        print("In production, each agent would:")
        print("  - Run their own LBM node")
        print("  - Sync with peers over P2P network")
        print("  - Use MCP interface for LLM integration")
        print()


def _get_all_txs(group):
    """Helper to get all transactions from a group's chain."""
    txs = []
    for block in group.chain.blocks:
        txs.extend(block.txs)
    return txs


if __name__ == "__main__":
    asyncio.run(run_demo())
