#!/usr/bin/env python3
"""
Claude Code Agent Integration with LBM

This module provides a wrapper for integrating Claude Code (or any LLM)
with Learning Batteries Market for multi-agent knowledge sharing.

Usage:
    1. Start the LBM MCP server: lb run-mcp --data ./mynode
    2. Configure Claude Code to use this MCP server
    3. Use the agent wrapper in your automation scripts

Example with Anthropic API:
    agent = ClaudeAgent("Architect", node_dir="./mynode")
    response = agent.think_and_share(
        task="Design a REST API for user management",
        context_query="API design patterns"
    )
"""

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple

# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from lb.node import BatteryNode


class LBMAgentBase:
    """
    Base agent that uses LBM for knowledge sharing.

    This can be extended to integrate with any LLM API.
    """

    def __init__(
        self,
        name: str,
        role: str,
        node_dir: str,
        group_id: Optional[str] = None,
    ):
        """
        Initialize agent with LBM connection.

        Args:
            name: Agent's name/identifier
            role: Agent's role (architect, developer, reviewer, etc.)
            node_dir: Path to LBM node data directory
            group_id: Optional specific group to use
        """
        self.name = name
        self.role = role
        self.node_dir = Path(node_dir)

        # Load or initialize node
        if self.node_dir.exists():
            self.node = BatteryNode.load(self.node_dir)
        else:
            self.node = BatteryNode.init(self.node_dir)

        # Use first group or create one
        if group_id:
            self.group_id = group_id
        elif self.node.groups:
            self.group_id = list(self.node.groups.keys())[0]
        else:
            self.group_id = self.node.create_group(f"project:{name.lower()}")

        self.pub_key = self.node.keys.sign_pub_b64

    def get_balance(self) -> int:
        """Get agent's token balance."""
        g = self.node.groups.get(self.group_id)
        if g:
            return g.chain.state.balances.get(self.pub_key, 0)
        return 0

    def query_knowledge(self, query: str, top_k: int = 5) -> Tuple[str, List[str]]:
        """
        Query existing knowledge base.

        Args:
            query: Search query
            top_k: Number of results to return

        Returns:
            Tuple of (compiled_context, claim_hashes)
        """
        return self.node.compile_context(self.group_id, query, top_k=top_k)

    def share_knowledge(
        self,
        content: str,
        tags: List[str],
        knowledge_type: str = "insight"
    ) -> str:
        """
        Share knowledge to the group.

        Args:
            content: Knowledge content
            tags: Tags for categorization
            knowledge_type: Type (decision, code, review, question, answer, insight)

        Returns:
            Claim hash
        """
        # Format with agent metadata
        full_content = f"[{self.name}:{knowledge_type}] {content}"
        return self.node.publish_claim(
            self.group_id,
            text=full_content,
            tags=[self.role, knowledge_type] + tags
        )

    def get_project_context(self) -> Dict[str, Any]:
        """Get summary of project knowledge."""
        g = self.node.groups.get(self.group_id)
        if not g:
            return {}

        state = g.chain.state
        stats = self.node.get_token_stats(self.group_id)

        return {
            "group_id": self.group_id,
            "chain_height": g.chain.head.height,
            "total_supply": stats["total_supply"],
            "my_balance": self.get_balance(),
            "policy": {
                "faucet": state.policy.faucet_amount,
                "claim_reward": state.policy.claim_reward_amount,
                "transfer_fee_bps": state.policy.transfer_fee_bps,
            }
        }


class ClaudeAgent(LBMAgentBase):
    """
    Agent that uses Anthropic's Claude API for reasoning.

    Requires ANTHROPIC_API_KEY environment variable.
    """

    def __init__(
        self,
        name: str,
        role: str = "assistant",
        node_dir: str = "./lbm_node",
        group_id: Optional[str] = None,
        model: str = "claude-sonnet-4-20250514",
    ):
        super().__init__(name, role, node_dir, group_id)
        self.model = model

        # Check for API key
        self.api_key = os.environ.get("ANTHROPIC_API_KEY")
        if not self.api_key:
            print("Warning: ANTHROPIC_API_KEY not set. Using mock responses.")

    def _call_claude(self, system: str, user: str) -> str:
        """Call Claude API."""
        if not self.api_key:
            return f"[Mock response for: {user[:50]}...]"

        try:
            import anthropic
            client = anthropic.Anthropic(api_key=self.api_key)
            message = client.messages.create(
                model=self.model,
                max_tokens=1024,
                system=system,
                messages=[{"role": "user", "content": user}]
            )
            return message.content[0].text
        except ImportError:
            return "[anthropic package not installed. Install with: pip install anthropic]"
        except Exception as e:
            return f"[API error: {e}]"

    def think_and_share(
        self,
        task: str,
        context_query: Optional[str] = None,
        tags: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Think about a task using existing knowledge, then share insights.

        Args:
            task: The task to think about
            context_query: Optional query to retrieve relevant context
            tags: Tags for the shared knowledge

        Returns:
            Dict with response and claim_hash
        """
        # 1. Query existing knowledge if requested
        context = ""
        if context_query:
            compiled_text, _ = self.query_knowledge(context_query)
            context = f"\n\nExisting knowledge:\n{compiled_text}"

        # 2. Build system prompt
        system = f"""You are {self.name}, a {self.role} agent working on a collaborative project.
Your role is to provide expert analysis and share valuable knowledge.

Project context:
{json.dumps(self.get_project_context(), indent=2)}
{context}

When responding:
1. Consider existing knowledge from other agents
2. Provide actionable insights
3. Be concise but thorough
"""

        # 3. Call Claude
        response = self._call_claude(system, task)

        # 4. Share the insight
        knowledge_tags = tags or [self.role, "insight"]
        claim_hash = self.share_knowledge(
            response,
            tags=knowledge_tags,
            knowledge_type="insight"
        )

        return {
            "response": response,
            "claim_hash": claim_hash,
            "balance": self.get_balance()
        }

    def answer_question(self, question: str) -> Dict[str, Any]:
        """
        Answer a question using project knowledge.

        Args:
            question: The question to answer

        Returns:
            Dict with answer and claim_hash
        """
        # Query relevant knowledge
        compiled_text, claim_hashes = self.query_knowledge(question, top_k=8)

        system = f"""You are {self.name}, answering questions about the project.

Relevant knowledge from the project:
{compiled_text}

Answer based on the existing knowledge. If the answer isn't in the knowledge base,
say so and provide your best guess based on general expertise.
"""

        response = self._call_claude(system, question)

        # Share as Q&A
        claim_hash = self.share_knowledge(
            f"Q: {question}\nA: {response}",
            tags=["qa", self.role],
            knowledge_type="answer"
        )

        return {
            "answer": response,
            "sources": claim_hashes,
            "claim_hash": claim_hash,
            "balance": self.get_balance()
        }


def demo_multi_agent_conversation():
    """Demo showing multiple agents having a conversation with separate identities."""
    import tempfile

    print("=" * 60)
    print("  Multi-Agent Conversation Demo")
    print("=" * 60)
    print()
    print("Each agent has their own LBM node with unique cryptographic identity.")
    print("In production, nodes would sync via P2P. Here we simulate by")
    print("copying chain state between operations.")
    print()

    with tempfile.TemporaryDirectory() as tmpdir:
        # Create separate node directories for each agent
        alice_dir = Path(tmpdir) / "alice_node"
        bob_dir = Path(tmpdir) / "bob_node"
        carol_dir = Path(tmpdir) / "carol_node"

        # Initialize Alice's node and create the project group
        alice = ClaudeAgent("Alice", "architect", str(alice_dir))
        group_id = alice.group_id

        # Configure token economy
        alice.node.update_group_policy(
            group_id,
            faucet_amount=100,
            claim_reward_amount=10
        )

        # Initialize Bob and Carol's nodes
        bob_node = BatteryNode.init(bob_dir)
        carol_node = BatteryNode.init(carol_dir)

        # Alice adds Bob and Carol to the group (using their unique pub keys)
        alice.node.add_member(group_id, bob_node.keys.sign_pub_b64, role="member")
        alice.node.add_member(group_id, carol_node.keys.sign_pub_b64, role="member")

        # Helper to sync chain state (simulates P2P sync)
        def sync_to_node(source_node, target_node, gid):
            """Copy group state from source to target node."""
            snapshot = source_node.export_group_snapshot(gid)
            target_node.import_group_snapshot(snapshot)

        # Sync initial state to Bob and Carol
        sync_to_node(alice.node, bob_node, group_id)
        sync_to_node(alice.node, carol_node, group_id)

        # Create agent wrappers for Bob and Carol with their own nodes
        class NodeAgent:
            def __init__(self, name, role, node, group_id):
                self.name = name
                self.role = role
                self.node = node
                self.group_id = group_id
                self.pub_key = node.keys.sign_pub_b64

            def get_balance(self):
                g = self.node.groups.get(self.group_id)
                return g.chain.state.balances.get(self.pub_key, 0) if g else 0

            def publish_claim(self, content, tags):
                full_content = f"[{self.name}:{self.role}] {content}"
                return self.node.publish_claim(self.group_id, text=full_content, tags=tags)

            def query_knowledge(self, query, top_k=5):
                return self.node.compile_context(self.group_id, query, top_k=top_k)

        bob = NodeAgent("Bob", "developer", bob_node, group_id)
        carol = NodeAgent("Carol", "reviewer", carol_node, group_id)

        print("Agents initialized with separate identities:")
        print(f"  - Alice (Architect): {alice.get_balance()} tokens, node={alice.node.node_id}")
        print(f"  - Bob (Developer):   {bob.get_balance()} tokens, node={bob.node.node_id}")
        print(f"  - Carol (Reviewer):  {carol.get_balance()} tokens, node={carol.node.node_id}")
        print()

        # Alice shares design
        print("[Alice] Sharing system design...")
        alice.share_knowledge(
            "System Design: REST API for todo list using FastAPI. "
            "Endpoints: GET/POST /todos, GET/PUT/DELETE /todos/{id}. "
            "Data model: Todo(id, title, description, completed, created_at).",
            tags=["architecture", "api", "design"],
            knowledge_type="decision"
        )
        print(f"  Balance after sharing: {alice.get_balance()} tokens")

        # Sync Alice's claims to Bob and Carol
        sync_to_node(alice.node, bob_node, group_id)
        sync_to_node(alice.node, carol_node, group_id)
        print("  [Synced to other agents]")
        print()

        # Bob queries and implements
        print("[Bob] Querying architecture before implementing...")
        context, _ = bob.query_knowledge("API design todo endpoints")
        print(f"  Found context: {context[:60]}...")
        bob.publish_claim(
            "Implementation Plan: Created routes/todos.py with FastAPI router. "
            "Using Pydantic models for validation. SQLAlchemy for database. "
            "Added dependency injection for DB sessions.",
            tags=["implementation", "code", "fastapi"]
        )
        print(f"  Balance after sharing: {bob.get_balance()} tokens")

        # Sync Bob's claims back
        sync_to_node(bob_node, alice.node, group_id)
        sync_to_node(bob_node, carol_node, group_id)
        print("  [Synced to other agents]")
        print()

        # Carol reviews
        print("[Carol] Reviewing implementation...")
        context, _ = carol.query_knowledge("implementation security validation")
        print(f"  Found context: {context[:60]}...")
        carol.publish_claim(
            "Code Review: Implementation looks good. Recommendations: "
            "1) Add rate limiting to prevent abuse. "
            "2) Add input sanitization for XSS prevention. "
            "3) Add authentication middleware for protected routes.",
            tags=["review", "security", "recommendations"]
        )
        print(f"  Balance after sharing: {carol.get_balance()} tokens")

        # Final sync
        sync_to_node(carol_node, alice.node, group_id)
        sync_to_node(carol_node, bob_node, group_id)
        print("  [Synced to other agents]")
        print()

        # Final stats from Alice's perspective (all chains should be in sync)
        print("=" * 60)
        print("Final Knowledge Base (from Alice's node):")
        g = alice.node.groups[group_id]
        print(f"  Chain height: {g.chain.head.height}")
        print(f"  Total supply: {g.chain.state.total_supply} tokens")
        print()
        print("Agent Balances (earning rewards for knowledge contributions):")
        print(f"  - Alice: {g.chain.state.balances.get(alice.pub_key, 0)} tokens")
        print(f"  - Bob:   {g.chain.state.balances.get(bob.pub_key, 0)} tokens")
        print(f"  - Carol: {g.chain.state.balances.get(carol.pub_key, 0)} tokens")
        print()

        # Show all claims
        print("Knowledge Claims Published:")
        for block in g.chain.blocks:
            for tx in block.txs:
                if tx.get("type") == "claim":
                    # Get the claim text from CAS
                    try:
                        artifact = alice.node.cas.get_json(tx["artifact_hash"])
                        text = artifact.get("text", "")[:60]
                        author = block.author[:12]
                        print(f"  - [{author}...] {text}...")
                    except:
                        pass
        print()


if __name__ == "__main__":
    demo_multi_agent_conversation()
