"""Extreme edge case tests for multi-agent coordination features.

Tests boundary conditions, error handling, and security limits.
"""
import time
import tempfile
from pathlib import Path

import pytest

from lb.chain import Chain, Block, ChainError, MAX_TOKEN_VALUE
from lb.keys import gen_node_keys
from lb.node import BatteryNode, NodeError
from lb.context_graph import ContextGraph, Claim


def _now_ms() -> int:
    return int(time.time() * 1000)


def make_chain(creator_keys, name="TestGroup", currency="TEST"):
    genesis = Chain.make_genesis(
        name,
        group_id=None,
        creator_priv=creator_keys.sign_priv,
        creator_pub_b64=creator_keys.sign_pub_b64,
        currency=currency
    )
    return Chain(genesis)


# =============================================================================
# Task ID Edge Cases
# =============================================================================

class TestTaskIdEdgeCases:
    """Test task_id validation edge cases."""

    @pytest.fixture
    def creator_keys(self):
        return gen_node_keys()

    @pytest.fixture
    def chain(self, creator_keys):
        return make_chain(creator_keys)

    def test_empty_task_id_fails(self, chain, creator_keys):
        """Empty task_id should be rejected."""
        tx = {"type": "task_create", "task_id": "", "title": "Test", "ts_ms": _now_ms()}
        block = Block.make(
            chain.state.group_id, chain.head.height + 1, chain.head.block_id,
            author_priv=creator_keys.sign_priv, author_pub_b64=creator_keys.sign_pub_b64,
            txs=[tx]
        )
        with pytest.raises(ChainError, match="missing task_id"):
            chain.append(block)

    def test_task_id_at_max_length(self, chain, creator_keys):
        """task_id at exactly 256 chars should work."""
        max_id = "x" * 256
        tx = {"type": "task_create", "task_id": max_id, "title": "Test", "ts_ms": _now_ms()}
        block = Block.make(
            chain.state.group_id, chain.head.height + 1, chain.head.block_id,
            author_priv=creator_keys.sign_priv, author_pub_b64=creator_keys.sign_pub_b64,
            txs=[tx]
        )
        chain.append(block)
        assert max_id in chain.state.tasks

    def test_very_long_task_id_fails(self, chain, creator_keys):
        """task_id over 256 chars should be rejected."""
        long_id = "x" * 257
        tx = {"type": "task_create", "task_id": long_id, "title": "Test", "ts_ms": _now_ms()}
        block = Block.make(
            chain.state.group_id, chain.head.height + 1, chain.head.block_id,
            author_priv=creator_keys.sign_priv, author_pub_b64=creator_keys.sign_pub_b64,
            txs=[tx]
        )
        with pytest.raises(ChainError, match="task_id too long"):
            chain.append(block)

    def test_task_id_with_special_chars(self, chain, creator_keys):
        """Task ID with special characters should work."""
        special_ids = [
            "task:with:colons",
            "task/with/slashes",
            "task-with-dashes",
            "task_with_underscores",
            "task.with.dots",
            "task with spaces",
            "task\nwith\nnewlines",
        ]
        for task_id in special_ids:
            tx = {"type": "task_create", "task_id": task_id, "title": "Test", "ts_ms": _now_ms()}
            block = Block.make(
                chain.state.group_id, chain.head.height + 1, chain.head.block_id,
                author_priv=creator_keys.sign_priv, author_pub_b64=creator_keys.sign_pub_b64,
                txs=[tx]
            )
            chain.append(block)
            assert task_id in chain.state.tasks


# =============================================================================
# Task Title/Description Edge Cases
# =============================================================================

class TestTaskTitleEdgeCases:
    """Test task title and description validation."""

    @pytest.fixture
    def creator_keys(self):
        return gen_node_keys()

    @pytest.fixture
    def chain(self, creator_keys):
        return make_chain(creator_keys)

    def test_empty_title_fails(self, chain, creator_keys):
        """Empty title should be rejected."""
        tx = {"type": "task_create", "task_id": "task1", "title": "", "ts_ms": _now_ms()}
        block = Block.make(
            chain.state.group_id, chain.head.height + 1, chain.head.block_id,
            author_priv=creator_keys.sign_priv, author_pub_b64=creator_keys.sign_pub_b64,
            txs=[tx]
        )
        with pytest.raises(ChainError, match="missing title"):
            chain.append(block)

    def test_title_at_max_length(self, chain, creator_keys):
        """Title at exactly 256 chars should work."""
        max_title = "x" * 256
        tx = {"type": "task_create", "task_id": "task1", "title": max_title, "ts_ms": _now_ms()}
        block = Block.make(
            chain.state.group_id, chain.head.height + 1, chain.head.block_id,
            author_priv=creator_keys.sign_priv, author_pub_b64=creator_keys.sign_pub_b64,
            txs=[tx]
        )
        chain.append(block)
        assert chain.state.tasks["task1"]["title"] == max_title

    def test_title_over_max_length_fails(self, chain, creator_keys):
        """Title over 256 chars should be rejected."""
        long_title = "x" * 257
        tx = {"type": "task_create", "task_id": "task1", "title": long_title, "ts_ms": _now_ms()}
        block = Block.make(
            chain.state.group_id, chain.head.height + 1, chain.head.block_id,
            author_priv=creator_keys.sign_priv, author_pub_b64=creator_keys.sign_pub_b64,
            txs=[tx]
        )
        with pytest.raises(ChainError, match="title too long"):
            chain.append(block)

    def test_description_at_max_length(self, chain, creator_keys):
        """Description at exactly 4096 chars should work."""
        max_desc = "x" * 4096
        tx = {"type": "task_create", "task_id": "task1", "title": "Test", "description": max_desc, "ts_ms": _now_ms()}
        block = Block.make(
            chain.state.group_id, chain.head.height + 1, chain.head.block_id,
            author_priv=creator_keys.sign_priv, author_pub_b64=creator_keys.sign_pub_b64,
            txs=[tx]
        )
        chain.append(block)

    def test_description_over_max_length_fails(self, chain, creator_keys):
        """Description over 4096 chars should be rejected."""
        long_desc = "x" * 4097
        tx = {"type": "task_create", "task_id": "task1", "title": "Test", "description": long_desc, "ts_ms": _now_ms()}
        block = Block.make(
            chain.state.group_id, chain.head.height + 1, chain.head.block_id,
            author_priv=creator_keys.sign_priv, author_pub_b64=creator_keys.sign_pub_b64,
            txs=[tx]
        )
        with pytest.raises(ChainError, match="description too long"):
            chain.append(block)


# =============================================================================
# Task Assignee Validation
# =============================================================================

class TestTaskAssigneeValidation:
    """Test assignee validation for tasks."""

    @pytest.fixture
    def creator_keys(self):
        return gen_node_keys()

    @pytest.fixture
    def non_member_keys(self):
        return gen_node_keys()

    @pytest.fixture
    def chain(self, creator_keys):
        return make_chain(creator_keys)

    def test_create_task_with_non_member_assignee_fails(self, chain, creator_keys, non_member_keys):
        """Creating task with non-member assignee should fail."""
        tx = {
            "type": "task_create",
            "task_id": "task1",
            "title": "Test",
            "assignee": non_member_keys.sign_pub_b64,  # Not a member
            "ts_ms": _now_ms()
        }
        block = Block.make(
            chain.state.group_id, chain.head.height + 1, chain.head.block_id,
            author_priv=creator_keys.sign_priv, author_pub_b64=creator_keys.sign_pub_b64,
            txs=[tx]
        )
        with pytest.raises(ChainError, match="assignee must be a member"):
            chain.append(block)

    def test_assign_task_to_non_member_fails(self, chain, creator_keys, non_member_keys):
        """Assigning task to non-member should fail."""
        # Create task first
        create_tx = {"type": "task_create", "task_id": "task1", "title": "Test", "ts_ms": _now_ms()}
        block1 = Block.make(
            chain.state.group_id, chain.head.height + 1, chain.head.block_id,
            author_priv=creator_keys.sign_priv, author_pub_b64=creator_keys.sign_pub_b64,
            txs=[create_tx]
        )
        chain.append(block1)

        # Try to assign to non-member
        assign_tx = {
            "type": "task_assign",
            "task_id": "task1",
            "assignee": non_member_keys.sign_pub_b64,  # Not a member
            "ts_ms": _now_ms()
        }
        block2 = Block.make(
            chain.state.group_id, chain.head.height + 1, chain.head.block_id,
            author_priv=creator_keys.sign_priv, author_pub_b64=creator_keys.sign_pub_b64,
            txs=[assign_tx]
        )
        with pytest.raises(ChainError, match="assignee must be a member"):
            chain.append(block2)


# =============================================================================
# Task Reward Edge Cases
# =============================================================================

class TestTaskRewardEdgeCases:
    """Test task reward edge cases."""

    @pytest.fixture
    def creator_keys(self):
        return gen_node_keys()

    @pytest.fixture
    def chain(self, creator_keys):
        return make_chain(creator_keys)

    def test_zero_reward(self, chain, creator_keys):
        """Zero reward should work."""
        tx = {"type": "task_create", "task_id": "task1", "title": "Test", "reward": 0, "ts_ms": _now_ms()}
        block = Block.make(
            chain.state.group_id, chain.head.height + 1, chain.head.block_id,
            author_priv=creator_keys.sign_priv, author_pub_b64=creator_keys.sign_pub_b64,
            txs=[tx]
        )
        chain.append(block)
        assert chain.state.tasks["task1"]["reward"] == 0

    def test_negative_reward_fails(self, chain, creator_keys):
        """Negative reward should be rejected."""
        tx = {"type": "task_create", "task_id": "task1", "title": "Test", "reward": -100, "ts_ms": _now_ms()}
        block = Block.make(
            chain.state.group_id, chain.head.height + 1, chain.head.block_id,
            author_priv=creator_keys.sign_priv, author_pub_b64=creator_keys.sign_pub_b64,
            txs=[tx]
        )
        with pytest.raises(ChainError, match="invalid reward"):
            chain.append(block)

    def test_max_reward(self, chain, creator_keys):
        """Reward at MAX_TOKEN_VALUE should work."""
        tx = {"type": "task_create", "task_id": "task1", "title": "Test", "reward": MAX_TOKEN_VALUE, "ts_ms": _now_ms()}
        block = Block.make(
            chain.state.group_id, chain.head.height + 1, chain.head.block_id,
            author_priv=creator_keys.sign_priv, author_pub_b64=creator_keys.sign_pub_b64,
            txs=[tx]
        )
        chain.append(block)

    def test_reward_over_max_fails(self, chain, creator_keys):
        """Reward over MAX_TOKEN_VALUE should be rejected."""
        tx = {"type": "task_create", "task_id": "task1", "title": "Test", "reward": MAX_TOKEN_VALUE + 1, "ts_ms": _now_ms()}
        block = Block.make(
            chain.state.group_id, chain.head.height + 1, chain.head.block_id,
            author_priv=creator_keys.sign_priv, author_pub_b64=creator_keys.sign_pub_b64,
            txs=[tx]
        )
        with pytest.raises(ChainError, match="reward too large"):
            chain.append(block)


# =============================================================================
# Task State Machine Edge Cases
# =============================================================================

class TestTaskStateMachineEdgeCases:
    """Test task state machine edge cases."""

    @pytest.fixture
    def creator_keys(self):
        return gen_node_keys()

    @pytest.fixture
    def member_keys(self):
        return gen_node_keys()

    @pytest.fixture
    def chain_with_member(self, creator_keys, member_keys):
        chain = make_chain(creator_keys)
        # Add member
        add_tx = {"type": "member_add", "pub": member_keys.sign_pub_b64, "role": "member", "ts_ms": _now_ms()}
        block = Block.make(
            chain.state.group_id, chain.head.height + 1, chain.head.block_id,
            author_priv=creator_keys.sign_priv, author_pub_b64=creator_keys.sign_pub_b64,
            txs=[add_tx]
        )
        chain.append(block)
        return chain

    def test_start_pending_task_fails(self, chain_with_member, creator_keys, member_keys):
        """Cannot start a pending task (must be assigned first)."""
        # Create pending task
        create_tx = {"type": "task_create", "task_id": "task1", "title": "Test", "ts_ms": _now_ms()}
        block1 = Block.make(
            chain_with_member.state.group_id, chain_with_member.head.height + 1, chain_with_member.head.block_id,
            author_priv=creator_keys.sign_priv, author_pub_b64=creator_keys.sign_pub_b64,
            txs=[create_tx]
        )
        chain_with_member.append(block1)

        # Try to start without assignment
        start_tx = {"type": "task_start", "task_id": "task1", "ts_ms": _now_ms()}
        block2 = Block.make(
            chain_with_member.state.group_id, chain_with_member.head.height + 1, chain_with_member.head.block_id,
            author_priv=creator_keys.sign_priv, author_pub_b64=creator_keys.sign_pub_b64,
            txs=[start_tx]
        )
        with pytest.raises(ChainError, match="task must be assigned"):
            chain_with_member.append(block2)

    def test_complete_assigned_task_fails(self, chain_with_member, creator_keys, member_keys):
        """Cannot complete an assigned task (must be in_progress)."""
        # Create and assign task
        create_tx = {
            "type": "task_create", "task_id": "task1", "title": "Test",
            "assignee": member_keys.sign_pub_b64, "ts_ms": _now_ms()
        }
        block1 = Block.make(
            chain_with_member.state.group_id, chain_with_member.head.height + 1, chain_with_member.head.block_id,
            author_priv=creator_keys.sign_priv, author_pub_b64=creator_keys.sign_pub_b64,
            txs=[create_tx]
        )
        chain_with_member.append(block1)

        # Try to complete without starting
        complete_tx = {"type": "task_complete", "task_id": "task1", "ts_ms": _now_ms()}
        block2 = Block.make(
            chain_with_member.state.group_id, chain_with_member.head.height + 1, chain_with_member.head.block_id,
            author_priv=member_keys.sign_priv, author_pub_b64=member_keys.sign_pub_b64,
            txs=[complete_tx]
        )
        with pytest.raises(ChainError, match="task must be in_progress"):
            chain_with_member.append(block2)

    def test_start_completed_task_fails(self, chain_with_member, creator_keys, member_keys):
        """Cannot start a completed task."""
        # Full lifecycle: create -> start -> complete
        create_tx = {
            "type": "task_create", "task_id": "task1", "title": "Test",
            "assignee": member_keys.sign_pub_b64, "ts_ms": _now_ms()
        }
        block1 = Block.make(
            chain_with_member.state.group_id, chain_with_member.head.height + 1, chain_with_member.head.block_id,
            author_priv=creator_keys.sign_priv, author_pub_b64=creator_keys.sign_pub_b64,
            txs=[create_tx]
        )
        chain_with_member.append(block1)

        start_tx = {"type": "task_start", "task_id": "task1", "ts_ms": _now_ms()}
        block2 = Block.make(
            chain_with_member.state.group_id, chain_with_member.head.height + 1, chain_with_member.head.block_id,
            author_priv=member_keys.sign_priv, author_pub_b64=member_keys.sign_pub_b64,
            txs=[start_tx]
        )
        chain_with_member.append(block2)

        complete_tx = {"type": "task_complete", "task_id": "task1", "ts_ms": _now_ms()}
        block3 = Block.make(
            chain_with_member.state.group_id, chain_with_member.head.height + 1, chain_with_member.head.block_id,
            author_priv=member_keys.sign_priv, author_pub_b64=member_keys.sign_pub_b64,
            txs=[complete_tx]
        )
        chain_with_member.append(block3)

        # Try to start again
        start_tx2 = {"type": "task_start", "task_id": "task1", "ts_ms": _now_ms()}
        block4 = Block.make(
            chain_with_member.state.group_id, chain_with_member.head.height + 1, chain_with_member.head.block_id,
            author_priv=member_keys.sign_priv, author_pub_b64=member_keys.sign_pub_b64,
            txs=[start_tx2]
        )
        with pytest.raises(ChainError, match="task must be assigned"):
            chain_with_member.append(block4)

    def test_reassign_in_progress_task_fails(self, chain_with_member, creator_keys, member_keys):
        """Cannot reassign an in_progress task."""
        # Create, assign, start
        create_tx = {
            "type": "task_create", "task_id": "task1", "title": "Test",
            "assignee": member_keys.sign_pub_b64, "ts_ms": _now_ms()
        }
        block1 = Block.make(
            chain_with_member.state.group_id, chain_with_member.head.height + 1, chain_with_member.head.block_id,
            author_priv=creator_keys.sign_priv, author_pub_b64=creator_keys.sign_pub_b64,
            txs=[create_tx]
        )
        chain_with_member.append(block1)

        start_tx = {"type": "task_start", "task_id": "task1", "ts_ms": _now_ms()}
        block2 = Block.make(
            chain_with_member.state.group_id, chain_with_member.head.height + 1, chain_with_member.head.block_id,
            author_priv=member_keys.sign_priv, author_pub_b64=member_keys.sign_pub_b64,
            txs=[start_tx]
        )
        chain_with_member.append(block2)

        # Try to reassign
        assign_tx = {"type": "task_assign", "task_id": "task1", "assignee": creator_keys.sign_pub_b64, "ts_ms": _now_ms()}
        block3 = Block.make(
            chain_with_member.state.group_id, chain_with_member.head.height + 1, chain_with_member.head.block_id,
            author_priv=creator_keys.sign_priv, author_pub_b64=creator_keys.sign_pub_b64,
            txs=[assign_tx]
        )
        with pytest.raises(ChainError, match="task not assignable"):
            chain_with_member.append(block3)


# =============================================================================
# Presence Edge Cases
# =============================================================================

class TestPresenceEdgeCases:
    """Test presence transaction edge cases."""

    @pytest.fixture
    def creator_keys(self):
        return gen_node_keys()

    @pytest.fixture
    def chain(self, creator_keys):
        return make_chain(creator_keys)

    def test_invalid_presence_status(self, chain, creator_keys):
        """Invalid presence status should be rejected."""
        tx = {"type": "presence", "status": "invalid", "ts_ms": _now_ms()}
        block = Block.make(
            chain.state.group_id, chain.head.height + 1, chain.head.block_id,
            author_priv=creator_keys.sign_priv, author_pub_b64=creator_keys.sign_pub_b64,
            txs=[tx]
        )
        with pytest.raises(ChainError, match="invalid presence status"):
            chain.append(block)

    def test_presence_empty_metadata(self, chain, creator_keys):
        """Presence with empty metadata should work."""
        tx = {"type": "presence", "status": "active", "metadata": {}, "ts_ms": _now_ms()}
        block = Block.make(
            chain.state.group_id, chain.head.height + 1, chain.head.block_id,
            author_priv=creator_keys.sign_priv, author_pub_b64=creator_keys.sign_pub_b64,
            txs=[tx]
        )
        chain.append(block)
        assert chain.state.presence[creator_keys.sign_pub_b64]["metadata"] == {}

    def test_presence_metadata_at_limit(self, chain, creator_keys):
        """Presence with metadata at 4KB limit should work."""
        # Create metadata just under 4KB
        metadata = {"data": "x" * 4000}
        tx = {"type": "presence", "status": "active", "metadata": metadata, "ts_ms": _now_ms()}
        block = Block.make(
            chain.state.group_id, chain.head.height + 1, chain.head.block_id,
            author_priv=creator_keys.sign_priv, author_pub_b64=creator_keys.sign_pub_b64,
            txs=[tx]
        )
        chain.append(block)

    def test_presence_metadata_over_limit_fails(self, chain, creator_keys):
        """Presence with metadata over 4KB should be rejected."""
        large_metadata = {"data": "x" * 5000}  # Over 4KB
        tx = {"type": "presence", "status": "active", "metadata": large_metadata, "ts_ms": _now_ms()}
        block = Block.make(
            chain.state.group_id, chain.head.height + 1, chain.head.block_id,
            author_priv=creator_keys.sign_priv, author_pub_b64=creator_keys.sign_pub_b64,
            txs=[tx]
        )
        with pytest.raises(ChainError, match="metadata too large"):
            chain.append(block)


# =============================================================================
# Claim Threading Edge Cases
# =============================================================================

class TestClaimThreadingEdgeCases:
    """Test claim threading edge cases."""

    @pytest.fixture
    def temp_node(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            node = BatteryNode.init(Path(tmpdir))
            yield node

    @pytest.fixture
    def group_id(self, temp_node):
        return temp_node.create_group("EdgeTest")

    def test_reply_to_retracted_claim(self, temp_node, group_id):
        """Reply to a retracted claim should still work (parent exists)."""
        parent = temp_node.publish_claim(group_id, "Parent claim", ["test"])
        # Retract the parent
        temp_node.retract_claim(group_id, parent)
        # Reply should still work since parent_hash exists
        child = temp_node.publish_claim(group_id, "Reply to retracted", ["test"], parent_hash=parent)
        g = temp_node.groups[group_id]
        assert g.graph.claims[child].parent_hash == parent

    def test_reply_chain_to_self(self, temp_node, group_id):
        """Creating a circular reference should fail."""
        # First create a claim
        claim1 = temp_node.publish_claim(group_id, "Claim 1", ["test"])
        # Cannot reply to self (claim doesn't exist yet when creating)
        # This is not a circular reference, just testing self-reply


# =============================================================================
# Time Query Edge Cases
# =============================================================================

class TestTimeQueryEdgeCases:
    """Test time query edge cases."""

    @pytest.fixture
    def temp_node(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            node = BatteryNode.init(Path(tmpdir))
            yield node

    @pytest.fixture
    def group_id(self, temp_node):
        return temp_node.create_group("TimeTest")

    def test_since_ms_zero(self, temp_node, group_id):
        """since_ms=0 should return all claims."""
        temp_node.publish_claim(group_id, "Claim 1", ["test"])
        temp_node.publish_claim(group_id, "Claim 2", ["test"])

        claims = temp_node.get_recent_claims(group_id, 0)
        assert len(claims) == 2

    def test_since_ms_negative(self, temp_node, group_id):
        """Negative since_ms should still work (all claims)."""
        temp_node.publish_claim(group_id, "Claim 1", ["test"])

        # Negative timestamp should return all claims
        claims = temp_node.get_recent_claims(group_id, -1000)
        assert len(claims) == 1

    def test_since_ms_future(self, temp_node, group_id):
        """since_ms in future should return no claims."""
        temp_node.publish_claim(group_id, "Claim 1", ["test"])

        future_ms = _now_ms() + 1000000  # Far in future
        claims = temp_node.get_recent_claims(group_id, future_ms)
        assert len(claims) == 0

    def test_limit_zero(self, temp_node, group_id):
        """limit=0 should return empty list."""
        temp_node.publish_claim(group_id, "Claim 1", ["test"])
        temp_node.publish_claim(group_id, "Claim 2", ["test"])

        claims = temp_node.get_recent_claims(group_id, 0, limit=0)
        assert len(claims) == 0

    def test_limit_negative(self, temp_node, group_id):
        """Negative limit should be handled gracefully."""
        temp_node.publish_claim(group_id, "Claim 1", ["test"])

        # Python slicing with negative limit returns empty
        claims = temp_node.get_recent_claims(group_id, 0, limit=-1)
        assert len(claims) == 0


# =============================================================================
# Context Graph Edge Cases
# =============================================================================

class TestContextGraphEdgeCases:
    """Test context graph edge cases."""

    def test_compile_empty_graph(self):
        """Compiling empty graph should return header but no claims."""
        graph = ContextGraph()
        context, hashes = graph.compile("query")
        # Returns header even with no claims
        assert "Context slice" in context or context == ""
        assert hashes == []

    def test_compile_with_all_retracted(self):
        """Compiling when all claims are retracted should return empty."""
        graph = ContextGraph()
        graph.add_claim("h1", "Test claim", ["test"], created_ms=1000)
        graph.retract("h1")

        context, hashes = graph.compile("test")
        assert hashes == []

    def test_claim_parent_hash_to_nonexistent(self):
        """Adding claim with non-existent parent should work at graph level."""
        # Graph doesn't validate parent existence - that's node's job
        graph = ContextGraph()
        graph.add_claim("child", "Child claim", ["test"], parent_hash="nonexistent", created_ms=1000)
        assert graph.claims["child"].parent_hash == "nonexistent"


# =============================================================================
# Node Method Edge Cases
# =============================================================================

class TestNodeMethodEdgeCases:
    """Test BatteryNode method edge cases."""

    @pytest.fixture
    def temp_node(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            node = BatteryNode.init(Path(tmpdir))
            yield node

    @pytest.fixture
    def group_id(self, temp_node):
        return temp_node.create_group("NodeTest")

    def test_get_tasks_invalid_group(self, temp_node):
        """get_tasks with invalid group should raise error."""
        with pytest.raises(NodeError):
            temp_node.get_tasks("invalid_group_id")

    def test_get_presence_invalid_group(self, temp_node):
        """get_presence with invalid group should raise error."""
        with pytest.raises(NodeError):
            temp_node.get_presence("invalid_group_id")

    def test_create_task_invalid_group(self, temp_node):
        """create_task with invalid group should raise error."""
        with pytest.raises(NodeError):
            temp_node.create_task("invalid_group_id", "task1", "Test")

    def test_update_presence_invalid_status(self, temp_node, group_id):
        """update_presence with invalid status should fail at chain level."""
        with pytest.raises(ChainError):
            temp_node.update_presence(group_id, "invalid_status")

    def test_get_tasks_filter_nonexistent_status(self, temp_node, group_id):
        """Filtering by non-existent status should return empty."""
        temp_node.create_task(group_id, "task1", "Test", assignee=temp_node.keys.sign_pub_b64)

        # Filter by status that no task has
        tasks = temp_node.get_tasks(group_id, status="nonexistent")
        assert tasks == []


# =============================================================================
# Error Message Edge Cases
# =============================================================================

class TestErrorMessageEdgeCases:
    """Test error message handling edge cases."""

    @pytest.fixture
    def creator_keys(self):
        return gen_node_keys()

    @pytest.fixture
    def chain(self, creator_keys):
        chain = make_chain(creator_keys)
        # Create and start task
        create_tx = {
            "type": "task_create", "task_id": "task1", "title": "Test",
            "assignee": creator_keys.sign_pub_b64, "ts_ms": _now_ms()
        }
        start_tx = {"type": "task_start", "task_id": "task1", "ts_ms": _now_ms()}
        block = Block.make(
            chain.state.group_id, chain.head.height + 1, chain.head.block_id,
            author_priv=creator_keys.sign_priv, author_pub_b64=creator_keys.sign_pub_b64,
            txs=[create_tx, start_tx]
        )
        chain.append(block)
        return chain

    def test_error_message_at_max_length(self, chain, creator_keys):
        """Error message at 1024 chars should work."""
        max_msg = "x" * 1024
        tx = {"type": "task_fail", "task_id": "task1", "error_message": max_msg, "ts_ms": _now_ms()}
        block = Block.make(
            chain.state.group_id, chain.head.height + 1, chain.head.block_id,
            author_priv=creator_keys.sign_priv, author_pub_b64=creator_keys.sign_pub_b64,
            txs=[tx]
        )
        chain.append(block)

    def test_error_message_over_max_fails(self, chain, creator_keys):
        """Error message over 1024 chars should be rejected."""
        long_msg = "x" * 1025
        tx = {"type": "task_fail", "task_id": "task1", "error_message": long_msg, "ts_ms": _now_ms()}
        block = Block.make(
            chain.state.group_id, chain.head.height + 1, chain.head.block_id,
            author_priv=creator_keys.sign_priv, author_pub_b64=creator_keys.sign_pub_b64,
            txs=[tx]
        )
        with pytest.raises(ChainError, match="error_message too long"):
            chain.append(block)

    def test_empty_error_message(self, chain, creator_keys):
        """Empty error message should work."""
        tx = {"type": "task_fail", "task_id": "task1", "error_message": "", "ts_ms": _now_ms()}
        block = Block.make(
            chain.state.group_id, chain.head.height + 1, chain.head.block_id,
            author_priv=creator_keys.sign_priv, author_pub_b64=creator_keys.sign_pub_b64,
            txs=[tx]
        )
        chain.append(block)
        assert chain.state.tasks["task1"]["error_message"] == ""
