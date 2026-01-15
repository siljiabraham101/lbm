"""Tests for multi-agent coordination features.

Tests new features added for agent coordination:
- Claim threading (parent_hash)
- Task management (create, assign, start, complete, fail)
- Agent presence tracking
- Time-windowed queries
- Backward compatibility
"""
import time
import tempfile
from pathlib import Path

import pytest

from lb.chain import Chain, Block, ChainError
from lb.keys import gen_node_keys
from lb.node import BatteryNode, NodeError
from lb.context_graph import ContextGraph, Claim


def _now_ms() -> int:
    return int(time.time() * 1000)


def make_chain(creator_keys, name="TestGroup", currency="TEST"):
    """Helper to create a chain with a genesis block."""
    genesis = Chain.make_genesis(
        name,
        group_id=None,
        creator_priv=creator_keys.sign_priv,
        creator_pub_b64=creator_keys.sign_pub_b64,
        currency=currency
    )
    return Chain(genesis)


# =============================================================================
# Claim Threading Tests
# =============================================================================

class TestClaimThreading:
    """Tests for claim threading via parent_hash."""

    @pytest.fixture
    def temp_node(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            node = BatteryNode.init(Path(tmpdir))
            yield node

    @pytest.fixture
    def group_id(self, temp_node):
        return temp_node.create_group("ThreadingTest")

    def test_publish_claim_without_parent(self, temp_node, group_id):
        """Test publishing a claim without parent_hash works."""
        claim_hash = temp_node.publish_claim(group_id, "Root claim", ["test"])
        assert claim_hash is not None

        g = temp_node.groups[group_id]
        claim = g.graph.claims.get(claim_hash)
        assert claim is not None
        assert claim.parent_hash is None

    def test_publish_claim_with_valid_parent(self, temp_node, group_id):
        """Test publishing a claim with valid parent_hash creates thread."""
        parent_hash = temp_node.publish_claim(group_id, "Question: How to optimize?", ["question"])
        child_hash = temp_node.publish_claim(group_id, "Answer: Use caching", ["answer"], parent_hash=parent_hash)

        g = temp_node.groups[group_id]
        child = g.graph.claims.get(child_hash)
        assert child is not None
        assert child.parent_hash == parent_hash

    def test_publish_claim_with_invalid_parent_fails(self, temp_node, group_id):
        """Test publishing a claim with non-existent parent_hash fails."""
        with pytest.raises(NodeError, match="parent claim .* not found"):
            temp_node.publish_claim(group_id, "Orphan reply", ["reply"], parent_hash="nonexistent_hash")

    def test_claim_threading_deep_nesting(self, temp_node, group_id):
        """Test multi-level claim threading."""
        root = temp_node.publish_claim(group_id, "Root", ["root"])
        level1 = temp_node.publish_claim(group_id, "Level 1", ["level1"], parent_hash=root)
        level2 = temp_node.publish_claim(group_id, "Level 2", ["level2"], parent_hash=level1)
        level3 = temp_node.publish_claim(group_id, "Level 3", ["level3"], parent_hash=level2)

        g = temp_node.groups[group_id]
        assert g.graph.claims[level1].parent_hash == root
        assert g.graph.claims[level2].parent_hash == level1
        assert g.graph.claims[level3].parent_hash == level2


class TestContextGraphThreading:
    """Direct tests on ContextGraph for threading."""

    def test_add_claim_with_parent_hash(self):
        """Test adding claim with parent_hash to context graph."""
        graph = ContextGraph()
        graph.add_claim("parent_hash", "Parent claim", ["parent"], created_ms=1000)
        graph.add_claim("child_hash", "Child claim", ["child"], parent_hash="parent_hash", created_ms=2000)

        assert graph.claims["child_hash"].parent_hash == "parent_hash"

    def test_claim_serialization_with_parent_hash(self):
        """Test Claim to_dict/from_dict preserves parent_hash."""
        claim = Claim(
            claim_hash="test_hash",
            text="Test claim",
            tags=["test"],
            created_ms=1000,
            evidence=[],
            parent_hash="parent_hash"
        )

        d = claim.to_dict()
        assert d["parent_hash"] == "parent_hash"

        restored = Claim.from_dict(d)
        assert restored.parent_hash == "parent_hash"

    def test_claim_serialization_without_parent_hash(self):
        """Test Claim to_dict/from_dict works without parent_hash."""
        claim = Claim(
            claim_hash="test_hash",
            text="Test claim",
            tags=["test"],
            created_ms=1000,
            evidence=[]
        )

        d = claim.to_dict()
        assert "parent_hash" not in d

        restored = Claim.from_dict(d)
        assert restored.parent_hash is None


# =============================================================================
# Time-Windowed Query Tests
# =============================================================================

class TestTimeWindowedQueries:
    """Tests for time-windowed queries."""

    @pytest.fixture
    def temp_node(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            node = BatteryNode.init(Path(tmpdir))
            yield node

    @pytest.fixture
    def group_id(self, temp_node):
        return temp_node.create_group("TimeQueryTest")

    def test_compile_context_with_since_ms(self, temp_node, group_id):
        """Test compile_context filters by since_ms."""
        # Create claims at different times
        old_time = _now_ms() - 10000

        g = temp_node.groups[group_id]
        g.graph.add_claim("old_claim", "Old claim", ["old"], created_ms=old_time)
        g.graph.add_claim("new_claim", "New claim about query", ["new"], created_ms=_now_ms())

        # Query with since_ms should only return new claim
        context, hashes = temp_node.compile_context(group_id, "query", top_k=10, since_ms=old_time + 1)

        assert "new_claim" in hashes
        assert "old_claim" not in hashes

    def test_get_recent_claims(self, temp_node, group_id):
        """Test get_recent_claims returns claims after timestamp."""
        # Create claims
        temp_node.publish_claim(group_id, "Claim 1", ["test"])
        time.sleep(0.01)  # Small delay
        cutoff = _now_ms()
        time.sleep(0.01)
        temp_node.publish_claim(group_id, "Claim 2", ["test"])
        temp_node.publish_claim(group_id, "Claim 3", ["test"])

        recent = temp_node.get_recent_claims(group_id, cutoff)

        # Should only get claims after cutoff
        assert len(recent) == 2
        for claim in recent:
            assert claim["created_ms"] >= cutoff

    def test_get_recent_claims_respects_limit(self, temp_node, group_id):
        """Test get_recent_claims respects limit parameter."""
        for i in range(10):
            temp_node.publish_claim(group_id, f"Claim {i}", ["test"])

        recent = temp_node.get_recent_claims(group_id, 0, limit=5)
        assert len(recent) == 5


class TestContextGraphTimeFiltering:
    """Direct tests on ContextGraph for time filtering."""

    def test_compile_with_since_ms_filters_old(self):
        """Test compile() with since_ms filters old claims."""
        graph = ContextGraph()
        graph.add_claim("old", "Old data", ["data"], created_ms=1000)
        graph.add_claim("new", "New data", ["data"], created_ms=2000)

        _, hashes = graph.compile("data", top_k=10, since_ms=1500)

        assert "new" in hashes
        assert "old" not in hashes

    def test_compile_without_since_ms_returns_all(self):
        """Test compile() without since_ms returns all claims."""
        graph = ContextGraph()
        graph.add_claim("old", "Old data", ["data"], created_ms=1000)
        graph.add_claim("new", "New data", ["data"], created_ms=2000)

        _, hashes = graph.compile("data", top_k=10)

        assert "old" in hashes
        assert "new" in hashes


# =============================================================================
# Task Management Tests
# =============================================================================

class TestTaskManagement:
    """Tests for task management transactions."""

    @pytest.fixture
    def creator_keys(self):
        return gen_node_keys()

    @pytest.fixture
    def member_keys(self):
        return gen_node_keys()

    @pytest.fixture
    def chain(self, creator_keys):
        return make_chain(creator_keys)

    def test_create_task(self, chain, creator_keys):
        """Test task_create transaction."""
        ts = _now_ms()
        tx = {
            "type": "task_create",
            "task_id": "task_1",
            "title": "Test Task",
            "description": "A test task",
            "reward": 100,
            "ts_ms": ts
        }

        block = Block.make(
            chain.state.group_id,
            chain.head.height + 1,
            chain.head.block_id,
            author_priv=creator_keys.sign_priv,
            author_pub_b64=creator_keys.sign_pub_b64,
            txs=[tx]
        )

        chain.append(block)

        task = chain.state.tasks.get("task_1")
        assert task is not None
        assert task["title"] == "Test Task"
        assert task["status"] == "pending"
        assert task["creator"] == creator_keys.sign_pub_b64

    def test_create_task_with_assignee(self, chain, creator_keys, member_keys):
        """Test task_create with immediate assignee."""
        # First add member
        add_tx = {"type": "member_add", "pub": member_keys.sign_pub_b64, "role": "member", "ts_ms": _now_ms()}
        block1 = Block.make(
            chain.state.group_id,
            chain.head.height + 1,
            chain.head.block_id,
            author_priv=creator_keys.sign_priv,
            author_pub_b64=creator_keys.sign_pub_b64,
            txs=[add_tx]
        )
        chain.append(block1)

        # Create task with assignee
        tx = {
            "type": "task_create",
            "task_id": "task_1",
            "title": "Assigned Task",
            "assignee": member_keys.sign_pub_b64,
            "ts_ms": _now_ms()
        }
        block2 = Block.make(
            chain.state.group_id,
            chain.head.height + 1,
            chain.head.block_id,
            author_priv=creator_keys.sign_priv,
            author_pub_b64=creator_keys.sign_pub_b64,
            txs=[tx]
        )
        chain.append(block2)

        task = chain.state.tasks["task_1"]
        assert task["assignee"] == member_keys.sign_pub_b64
        assert task["status"] == "assigned"

    def test_duplicate_task_id_fails(self, chain, creator_keys):
        """Test creating duplicate task_id fails."""
        tx1 = {"type": "task_create", "task_id": "task_1", "title": "Task 1", "ts_ms": _now_ms()}
        block1 = Block.make(
            chain.state.group_id,
            chain.head.height + 1,
            chain.head.block_id,
            author_priv=creator_keys.sign_priv,
            author_pub_b64=creator_keys.sign_pub_b64,
            txs=[tx1]
        )
        chain.append(block1)

        tx2 = {"type": "task_create", "task_id": "task_1", "title": "Duplicate", "ts_ms": _now_ms()}
        block2 = Block.make(
            chain.state.group_id,
            chain.head.height + 1,
            chain.head.block_id,
            author_priv=creator_keys.sign_priv,
            author_pub_b64=creator_keys.sign_pub_b64,
            txs=[tx2]
        )

        with pytest.raises(ChainError, match="task_id already exists"):
            chain.append(block2)

    def test_task_assign(self, chain, creator_keys, member_keys):
        """Test task_assign transaction."""
        # Add member
        add_tx = {"type": "member_add", "pub": member_keys.sign_pub_b64, "role": "member", "ts_ms": _now_ms()}
        block1 = Block.make(
            chain.state.group_id,
            chain.head.height + 1,
            chain.head.block_id,
            author_priv=creator_keys.sign_priv,
            author_pub_b64=creator_keys.sign_pub_b64,
            txs=[add_tx]
        )
        chain.append(block1)

        # Create task
        create_tx = {"type": "task_create", "task_id": "task_1", "title": "Task", "ts_ms": _now_ms()}
        block2 = Block.make(
            chain.state.group_id,
            chain.head.height + 1,
            chain.head.block_id,
            author_priv=creator_keys.sign_priv,
            author_pub_b64=creator_keys.sign_pub_b64,
            txs=[create_tx]
        )
        chain.append(block2)

        # Assign task
        assign_tx = {"type": "task_assign", "task_id": "task_1", "assignee": member_keys.sign_pub_b64, "ts_ms": _now_ms()}
        block3 = Block.make(
            chain.state.group_id,
            chain.head.height + 1,
            chain.head.block_id,
            author_priv=creator_keys.sign_priv,
            author_pub_b64=creator_keys.sign_pub_b64,
            txs=[assign_tx]
        )
        chain.append(block3)

        task = chain.state.tasks["task_1"]
        assert task["assignee"] == member_keys.sign_pub_b64
        assert task["status"] == "assigned"

    def test_task_start_only_by_assignee(self, chain, creator_keys, member_keys):
        """Test task_start only allowed by assignee."""
        # Setup: add member, create task, assign
        add_tx = {"type": "member_add", "pub": member_keys.sign_pub_b64, "role": "member", "ts_ms": _now_ms()}
        block1 = Block.make(
            chain.state.group_id, chain.head.height + 1, chain.head.block_id,
            author_priv=creator_keys.sign_priv, author_pub_b64=creator_keys.sign_pub_b64,
            txs=[add_tx]
        )
        chain.append(block1)

        create_tx = {"type": "task_create", "task_id": "task_1", "title": "Task",
                     "assignee": member_keys.sign_pub_b64, "ts_ms": _now_ms()}
        block2 = Block.make(
            chain.state.group_id, chain.head.height + 1, chain.head.block_id,
            author_priv=creator_keys.sign_priv, author_pub_b64=creator_keys.sign_pub_b64,
            txs=[create_tx]
        )
        chain.append(block2)

        # Creator (not assignee) tries to start - should fail
        start_tx = {"type": "task_start", "task_id": "task_1", "ts_ms": _now_ms()}
        block3 = Block.make(
            chain.state.group_id, chain.head.height + 1, chain.head.block_id,
            author_priv=creator_keys.sign_priv, author_pub_b64=creator_keys.sign_pub_b64,
            txs=[start_tx]
        )

        with pytest.raises(ChainError, match="only assignee can start"):
            chain.append(block3)

        # Assignee starts - should work
        block4 = Block.make(
            chain.state.group_id, chain.head.height + 1, chain.head.block_id,
            author_priv=member_keys.sign_priv, author_pub_b64=member_keys.sign_pub_b64,
            txs=[start_tx]
        )
        chain.append(block4)

        assert chain.state.tasks["task_1"]["status"] == "in_progress"

    def test_task_complete_mints_reward(self, chain, creator_keys, member_keys):
        """Test task_complete mints reward to assignee."""
        # Setup: add member, create task with reward, assign, start
        add_tx = {"type": "member_add", "pub": member_keys.sign_pub_b64, "role": "member", "ts_ms": _now_ms()}
        block1 = Block.make(
            chain.state.group_id, chain.head.height + 1, chain.head.block_id,
            author_priv=creator_keys.sign_priv, author_pub_b64=creator_keys.sign_pub_b64,
            txs=[add_tx]
        )
        chain.append(block1)

        create_tx = {"type": "task_create", "task_id": "task_1", "title": "Task",
                     "assignee": member_keys.sign_pub_b64, "reward": 100, "ts_ms": _now_ms()}
        block2 = Block.make(
            chain.state.group_id, chain.head.height + 1, chain.head.block_id,
            author_priv=creator_keys.sign_priv, author_pub_b64=creator_keys.sign_pub_b64,
            txs=[create_tx]
        )
        chain.append(block2)

        start_tx = {"type": "task_start", "task_id": "task_1", "ts_ms": _now_ms()}
        block3 = Block.make(
            chain.state.group_id, chain.head.height + 1, chain.head.block_id,
            author_priv=member_keys.sign_priv, author_pub_b64=member_keys.sign_pub_b64,
            txs=[start_tx]
        )
        chain.append(block3)

        # Initial balance
        initial_balance = chain.state.balances.get(member_keys.sign_pub_b64, 0)
        initial_supply = chain.state.total_supply

        # Complete task
        complete_tx = {"type": "task_complete", "task_id": "task_1", "ts_ms": _now_ms()}
        block4 = Block.make(
            chain.state.group_id, chain.head.height + 1, chain.head.block_id,
            author_priv=member_keys.sign_priv, author_pub_b64=member_keys.sign_pub_b64,
            txs=[complete_tx]
        )
        chain.append(block4)

        # Verify reward minted
        assert chain.state.tasks["task_1"]["status"] == "completed"
        assert chain.state.balances.get(member_keys.sign_pub_b64, 0) == initial_balance + 100
        assert chain.state.total_supply == initial_supply + 100

    def test_task_fail(self, chain, creator_keys, member_keys):
        """Test task_fail transition."""
        # Setup: add member, create task, assign, start
        add_tx = {"type": "member_add", "pub": member_keys.sign_pub_b64, "role": "member", "ts_ms": _now_ms()}
        create_tx = {"type": "task_create", "task_id": "task_1", "title": "Task",
                     "assignee": member_keys.sign_pub_b64, "ts_ms": _now_ms()}
        block1 = Block.make(
            chain.state.group_id, chain.head.height + 1, chain.head.block_id,
            author_priv=creator_keys.sign_priv, author_pub_b64=creator_keys.sign_pub_b64,
            txs=[add_tx, create_tx]
        )
        chain.append(block1)

        start_tx = {"type": "task_start", "task_id": "task_1", "ts_ms": _now_ms()}
        block2 = Block.make(
            chain.state.group_id, chain.head.height + 1, chain.head.block_id,
            author_priv=member_keys.sign_priv, author_pub_b64=member_keys.sign_pub_b64,
            txs=[start_tx]
        )
        chain.append(block2)

        # Fail task
        fail_tx = {"type": "task_fail", "task_id": "task_1", "error_message": "Blocked by dependency", "ts_ms": _now_ms()}
        block3 = Block.make(
            chain.state.group_id, chain.head.height + 1, chain.head.block_id,
            author_priv=member_keys.sign_priv, author_pub_b64=member_keys.sign_pub_b64,
            txs=[fail_tx]
        )
        chain.append(block3)

        task = chain.state.tasks["task_1"]
        assert task["status"] == "failed"
        assert task["error_message"] == "Blocked by dependency"

    def test_task_complete_requires_in_progress(self, chain, creator_keys, member_keys):
        """Test task_complete fails if task not in_progress."""
        add_tx = {"type": "member_add", "pub": member_keys.sign_pub_b64, "role": "member", "ts_ms": _now_ms()}
        create_tx = {"type": "task_create", "task_id": "task_1", "title": "Task",
                     "assignee": member_keys.sign_pub_b64, "ts_ms": _now_ms()}
        block1 = Block.make(
            chain.state.group_id, chain.head.height + 1, chain.head.block_id,
            author_priv=creator_keys.sign_priv, author_pub_b64=creator_keys.sign_pub_b64,
            txs=[add_tx, create_tx]
        )
        chain.append(block1)

        # Try to complete without starting
        complete_tx = {"type": "task_complete", "task_id": "task_1", "ts_ms": _now_ms()}
        block2 = Block.make(
            chain.state.group_id, chain.head.height + 1, chain.head.block_id,
            author_priv=member_keys.sign_priv, author_pub_b64=member_keys.sign_pub_b64,
            txs=[complete_tx]
        )

        with pytest.raises(ChainError, match="task must be in_progress"):
            chain.append(block2)


class TestTaskManagementNode:
    """Tests for task management via BatteryNode."""

    @pytest.fixture
    def temp_node(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            node = BatteryNode.init(Path(tmpdir))
            yield node

    @pytest.fixture
    def group_id(self, temp_node):
        return temp_node.create_group("TaskTest")

    def test_full_task_lifecycle(self, temp_node, group_id):
        """Test full task lifecycle: create -> assign -> start -> complete."""
        # Create task
        temp_node.create_task(group_id, "task_1", "Test Task", description="A test", reward=50)

        tasks = temp_node.get_tasks(group_id)
        assert len(tasks) == 1
        assert tasks[0]["status"] == "pending"

        # Assign to self
        temp_node.assign_task(group_id, "task_1", temp_node.keys.sign_pub_b64)
        tasks = temp_node.get_tasks(group_id)
        assert tasks[0]["status"] == "assigned"

        # Start
        temp_node.start_task(group_id, "task_1")
        tasks = temp_node.get_tasks(group_id)
        assert tasks[0]["status"] == "in_progress"

        # Complete
        temp_node.complete_task(group_id, "task_1", result_hash="result_abc")
        tasks = temp_node.get_tasks(group_id)
        assert tasks[0]["status"] == "completed"
        assert tasks[0]["result_hash"] == "result_abc"

    def test_get_tasks_filter_by_status(self, temp_node, group_id):
        """Test filtering tasks by status."""
        temp_node.create_task(group_id, "task_pending", "Pending")
        temp_node.create_task(group_id, "task_assigned", "Assigned", assignee=temp_node.keys.sign_pub_b64)

        pending = temp_node.get_tasks(group_id, status="pending")
        assert len(pending) == 1
        assert pending[0]["task_id"] == "task_pending"

        assigned = temp_node.get_tasks(group_id, status="assigned")
        assert len(assigned) == 1
        assert assigned[0]["task_id"] == "task_assigned"

    def test_get_tasks_filter_by_assignee(self, temp_node, group_id):
        """Test filtering tasks by assignee."""
        temp_node.create_task(group_id, "task_1", "Task 1", assignee=temp_node.keys.sign_pub_b64)
        temp_node.create_task(group_id, "task_2", "Task 2")  # No assignee

        my_tasks = temp_node.get_tasks(group_id, assignee=temp_node.keys.sign_pub_b64)
        assert len(my_tasks) == 1
        assert my_tasks[0]["task_id"] == "task_1"


# =============================================================================
# Agent Presence Tests
# =============================================================================

class TestAgentPresence:
    """Tests for agent presence tracking."""

    @pytest.fixture
    def creator_keys(self):
        return gen_node_keys()

    @pytest.fixture
    def chain(self, creator_keys):
        return make_chain(creator_keys)

    def test_presence_update(self, chain, creator_keys):
        """Test presence transaction updates state."""
        ts = _now_ms()
        tx = {"type": "presence", "status": "active", "metadata": {"agent": "test"}, "ts_ms": ts}

        block = Block.make(
            chain.state.group_id, chain.head.height + 1, chain.head.block_id,
            author_priv=creator_keys.sign_priv, author_pub_b64=creator_keys.sign_pub_b64,
            txs=[tx]
        )
        chain.append(block)

        presence = chain.state.presence.get(creator_keys.sign_pub_b64)
        assert presence is not None
        assert presence["status"] == "active"
        assert presence["metadata"]["agent"] == "test"
        assert presence["last_seen_ms"] == ts

    def test_presence_invalid_status_fails(self, chain, creator_keys):
        """Test presence with invalid status fails."""
        tx = {"type": "presence", "status": "invalid_status", "ts_ms": _now_ms()}

        block = Block.make(
            chain.state.group_id, chain.head.height + 1, chain.head.block_id,
            author_priv=creator_keys.sign_priv, author_pub_b64=creator_keys.sign_pub_b64,
            txs=[tx]
        )

        with pytest.raises(ChainError, match="invalid presence status"):
            chain.append(block)

    def test_presence_all_valid_statuses(self, chain, creator_keys):
        """Test all valid presence statuses."""
        for status in ["active", "idle", "busy", "offline"]:
            tx = {"type": "presence", "status": status, "ts_ms": _now_ms()}
            block = Block.make(
                chain.state.group_id, chain.head.height + 1, chain.head.block_id,
                author_priv=creator_keys.sign_priv, author_pub_b64=creator_keys.sign_pub_b64,
                txs=[tx]
            )
            chain.append(block)
            assert chain.state.presence[creator_keys.sign_pub_b64]["status"] == status


class TestAgentPresenceNode:
    """Tests for agent presence via BatteryNode."""

    @pytest.fixture
    def temp_node(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            node = BatteryNode.init(Path(tmpdir))
            yield node

    @pytest.fixture
    def group_id(self, temp_node):
        return temp_node.create_group("PresenceTest")

    def test_update_and_get_presence(self, temp_node, group_id):
        """Test updating and retrieving presence."""
        temp_node.update_presence(group_id, "active", metadata={"version": "1.0"})

        presence = temp_node.get_presence(group_id)
        my_presence = presence.get(temp_node.keys.sign_pub_b64)

        assert my_presence is not None
        assert my_presence["status"] == "active"
        assert my_presence["metadata"]["version"] == "1.0"
        assert my_presence["is_stale"] is False

    def test_presence_stale_detection(self, temp_node, group_id):
        """Test stale presence detection."""
        # Update presence with old timestamp (simulate by checking with very short threshold)
        temp_node.update_presence(group_id, "active")

        # Use very short stale threshold
        presence = temp_node.get_presence(group_id, stale_threshold_ms=1)
        time.sleep(0.01)  # Ensure time passes
        presence = temp_node.get_presence(group_id, stale_threshold_ms=1)

        my_presence = presence.get(temp_node.keys.sign_pub_b64)
        assert my_presence["is_stale"] is True


# =============================================================================
# Backward Compatibility Tests
# =============================================================================

class TestBackwardCompatibility:
    """Tests for backward compatibility."""

    def test_old_claim_without_parent_hash(self):
        """Test old claims without parent_hash still work."""
        old_data = {
            "claim_hash": "old_hash",
            "text": "Old claim",
            "tags": ["old"],
            "created_ms": 1000,
            "evidence": []
        }

        claim = Claim.from_dict(old_data)
        assert claim.parent_hash is None
        assert claim.text == "Old claim"

    def test_context_graph_snapshot_compatibility(self):
        """Test ContextGraph snapshot with mixed claims."""
        graph = ContextGraph()
        graph.add_claim("old_hash", "Old claim", ["old"], created_ms=1000)
        graph.add_claim("new_hash", "New claim", ["new"], parent_hash="old_hash", created_ms=2000)

        # Take snapshot
        snapshot = graph.snapshot()

        # Restore
        restored = ContextGraph.from_snapshot(snapshot)

        assert "old_hash" in restored.claims
        assert "new_hash" in restored.claims
        assert restored.claims["old_hash"].parent_hash is None
        assert restored.claims["new_hash"].parent_hash == "old_hash"

    def test_chain_state_without_tasks_presence(self):
        """Test chain state works without tasks/presence fields."""
        from lb.chain import GroupState, GroupPolicy

        # Simulate old snapshot without tasks/presence
        old_snapshot = {
            "group_id": "test_group",
            "policy": {"name": "Test", "currency": "TST"},
            "members": {"pub1": "member"},
            "admins": {"pub1"},
            "balances": {"pub1": 100},
            "total_supply": 100,
            "nonces": {},
            "offers": {},
            "grants": {},
            # No tasks or presence fields
        }

        state = GroupState.from_snapshot(old_snapshot)
        assert state.tasks == {}
        assert state.presence == {}


# =============================================================================
# Integration Tests
# =============================================================================

class TestMultiAgentIntegration:
    """Integration tests for multi-agent coordination."""

    @pytest.fixture
    def temp_node(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            node = BatteryNode.init(Path(tmpdir))
            yield node

    @pytest.fixture
    def group_id(self, temp_node):
        return temp_node.create_group("IntegrationTest")

    def test_threaded_conversation(self, temp_node, group_id):
        """Test a threaded conversation between agents."""
        # Agent 1 asks question
        question = temp_node.publish_claim(group_id, "Question: How do I optimize database queries?", ["question"])

        # Agent 2 answers
        answer = temp_node.publish_claim(group_id, "Answer: Consider using indexes and query caching", ["answer"], parent_hash=question)

        # Agent 1 follows up
        followup = temp_node.publish_claim(group_id, "Thanks! What about connection pooling?", ["followup"], parent_hash=answer)

        # Agent 2 responds
        response = temp_node.publish_claim(group_id, "Yes, connection pooling helps reduce overhead", ["response"], parent_hash=followup)

        g = temp_node.groups[group_id]
        assert g.graph.claims[answer].parent_hash == question
        assert g.graph.claims[followup].parent_hash == answer
        assert g.graph.claims[response].parent_hash == followup

    def test_threading_survives_rebuild(self, temp_node, group_id):
        """Test that parent_hash is preserved after rebuild_group_graph().

        This tests the fix for a bug where rebuild_group_graph() was not
        passing parent_hash when reconstructing claims from CAS.
        """
        # Create a threaded conversation
        question = temp_node.publish_claim(group_id, "What is the best approach?", ["question"])
        answer = temp_node.publish_claim(group_id, "Use pattern X", ["answer"], parent_hash=question)
        followup = temp_node.publish_claim(group_id, "Thanks, any alternatives?", ["followup"], parent_hash=answer)

        # Verify threading before rebuild
        g = temp_node.groups[group_id]
        assert g.graph.claims[answer].parent_hash == question
        assert g.graph.claims[followup].parent_hash == answer

        # Rebuild the graph (simulates sync/restore scenario)
        temp_node.rebuild_group_graph(group_id)

        # Verify threading is preserved after rebuild
        g = temp_node.groups[group_id]
        assert g.graph.claims[answer].parent_hash == question
        assert g.graph.claims[followup].parent_hash == answer
        assert g.graph.claims[question].parent_hash is None

    def test_task_with_knowledge_sharing(self, temp_node, group_id):
        """Test task completion with knowledge sharing."""
        # Create a task
        temp_node.create_task(group_id, "research_task", "Research best practices", reward=100)
        temp_node.assign_task(group_id, "research_task", temp_node.keys.sign_pub_b64)
        temp_node.start_task(group_id, "research_task")

        # Share findings as claims
        finding1 = temp_node.publish_claim(group_id, "Finding 1: Caching improves performance by 50%", ["research", "finding"])
        finding2 = temp_node.publish_claim(group_id, "Finding 2: Indexing reduces query time", ["research", "finding"])

        # Complete task with reference to findings
        temp_node.complete_task(group_id, "research_task", result_hash=finding1)

        # Verify task completed
        tasks = temp_node.get_tasks(group_id)
        assert tasks[0]["status"] == "completed"
        assert tasks[0]["result_hash"] == finding1

    def test_presence_aware_compilation(self, temp_node, group_id):
        """Test that presence tracking works alongside knowledge compilation."""
        # Update presence
        temp_node.update_presence(group_id, "active", metadata={"specialization": "database"})

        # Add knowledge
        temp_node.publish_claim(group_id, "Database optimization techniques", ["database"])
        temp_node.publish_claim(group_id, "Query caching strategies", ["database", "caching"])

        # Compile context
        context, hashes = temp_node.compile_context(group_id, "database optimization")
        assert len(hashes) > 0

        # Verify presence
        presence = temp_node.get_presence(group_id)
        assert temp_node.keys.sign_pub_b64 in presence
