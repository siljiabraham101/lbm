"""Background sync daemon for Learning Battery Market.

Periodically syncs subscribed groups from their registered peers.
Handles errors gracefully, respects configured intervals, and supports pause/resume.
"""
from __future__ import annotations

import asyncio
import time
from typing import TYPE_CHECKING, Any, Dict, Optional

from .config import get_config
from .logging_config import get_logger

if TYPE_CHECKING:
    from .node import BatteryNode
    from .registry import PeerRegistry, Subscription

logger = get_logger("lb.sync")


def _now_ms() -> int:
    """Current time in milliseconds."""
    return int(time.time() * 1000)


class SyncDaemon:
    """Background daemon for auto-syncing subscribed groups.

    Usage:
        daemon = SyncDaemon(node, node.peer_registry)
        await daemon.start()
        # ... daemon runs in background ...
        await daemon.stop()
    """

    def __init__(self, node: "BatteryNode", registry: "PeerRegistry"):
        """Initialize the sync daemon.

        Args:
            node: BatteryNode instance for sync operations
            registry: PeerRegistry for subscriptions and peer tracking
        """
        self.node = node
        self.registry = registry
        self._running = False
        self._task: Optional[asyncio.Task] = None
        self._sync_results: Dict[str, Dict[str, Any]] = {}  # Last sync results per group
        self._sync_semaphore: Optional[asyncio.Semaphore] = None
        self._failure_counts: Dict[str, int] = {}  # Consecutive failures per group

    @property
    def check_interval(self) -> float:
        """Get the daemon check interval in seconds."""
        config = get_config()
        return config.sync.daemon_check_interval_s

    @property
    def max_concurrent(self) -> int:
        """Get max concurrent sync operations."""
        config = get_config()
        return config.sync.max_concurrent_syncs

    @property
    def retry_delay_s(self) -> int:
        """Get retry delay in seconds after failure."""
        config = get_config()
        return config.sync.retry_delay_s

    @property
    def max_retries(self) -> int:
        """Get max consecutive retries before disabling."""
        config = get_config()
        return config.sync.max_retries

    async def start(self) -> None:
        """Start the sync daemon."""
        if self._running:
            logger.warning("Sync daemon already running")
            return

        self._running = True
        self._sync_semaphore = asyncio.Semaphore(self.max_concurrent)
        self._task = asyncio.create_task(self._run_loop())
        logger.info("Sync daemon started")

    async def stop(self) -> None:
        """Stop the sync daemon gracefully."""
        if not self._running:
            return

        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None

        logger.info("Sync daemon stopped")

    async def _run_loop(self) -> None:
        """Main daemon loop - check subscriptions and sync as needed."""
        while self._running:
            try:
                await self._check_and_sync()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Sync loop error: {type(e).__name__}: {e}")

            try:
                await asyncio.sleep(self.check_interval)
            except asyncio.CancelledError:
                break

    async def _check_and_sync(self) -> None:
        """Check all subscriptions and sync those that are due."""
        # Hot-reload groups just in case new ones were created via CLI
        try:
            self.node.refresh_groups()
        except Exception as e:
            logger.warning(f"Error refreshing groups: {e}")

        now_ms = _now_ms()
        due_subs = self.registry.list_due_subscriptions(now_ms)

        if not due_subs:
            return

        logger.debug(f"Found {len(due_subs)} subscriptions due for sync")

        # Create tasks for due subscriptions (limited by semaphore)
        tasks = []
        for sub in due_subs:
            task = asyncio.create_task(self._sync_with_semaphore(sub))
            tasks.append(task)

        # Wait for all sync tasks to complete
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    async def _sync_with_semaphore(self, sub: "Subscription") -> None:
        """Sync a subscription with concurrency limiting."""
        async with self._sync_semaphore:
            await self._sync_group(sub)

    async def _sync_group(self, sub: "Subscription") -> None:
        """Sync a single group from its peer."""
        start_ms = _now_ms()
        group_id = sub.group_id

        try:
            logger.debug(f"Syncing group {group_id} from {sub.peer_host}:{sub.peer_port}")

            replaced = await self.node.sync_group_from_peer(
                sub.peer_host,
                sub.peer_port,
                group_id
            )

            # Update registry with success
            self.registry.update_sync_status(group_id, start_ms, error=None)

            # Also update peer last_seen
            peer_key = f"{sub.peer_host}:{sub.peer_port}"
            self.registry.update_peer_status(peer_key, start_ms, error=None)

            # Reset failure count on success
            self._failure_counts.pop(group_id, None)

            # Track result
            duration_ms = _now_ms() - start_ms
            self._sync_results[group_id] = {
                "success": True,
                "replaced": replaced,
                "timestamp_ms": start_ms,
                "duration_ms": duration_ms,
            }

            logger.info(f"Synced group {group_id}: replaced={replaced}, duration={duration_ms}ms")

        except Exception as e:
            error_msg = f"{type(e).__name__}: {e}"

            # Increment failure count
            failures = self._failure_counts.get(group_id, 0) + 1
            self._failure_counts[group_id] = failures

            # Calculate backoff: use retry_delay_s * failure_count (capped at sync_interval)
            backoff_s = min(
                self.retry_delay_s * failures,
                sub.sync_interval_s
            )
            # Set next sync time to now + backoff (in ms)
            next_sync_ms = start_ms + (backoff_s * 1000)

            logger.warning(
                f"Failed to sync group {group_id} (attempt {failures}): {error_msg}. "
                f"Next retry in {backoff_s}s"
            )

            # Check if we've exceeded max retries
            if failures >= self.max_retries:
                logger.error(
                    f"Group {group_id} exceeded max retries ({self.max_retries}), "
                    f"disabling subscription"
                )
                self.registry.set_enabled(group_id, False)
                error_msg = f"{error_msg} (disabled after {failures} failures)"

            # Update registry with error and backoff time
            self.registry.update_sync_status(group_id, next_sync_ms, error=error_msg)

            # Track result
            self._sync_results[group_id] = {
                "success": False,
                "error": error_msg,
                "timestamp_ms": start_ms,
                "failure_count": failures,
                "next_retry_ms": next_sync_ms,
            }

    async def sync_now(self, group_id: str) -> Dict[str, Any]:
        """Manually trigger sync for a specific group.

        Args:
            group_id: Group to sync

        Returns:
            Dict with sync result (success, error, etc.)
        """
        sub = self.registry.get_subscription(group_id)
        if not sub:
            return {"success": False, "error": "not subscribed"}

        await self._sync_group(sub)
        return self._sync_results.get(group_id, {"success": False, "error": "unknown"})

    def get_status(self) -> Dict[str, Any]:
        """Get daemon status and recent sync results.

        Returns:
            Dict with running status, subscription counts, and last results
        """
        subs = self.registry.list_subscriptions()
        enabled_subs = [s for s in subs if s.enabled]
        due_subs = self.registry.list_due_subscriptions()

        return {
            "running": self._running,
            "check_interval_s": self.check_interval,
            "max_concurrent": self.max_concurrent,
            "subscriptions_total": len(subs),
            "subscriptions_enabled": len(enabled_subs),
            "subscriptions_due": len(due_subs),
            "last_results": dict(self._sync_results),
        }

    def get_sync_result(self, group_id: str) -> Optional[Dict[str, Any]]:
        """Get the last sync result for a specific group."""
        return self._sync_results.get(group_id)
