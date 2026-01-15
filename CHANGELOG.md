# Changelog

## [0.6.0] - Multi-Agent Coordination Release

This release adds comprehensive multi-agent coordination features including claim threading, task management, agent presence tracking, and time-windowed queries.

### Multi-Agent Coordination

- **Claim Threading**: Parent-child relationships for threaded conversations
  - `parent_hash` parameter on `publish_claim`
  - Query claims with thread context

- **Task Management**: Full task lifecycle with state machine
  - State machine: `pending` → `assigned` → `in_progress` → `completed`/`failed`
  - Transaction types: `task_create`, `task_assign`, `task_start`, `task_complete`, `task_fail`
  - Automatic token rewards on task completion
  - Query tasks by status or assignee

- **Agent Presence**: Heartbeat tracking with stale detection
  - Status updates: `active`, `idle`, `busy`, `offline`
  - Custom metadata support (max 4KB)
  - Stale detection (default: 5 minutes)

- **Time-Windowed Queries**: Get "what's new" since a timestamp
  - `since_ms` parameter on `compile_context`
  - `get_recent_claims` for time-filtered claims
  - `watch_claims` for cursor-based pagination

### MCP Tools

New tools for agent integration:
- `create_task`, `assign_task`, `start_task`, `complete_task`, `fail_task`, `list_tasks`
- `update_presence`, `get_presence`
- `get_recent_claims`, `watch_claims`
- Updated `publish_claim` with `parent_hash`
- Updated `compile_context` with `since_ms`

### Token Economy

- Member faucet (auto-mint on join)
- Claim rewards (tokens for knowledge)
- Task rewards (tokens for task completion)
- Transfer fees (basis points to treasury)
- Supply caps (total and per-account)

### Security

- Task ID length limit (256 chars)
- Task title/description limits (256 chars / 4KB)
- Error message limit (1KB)
- Presence metadata limit (4KB)
- Assignee must be group member
- Integer overflow protection (MAX_TOKEN_VALUE = 2^63 - 1)

### Infrastructure

- Key encryption at rest (Scrypt + ChaCha20-Poly1305)
- Rate limiting (per-IP connections, per-peer requests)
- Web admin panel
- Auto-sync daemon
- Peer discovery and registry

### Tests

- 177 tests covering all functionality
- Edge case tests for security validations
- Multi-agent coordination tests

### CLI Commands

```bash
lb init --data ./mynode --encrypt-keys
lb run-p2p --data ./mynode --port 7337
lb run-admin --data ./mynode --port 8080
lb run-mcp --data ./mynode
```
