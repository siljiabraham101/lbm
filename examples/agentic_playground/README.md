# Agentic Playground

A **Manus-like** multi-agent coordination system powered by Claude Agent SDK and Learning Batteries Market (LBM).

## Overview

Agentic Playground enables autonomous AI agents to collaborate on complex software projects. An **Orchestrator** agent analyzes your goal, assembles a team of specialized agents, and coordinates their work while sharing knowledge through LBM.

```
                    ┌─────────────────┐
                    │   Orchestrator  │
                    │   (Meta-Agent)  │
                    └────────┬────────┘
                             │
              ┌──────────────┼──────────────┐
              │              │              │
     ┌────────▼───────┐ ┌────▼────┐ ┌───────▼───────┐
     │   Architect    │ │Developer│ │    Tester     │
     │  (System       │ │(Writes  │ │(Creates &     │
     │   Design)      │ │ Code)   │ │ Runs Tests)   │
     └────────┬───────┘ └────┬────┘ └───────┬───────┘
              │              │              │
              └──────────────┼──────────────┘
                             │
                    ┌────────▼────────┐
                    │       LBM       │
                    │ (Knowledge Base)│
                    └─────────────────┘
```

## Features

- **Dynamic Agent Creation**: Orchestrator analyzes goals and creates the right team
- **Specialized Agents**: Architect, Developer, Reviewer, Tester, Documenter
- **Knowledge Sharing**: All agents share insights through LBM
- **Token Economy**: Agents earn tokens for valuable contributions
- **Docker Support**: Isolated containers for agent environments
- **CLI Interface**: Easy project initialization and management

## Installation

```bash
# From the examples/agentic_playground directory
pip install -e .

# Or install dependencies manually
pip install claude-agent-sdk httpx pydantic
```

## Quick Start

### 1. Initialize a Project

```bash
agentic-playground init --name my-api --goal "Build a REST API for user management"
```

This creates:
```
my-api/
├── src/              # Source code
├── tests/            # Test files
├── docs/             # Documentation
├── .lbm/             # LBM knowledge base
│   ├── coordinator/  # Coordinator data
│   └── agents/       # Agent data
├── agentic.json      # Configuration
└── README.md
```

### 2. Set Your API Key

```bash
export ANTHROPIC_API_KEY=your-key-here
```

### 3. Run the Orchestrator

```bash
agentic-playground run --goal "Build a REST API with user registration and authentication"
```

The orchestrator will:
1. Analyze your goal
2. Create a project plan
3. Assemble a team of agents
4. Execute phases sequentially
5. Share learnings via LBM

### 4. Check Status

```bash
agentic-playground status
```

### 5. View Knowledge Base

```bash
agentic-playground knowledge --limit 20
```

## CLI Commands

| Command | Description |
|---------|-------------|
| `init` | Initialize a new project |
| `run` | Run the orchestrator with a goal |
| `status` | Show project status |
| `export` | Export learnings to JSON |
| `docker` | Manage Docker infrastructure |
| `knowledge` | View knowledge base claims |

### Examples

```bash
# Initialize with Docker support
agentic-playground init --name my-project --docker

# Run with verbose output
agentic-playground run --goal "Create a CLI tool" -v

# Export learnings
agentic-playground export --output my-learnings.json

# Docker management
agentic-playground docker setup
agentic-playground docker up
agentic-playground docker down
agentic-playground docker status
```

## Agent Types

### Architect
Designs system architecture and makes technology decisions.
- Tools: Read, Glob, Grep, Write
- Focus: Structure, patterns, tech stack

### Developer
Writes code and implements features.
- Tools: Read, Glob, Grep, Write, Edit, Bash
- Specialties: Backend, Frontend, Full-stack

### Reviewer
Reviews code for quality and security.
- Tools: Read, Glob, Grep (read-only)
- Focus: Best practices, security, performance

### Tester
Creates and runs tests.
- Tools: Read, Glob, Grep, Write, Edit, Bash
- Focus: Unit tests, integration tests, coverage

### Documenter
Writes documentation and comments.
- Tools: Read, Glob, Grep, Write
- Focus: API docs, user guides, inline comments

## Team Presets

```python
from agentic_playground import AgentFactory

factory = AgentFactory(coordinator, work_dir)

# Minimal team: architect + developer
team = factory.create_team(preset="minimal")

# Standard team: architect + developer + tester
team = factory.create_team(preset="standard")

# Full team: all agent types
team = factory.create_team(preset="full")

# API project: architect + backend dev + tester + documenter
team = factory.create_team(preset="api")

# Custom team
team = factory.create_team(preset="custom",
                           custom_roles=["architect", "developer", "reviewer"])
```

## Knowledge Sharing via LBM

All agents share insights through the Learning Batteries Market:

```python
# Share knowledge
coordinator.share_knowledge(
    agent_name="Architect",
    text="Decision: Using FastAPI for REST endpoints due to async support",
    claim_type="decision",
    tags=["architecture", "framework"]
)

# Query knowledge
context, tokens = coordinator.query_knowledge(
    agent_name="Developer",
    query="What framework should I use?"
)
```

### Token Economy

- **Faucet**: New agents receive 100 tokens
- **Claim Rewards**: Earn 10 tokens per knowledge claim
- **Transfer Fees**: 1% fee on transfers (goes to treasury)

## Configuration

`agentic.json`:
```json
{
  "name": "my-project",
  "version": "0.1.0",
  "lbm": {
    "faucet_amount": 100,
    "claim_reward": 10,
    "transfer_fee_bps": 100
  },
  "agents": {
    "default_team": "standard"
  },
  "docker": {
    "enabled": false,
    "image": "agentic-playground:latest"
  }
}
```

## Docker Infrastructure

For isolated agent environments:

```bash
# Generate Docker files
agentic-playground docker setup

# Start all services
agentic-playground docker up

# Stop services
agentic-playground docker down
```

This creates:
- `Dockerfile.agent` - Agent container image
- `docker-compose.yml` - Multi-container orchestration
- `.env.template` - Environment configuration

## Programmatic Usage

```python
import asyncio
from pathlib import Path
from agentic_playground import Orchestrator

async def main():
    # Create orchestrator
    orchestrator = Orchestrator(
        work_dir=Path("./my-project"),
        project_name="my-project"
    )

    # Run with goal
    results = await orchestrator.run(
        "Build a REST API with user authentication"
    )

    print(f"Completed {len(results['results'])} phases")
    print(f"Knowledge claims: {results['stats']['claim_count']}")

asyncio.run(main())
```

## Architecture

```
agentic_playground/
├── __init__.py          # Package exports
├── orchestrator.py      # Master coordination agent
├── cli.py               # Command-line interface
├── lbm/
│   ├── __init__.py
│   └── coordinator.py   # LBM integration layer
├── agents/
│   ├── __init__.py
│   ├── base.py          # Base agent with LBM
│   ├── specialized.py   # Role-specific agents
│   └── factory.py       # Dynamic agent creation
└── infra/
    ├── __init__.py
    ├── docker_manager.py # Container management
    └── project_setup.py  # Project initialization
```

## Requirements

- Python 3.10+
- Claude Agent SDK
- Anthropic API key
- Docker (optional, for containerized agents)

## License

Apache-2.0 - See the repository root LICENSE file for details.

## Credits

- Powered by [Claude Agent SDK](https://github.com/anthropics/claude-agent-sdk)
- Knowledge coordination by [Learning Batteries Market](https://github.com/amazedsaint/lbm)
