# Molt-Shield Architecture

## System Overview

Molt-Shield is a containerized MCP (Model Context Protocol) server that acts as a zero-trust gateway between proprietary scientific data and cloud AI services.

## Component Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                        Claude Desktop                             │
│                     (localhost:3000)                              │
└─────────────────────────┬───────────────────────────────────────┘
                          │ MCP Protocol (stdio)
                          ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Molt-Shield Container                         │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │                    MCP Server                              │  │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────────┐  │  │
│  │  │   Server    │  │  Policy     │  │    Security     │  │  │
│  │  │  (server.py)│  │  Engine     │  │   Verification  │  │  │
│  │  └──────┬──────┘  └──────┬──────┘  └────────┬────────┘  │  │
│  │         │                │                   │           │  │
│  │         └────────────────┼───────────────────┘           │  │
│  │                          ▼                                │  │
│  │  ┌─────────────────────────────────────────────────────┐ │  │
│  │  │              Gatekeeper (gatekeeper.py)             │ │  │
│  │  │  ┌────────────┐  ┌────────────┐  ┌──────────────┐  │ │  │
│  │  │  │   Mask     │  │   Shuffle  │  │ Tag Shadow   │  │ │  │
│  │  │  │  Values    │  │  Siblings  │  │    Map       │  │ │  │
│  │  │  └─────┬──────┘  └─────┬──────┘  └──────┬───────┘  │ │  │
│  │  └────────┼────────────────┼────────────────┼──────────┘ │  │
│  │           │                │                │             │  │
│  └───────────┼────────────────┼────────────────┼─────────────┘  │
│              │                │                │                 │
│              ▼                ▼                ▼                 │
│    ┌──────────────┐  ┌──────────────┐  ┌──────────────┐       │
│    │  Input XML   │  │  Vault       │  │ Output XML  │       │
│    │  (Read-Only) │  │  (tmpfs)     │  │ (Writable)  │       │
│    └──────────────┘  └──────────────┘  └──────────────┘       │
└─────────────────────────────────────────────────────────────────┘
```

## Core Components

### 1. Server (server.py)

The MCP server that exposes tools to Claude Desktop via stdio.

**Tools exposed:**
- `read_safe_structure` - Read and sanitize XML
- `submit_optimization` - Receive AI suggestions
- `list_policies` - List available policies
- `get_vault_info` - Show vault status

### 2. Policy Engine (policy_engine.py)

Manages security policies that define what to mask/shuffle.

**Policy structure:**
```python
@dataclass
class Policy:
    version: str
    global_masking: bool
    rules: list[Rule]

@dataclass
class Rule:
    tag_pattern: str  # XPath or tag name
    action: Literal["preserve", "redact", "mask_value", "shuffle_siblings"]
    parameters: dict | None
```

### 3. Gatekeeper (gatekeeper.py)

Applies security transformations to XML documents.

**Transformations:**
1. **Value Masking** - Replace numeric values with `VAL_<uuid>`
2. **Tag Shadowing** - Map proprietary tags to generic names
3. **Sibling Shuffling** - Randomize element order

### 4. Vault (vault.py)

Stores original values for later rehydration.

**Storage format:**
```json
{
  "VAL_abc123": {
    "masked_value": "VAL_abc123",
    "original_value": "123.45",
    "created_at": "2024-01-15T10:30:00Z"
  }
}
```

### 5. Security (security.py)

Verifies container/runtime security posture.

**Checks:**
- Network isolation (localhost only)
- Filesystem permissions (read-only input)
- Process security (non-root, no-new-privileges)

## Data Flow

```
1. Input XML (read-only volume)
       │
       ▼
2. Policy loaded (config/policy_locked.json)
       │
       ▼
3. Gatekeeper applies transformations
   - Mask numeric values → VAL_<uuid>
   - Shadow proprietary tags → generic names
   - Shuffle sibling elements → random order
       │
       ├──────────────────┬──────────────────┐
       ▼                  ▼                  ▼
4. Output XML      Vault Storage      Metadata
   (writable)     (tmpfs/encrypted)  (logs)
```

## Directory Structure

```
molt-shield/
├── src/
│   ├── server.py         # MCP server entry
│   ├── policy_engine.py  # Policy management
│   ├── gatekeeper.py    # XML transformations
│   ├── vault.py         # Value storage
│   ├── config.py        # Configuration
│   ├── cli.py           # CLI interface
│   └── security.py      # Security checks
├── config/
│   ├── default.yaml     # Default config
│   ├── security.yaml    # Security policies
│   └── policy_locked.json  # Active policy
├── data/
│   ├── input/           # Read-only input
│   └── output/          # Writable output
├── vault/               # Vault storage (tmpfs)
├── compose/             # Docker Compose files
└── tests/              # Test suite
```

## Container Security Layers

| Layer | Protection |
|-------|------------|
| Network | Binds to localhost only (127.0.0.1) |
| Filesystem | Input volumes read-only, output write-only |
| Process | Non-root user, no-new-privileges |
| Memory | Vault in tmpfs (encrypted at rest) |

## Extension Points

### Custom Tag Mappings

Edit `gatekeeper.py` to add custom tag shadows:

```python
DEFAULT_TAG_MAP = {
    "pressure": "metric_alpha",
    "temperature": "thermal_beta",
    "velocity": "kinematic_gamma",
    # Add your custom mappings
}
```

### Custom Policies

Create custom policies in `config/`:

```json
{
  "version": "1.0",
  "global_masking": true,
  "rules": [
    {"tag_pattern": "your_tag", "action": "mask_value"}
  ]
}
```
