# Molt-Shield

**Zero-Trust Engineering Gateway** - A containerized MCP server that anonymizes proprietary XML data before it reaches Cloud AI services.

## How It Works (End-to-End)

```
┌──────────────────────────────────────────────────────────────────────────────────┐
│                           MOLT-SHIELD DATA FLOW                                 │
└──────────────────────────────────────────────────────────────────────────────────┘

  ┌─────────────┐     ┌──────────────┐     ┌─────────────────┐     ┌─────────┐
  │  YOUR DATA  │     │    CLI       │     │   GATEKEEPER    │     │  VAULT  │
  │             │     │   (scan)     │     │   (transforms)  │     │         │
  └──────┬──────┘     └──────┬───────┘     └────────┬────────┘     └────┬────┘
         │                    │                       │                   │
         │  <simulation.xml> │                       │                   │
         │───────────────────>│                       │                   │
         │                    │                       │                   │
         │                    │  Generate Policy      │                   │
         │                    │──────────────────────>│                   │
         │                    │                       │                   │
         │                    │  policy_locked.json   │                   │
         │                    │<──────────────────────│                   │
         │                    │                       │                   │
         │                    │    ┌─────────────────┴─────────────┐       │
         │                    │    │      MCP SERVER (port 3000)   │       │
         │                    │    │                               │       │
         │                    │    │  ┌─────────────────────────┐ │       │
         │                    │    │  │   read_safe_structure  │ │       │
         │                    │    │  │        tool             │ │       │
         │                    │    │  └─────────────────────────┘ │       │
         │                    │    └───────────────────────────────┘       │
         │                    │                       │                   │
         └────────────────────┘                       │                   │
                                                     │                   │
                                                     ▼                   ▼
  ┌─────────────────────────────────────────────────────────────────────────────┐
  │                         CLOUD AI (Claude Desktop)                           │
  │                                                                             │
  │   ┌─────────────────────────────────────────────────────────────────────┐   │
  │   │                    SANITIZED OUTPUT                                  │   │
  │   │                                                                      │   │
  │   │   <simulation>                                                      │   │
  │   │     <element id="e1">                                               │   │
  │   │       <metric_alpha>VAL_a1b2c3</metric_alpha>    ← masked!         │   │
  │   │       <thermal_beta>VAL_d4e5f6</thermal_beta>   ← masked!         │   │
  │   │     </element>                                                       │   │
  │   │     <element id="e2">                                               │   │
  │   │       <metric_alpha>VAL_g7h8i9</metric_alpha>                       │   │
  │   │     </element>                                                       │   │
  │   │   </simulation>                                                     │   │
  │   │                                                                      │   │
  │   │   ✓ No proprietary tag names                                        │   │
  │   │   ✓ No numeric values                                               │   │
  │   │   ✓ Semantic structure preserved                                    │   │
  │   └─────────────────────────────────────────────────────────────────────┘   │
  └─────────────────────────────────────────────────────────────────────────────┘

  ===============================================================================
  TRANSFORMATION EXAMPLE:
  ===============================================================================

  INPUT (Proprietary)          OUTPUT (Anonymized)
  ─────────────────────        ────────────────────
  <element id="e1">            →     <element id="e1">
    <pressure>123.45</pressure>     <metric_alpha>VAL_x7k2m</metric_alpha>
    <temperature>500.0</temperature>→ <thermal_beta>VAL_p9q3r</thermal_beta>
  </element>                       </element>

  TAG SHADOWING MAP:
  ─────────────────
  pressure    → metric_alpha
  temperature → thermal_beta
  velocity   → kinematic_gamma
  coordinates→ spatial_delta
```

## Overview

Molt-Shield acts as a deterministic firewall between your proprietary scientific/simulation/... data and cloud AI services. It "shuffles and masks" XML data to ensure semantic reasoning without IP leakage.

## Features

- **Value Masking** - Replaces numeric values with UUID placeholders
- **Tag Shadowing** - Maps proprietary tag names to generic equivalents
- **Sibling Shuffling** - Randomizes element order for structural anonymity
- **Vault Storage** - Stores originals for later rehydration
- **Zero-Trust Security** - Network isolation, read-only volumes, non-root execution

## Quickstart

### 1. Installation

```bash
# Clone or navigate to project
cd /path/to/molt-shield

# Create virtual environment (optional)
python -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 2. Generate a Policy

```bash
# Scan an XML file to auto-generate a security policy
python -m src.cli scan tests/fixtures/sample.xml
```

This creates `config/policy_locked.json` with rules for masking, shuffling, and tag shadowing.

### 3. Run the MCP Server

```bash
# Start the server (binds to localhost:3000)
python -m src.cli serve

# Or with custom settings
python -m src.cli serve --host 127.0.0.1 --port 3000 --strict
```

### 4. Use with Claude Desktop

Configure Claude Desktop to connect to Molt-Shield:

```json
{
  "mcpServers": {
    "molt-shield": {
      "command": "python",
      "args": ["-m", "src.server"],
      "env": {
        "PYTHONPATH": "/path/to/molt-shield"
      }
    }
  }
}
```

## Usage

### CLI Commands

```bash
# Scan and generate policy
python -m src.cli scan <input.xml>

# Start MCP server
python -m src.cli serve

# Show help
python -m src.cli --help
```

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `MOLT_HOST` | `127.0.0.1` | Server bind address |
| `MOLT_PORT` | `3000` | Server port |
| `MOLT_STRICT` | `false` | Enable strict security mode |
| `MOLT_INPUT_DIR` | `./data/input` | Input XML directory |
| `MOLT_OUTPUT_DIR` | `./data/output` | Output directory |
| `MOLT_VAULT_DIR` | `./vault` | Vault storage directory |

## Tutorial

### Step 1: Prepare Your Data

Place your XML files in the input directory:

```bash
mkdir -p data/input
cp your_simulation.xml data/input/
```

### Step 2: Generate a Policy

Run the scanner to auto-detect sensitive elements:

```bash
python -m src.cli scan data/input/your_simulation.xml
```

Review the generated `config/policy_locked.json`:

```json
{
  "version": "1.0",
  "global_masking": true,
  "rules": [
    {"tag_pattern": "pressure", "action": "mask_value"},
    {"tag_pattern": "temperature", "action": "mask_value"},
    {"tag_pattern": "element", "action": "shuffle_siblings"}
  ]
}
```

### Step 3: Start the Server

```bash
python -m src.cli serve
```

### Step 4: Analyze with AI

In Claude Desktop, use the tools:

```
read_safe_structure(filepath="your_simulation.xml")
```

The AI receives sanitized data while originals stay in the vault.

### Step 5: Rehydrate (Optional)

After AI analysis, restore original values from the vault:

```bash
# Rehydrate a JSON file (e.g., AI suggestions)
python -m src.cli rehydrate ai_suggestions.json --vault vault/session.vault.json

# Rehydrate an XML file
python -m src.cli rehydrate modified_data.xml --vault vault/session.vault.json

# Rehydrate in-place (creates backup)
python -m src.cli rehydrate data.xml --vault vault/session.vault.json --in-place
```

**Example workflow:**
```bash
# 1. AI analyzes sanitized data and returns suggestions:
#    {"element": {"id": "e1", "pressure": "VAL_x7k2m"}}

# 2. Rehydrate to get original values:
#    {"element": {"id": "e1", "pressure": "123.45"}}
```

## Notebooks (Google Colab)

Interactive tutorials for learning and experimentation:

| Notebook | Description |
|----------|-------------|
| [molt_shield_demo.ipynb](notebooks/molt_shield_demo.ipynb) | Basic masking, shuffling, and rehydration |
| [molt_shield_llm_demo.ipynb](notebooks/molt_shield_llm_demo.ipynb) | Full LLM workflow with simulated responses |
| [custom_policies_workshop.ipynb](notebooks/custom_policies_workshop.ipynb) | Create policies for CFD, FEA, thermal simulations |
| [batch_processing_pipeline.ipynb](notebooks/batch_processing_pipeline.ipynb) | Process multiple XML files automatically |
| [fastapi_integration.ipynb](notebooks/fastapi_integration.ipynb) | REST API with FastAPI |
| [cicd_github_actions.ipynb](notebooks/cicd_github_actions.ipynb) | CI/CD automation with GitHub Actions |

### Running Notebooks in Google Colab

```python
# Clone from GitHub
!git clone https://github.com/batmanvane/molt-shield.git /content/molt-shield

# Or upload files manually
# Upload src/ and config/ folders to Colab

# Dependencies are auto-installed in each notebook
```

## Docker Deployment

### Development

```bash
docker-compose -f compose/docker-compose.yml up --build
```

### Production

```bash
docker-compose -f compose/docker-compose.prod.yml up --build
```

## Architecture

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for detailed architecture.

## Security

See [docs/SECURITY.md](docs/SECURITY.md) for security considerations.

## Testing

```bash
# Run all tests
./scripts/run_tests.sh

# Or with pytest directly
python -m pytest tests/ -v
```

## License

MIT
