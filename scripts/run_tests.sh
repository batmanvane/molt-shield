#!/bin/bash
# Molt-Shield Test Suite Runner
# Executes unit, integration, and security tests

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

echo "=== Molt-Shield Test Suite ==="
echo "Project root: $PROJECT_ROOT"
echo ""

# Change to project root
cd "$PROJECT_ROOT"

# Ensure test environment
export PYTHONPATH="$PROJECT_ROOT:$PYTHONPATH"

# Run tests with coverage
echo "[1/4] Running unit tests..."
python -m pytest tests/unit/ -v --tb=short --cov=src --cov-report=term-missing

echo ""
echo "[2/4] Running integration tests..."
python -m pytest tests/integration/ -v --tb=short --cov=src --cov-report=term-missing

echo ""
echo "[3/4] Running security tests..."
python -m pytest tests/security/ -v --tb=short --cov=src --cov-report=term-missing

echo ""
echo "[4/4] Generating coverage report..."
python -m pytest tests/ -v --tb=short --cov=src --cov-report=term-missing --cov-report=html 2>/dev/null || true

echo ""
echo "=== All tests passed ==="
