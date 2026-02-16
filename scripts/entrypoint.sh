#!/bin/sh
set -e

echo "=== Molt-Shield Security Gateway ==="
echo "Strict Mode: ${MOLT_STRICT:-false}"
echo "Host Binding: ${MOLT_HOST:-127.0.0.1}"

if [ "${MOLT_STRICT:-false}" = "true" ]; then
    echo "[SECURITY] Verifying network isolation..."

    if [ "${MOLT_HOST}" != "127.0.0.1" ] && [ "${MOLT_HOST}" != "localhost" ]; then
        echo "[ERROR] Strict mode requires localhost binding only"
        exit 1
    fi

    if [ -n "${HTTP_PROXY}" ] || [ -n "${HTTPS_PROXY}" ]; then
        echo "[ERROR] Proxy environment variables not allowed in strict mode"
        exit 1
    fi

    echo "[SECURITY] Network isolation verified"
fi

if [ ! -f "/home/appuser/config/policy.json" ]; then
    echo "[WARN] No policy file found at /home/appuser/config/policy.json"
    echo "[WARN] Run policy generation before serving"
fi

echo "[INFO] Starting MCP Server..."
exec python -m src.server "$@"
