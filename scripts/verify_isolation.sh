#!/bin/bash
# verify_isolation.sh
# Verifies that the runtime environment meets security isolation requirements

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

ERRORS=0
WARNINGS=0

echo "=== Molt-Shield Security Isolation Verification ==="
echo ""

# Check if running in container
check_container() {
    echo "[1/8] Checking container environment..."

    if [ -f /.dockerenv ]; then
        echo "  ✓ Running inside Docker container"
    elif grep -q "docker\|lxc" /proc/1/cgroup 2>/dev/null; then
        echo "  ✓ Running inside container (detected via cgroup)"
    else
        echo "  ⚠ Not running in container - some checks may not apply"
    fi
}

# Check user is non-root
check_non_root() {
    echo "[2/8] Checking process user..."

    local uid
    uid=$(id -u 2>/dev/null || echo "unknown")

    if [ "$uid" = "0" ]; then
        echo -e "  ✗ ${RED}Running as root (UID=$uid) - should be non-root${NC}"
        ((ERRORS++))
    else
        echo -e "  ✓ ${GREEN}Running as non-root (UID=$uid)${NC}"
    fi
}

# Check network binding
check_network() {
    echo "[3/8] Checking network binding..."

    local host
    host="${MOLT_HOST:-127.0.0.1}"

    if [ "$host" = "127.0.0.1" ] || [ "$host" = "localhost" ] || [ "$host" = "::1" ]; then
        echo -e "  ✓ ${GREEN}Network binding is isolated ($host)${NC}"
    else
        echo -e "  ✗ ${RED}Network binding not isolated ($host)${NC}"
        ((ERRORS++))
    fi
}

# Check no proxy variables
check_proxy() {
    echo "[4/8] Checking proxy variables..."

    local proxy_vars=("HTTP_PROXY" "HTTPS_PROXY" "http_proxy" "https_proxy")
    local found=0

    for var in "${proxy_vars[@]}"; do
        if [ -n "${!var}" ]; then
            echo "  ✗ $var is set"
            ((found++))
        fi
    done

    if [ $found -eq 0 ]; then
        echo -e "  ✓ ${GREEN}No proxy variables set${NC}"
    else
        echo -e "  ✗ ${RED}$found proxy variable(s) set${NC}"
        ((ERRORS++))
    fi
}

# Check filesystem permissions
check_filesystem() {
    echo "[5/8] Checking filesystem permissions..."

    local input_dir="${MOLT_INPUT_DIR:-$PROJECT_ROOT/data/input}"

    if [ ! -d "$input_dir" ]; then
        echo -e "  ⚠ ${YELLOW}Input directory does not exist: $input_dir${NC}"
        ((WARNINGS++))
        return
    fi

    # Try to create a test file
    if touch "$input_dir/.write_test" 2>/dev/null; then
        rm -f "$input_dir/.write_test"
        echo -e "  ✗ ${RED}Input directory is writable (should be read-only)${NC}"
        ((ERRORS++))
    else
        echo -e "  ✓ ${GREEN}Input directory is read-only${NC}"
    fi
}

# Check no-new-privileges
check_no_new_privileges() {
    echo "[6/8] Checking no-new-privileges..."

    if [ ! -f /proc/self/status ]; then
        echo "  ⚠ /proc not available (not Linux?)"
        return
    fi

    local no_new_privs
    no_new_privs=$(grep -E "^NoNewPrivs:" /proc/self/status 2>/dev/null | cut -f2 | tr -d ' \t')

    if [ "$no_new_privs" = "1" ]; then
        echo -e "  ✓ ${GREEN}no-new-privileges is enabled${NC}"
    else
        echo -e "  ⚠ ${YELLOW}no-new-privileges not detected (may not be in container)${NC}"
        ((WARNINGS++))
    fi
}

# Check capabilities
check_capabilities() {
    echo "[7/8] Checking capabilities..."

    if ! command -v capsh &> /dev/null; then
        echo "  ⚠ capsh not available - skipping capability check"
        return
    fi

    local current_caps
    current_caps=$(capsh --print 2>/dev/null | grep "Current:" | head -1)

    if echo "$current_caps" | grep -qE "(cap_sys_admin|cap_net_admin|cap_sys_ptrace)"; then
        echo -e "  ✗ ${RED}Dangerous capabilities detected${NC}"
        ((ERRORS++))
    else
        echo -e "  ✓ ${GREEN}No dangerous capabilities${NC}"
    fi
}

# Check strict mode
check_strict_mode() {
    echo "[8/8] Checking strict mode..."

    local strict
    strict="${MOLT_STRICT:-false}"

    if [ "$strict" = "true" ]; then
        echo -e "  ✓ ${GREEN}Strict mode enabled${NC}"
    else
        echo -e "  ⚠ ${YELLOW}Strict mode not enabled (MOLT_STRICT=$strict)${NC}"
        ((WARNINGS++))
    fi
}

# Run all checks
main() {
    check_container
    check_non_root
    check_network
    check_proxy
    check_filesystem
    check_no_new_privileges
    check_capabilities
    check_strict_mode

    echo ""
    echo "=== Verification Summary ==="

    if [ $ERRORS -gt 0 ]; then
        echo -e "  ${RED}ERRORS: $ERRORS${NC}"
    fi

    if [ $WARNINGS -gt 0 ]; then
        echo -e "  ${YELLOW}WARNINGS: $WARNINGS${NC}"
    fi

    if [ $ERRORS -eq 0 ] && [ $WARNINGS -eq 0 ]; then
        echo -e "  ${GREEN}All checks passed!${NC}"
        exit 0
    elif [ $ERRORS -eq 0 ]; then
        echo -e "  ${GREEN}No errors, but $WARNINGS warning(s)${NC}"
        exit 0
    else
        echo -e "  ${RED}Verification failed with $ERRORS error(s)${NC}"
        exit 1
    fi
}

main "$@"
