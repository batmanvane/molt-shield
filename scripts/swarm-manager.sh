#!/bin/bash
# Molt-Shield Claude Code Swarm Manager
# Manages Claude Code agent swarm in tmux sessions using MiniMax-M2.5

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Use claude-m25 alias - MUST source ~/.zshrc first
AGENT_CMD="claude-m25"

SESSION_PREFIX="molt"

# Agent configurations: name:description
AGENTS=(
    "task-manager:Task coordination and planning"
    "code-writer:Implementation and code generation"
    "tester:Testing and validation"
    "researcher:Exploration and research"
)

usage() {
    cat <<EOF
Molt-Shield Claude Code Swarm Manager (MiniMax-M2.5)

Prerequisite: Source your aliases first
    source ~/.zshrc

Usage: $0 <command> [options]

Commands:
    start       Start all agent sessions (requires claude-m25 alias)
    stop        Stop all agent sessions
    status      Show status of all agents
    attach      Attach to a specific agent session
    logs        Show recent logs from an agent

Examples:
    source ~/.zshrc && $0 start
    $0 attach task-manager
    $0 status
EOF
    exit 1
}

start_agents() {
    echo "=== Starting Molt-Shield Swarm (MiniMax-M2.5) ==="

    # Check if claude-m25 alias exists
    if ! alias claude-m25 >/dev/null 2>&1; then
        echo "Error: claude-m25 alias not found"
        echo "Please run: source ~/.zshrc"
        exit 1
    fi

    # Stop any existing sessions
    stop_agents

    # Create agent sessions
    for agent_info in "${AGENTS[@]}"; do
        IFS=':' read -r agent_name agent_desc <<< "$agent_info"
        session_name="${SESSION_PREFIX}-${agent_name}"

        echo "Starting: $agent_name ($agent_desc)"

        # Create detached session with claude-m25
        tmux new-session -d -s "$session_name"
        tmux send-keys -t "$session_name" "cd $PROJECT_ROOT" C-m
        tmux send-keys -t "$session_name" "source ~/.zshrc" C-m
        tmux send-keys -t "$session_name" "$AGENT_CMD" C-m
    done

    echo ""
    echo "=== Swarm started successfully ==="
    echo "Use '$0 attach <agent-name>' to connect to an agent"
    echo ""
    echo "Available agents:"
    for agent_info in "${AGENTS[@]}"; do
        IFS=':' read -r agent_name agent_desc <<< "$agent_info"
        echo "  - $agent_name: $agent_desc"
    done
}

stop_agents() {
    echo "=== Stopping Molt-Shield Swarm ==="

    for agent_info in "${AGENTS[@]}"; do
        IFS=':' read -r agent_name agent_desc <<< "$agent_info"
        session_name="${SESSION_PREFIX}-${agent_name}"
        tmux kill-session -t "$session_name" 2>/dev/null || true
    done

    echo "=== Swarm stopped ==="
}

status_agents() {
    echo "=== Molt-Shield Swarm Status (MiniMax-M2.5) ==="
    echo ""

    for agent_info in "${AGENTS[@]}"; do
        IFS=':' read -r agent_name agent_desc <<< "$agent_info"
        session_name="${SESSION_PREFIX}-${agent_name}"

        if tmux has-session -t "$session_name" 2>/dev/null; then
            echo "  [RUNNING] $agent_name - $agent_desc"
        else
            echo "  [STOPPED] $agent_name - $agent_desc"
        fi
    done
}

attach_agent() {
    agent_name="${1:-task-manager}"
    session_name="${SESSION_PREFIX}-${agent_name}"

    if ! tmux has-session -t "$session_name" 2>/dev/null; then
        echo "Error: Session '$session_name' does not exist"
        echo "Run '$0 start' first"
        exit 1
    fi

    echo "Attaching to $agent_name (Ctrl-B d to detach)"
    tmux attach-session -t "$session_name"
}

show_logs() {
    agent_name="${1:-task-manager}"
    session_name="${SESSION_PREFIX}-${agent_name}"

    if ! tmux has-session -t "$session_name" 2>/dev/null; then
        echo "Error: Session '$session_name' does not exist"
        exit 1
    fi

    tmux capture-pane -t "$session_name" -p -S -100
}

# Main dispatcher
case "${1:-}" in
    start) start_agents ;;
    stop) stop_agents ;;
    status) status_agents ;;
    attach) attach_agent "${2:-}" ;;
    logs) show_logs "${2:-}" ;;
    *) usage ;;
esac
