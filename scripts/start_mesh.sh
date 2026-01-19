#!/bin/bash
# start_mesh.sh - Startup script for Learning Batteries Market (LBM)
# Usage: ./start_mesh.sh [--bg|--fg|--kill]

# Configuration
LBM_DIR="$HOME/Code/lbm"
NODE_DIR_HUB="./node"
NODE_DIR_CLIENT="$HOME/my-brain/node"
VENV_PYTHON="$LBM_DIR/.venv/bin/python"
LB_BIN="$LBM_DIR/.venv/bin/lb"
SCREEN_SESSION="lbm_mesh"

# Detect Node Directory
# If running on Mac Mini (Hub), use local ./node if checking from repo, or explicit path
HOST_LOWER=$(hostname | tr '[:upper:]' '[:lower:]')
if [[ "$HOST_LOWER" == *"mac-mini"* ]]; then
    # Hub Configuration
    DATA_ARG="--data $LBM_DIR/node"
    P2P_PORT=7337
    ROLE="HUB"
else
    # Client Configuration (Laptop)
    DATA_ARG="--data $NODE_DIR_CLIENT"
    P2P_PORT=7337 # Client listens on same port usually, or 7338 if testing locally
    ROLE="CLIENT"
fi

echo "🧠 Starting Personal Knowledge Mesh ($ROLE)..."
echo "   Data: $DATA_ARG"
echo "   Port: $P2P_PORT"

# Function to stop existing processes
stop_mesh() {
    echo "🛑 Stopping existing LBM processes..."
    pkill -f "lb.*run-p2p"
    pkill -f "lb.*run-mcp"
    # Also wipe screen session if exists
    screen -X -S "$SCREEN_SESSION" quit 2>/dev/null
    echo "✅ Stopped."
}

# Parse Arguments
MODE="fg"
if [[ "$1" == "--bg" ]]; then
    MODE="bg"
elif [[ "$1" == "--kill" ]]; then
    stop_mesh
    exit 0
fi

# Ensure cleanup on exit in FG mode
trap stop_mesh EXIT

if [[ "$MODE" == "bg" ]]; then
    echo "🚀 Launching in BACKGROUND (Screen session: $SCREEN_SESSION)..."
    
    # 1. Start Screen detached
    screen -dmS "$SCREEN_SESSION"
    
    # 2. Run P2P Server
    screen -S "$SCREEN_SESSION" -X screen -t "P2P" bash -c "$LB_BIN $DATA_ARG run-p2p --host 0.0.0.0 --port $P2P_PORT; exec bash"
    
    # 3. Run Sync Daemon
    screen -S "$SCREEN_SESSION" -X screen -t "Sync" bash -c "$LB_BIN $DATA_ARG run-sync-daemon; exec bash"
    
    echo "✅ Started! View logs with: screen -r $SCREEN_SESSION"
    echo "   (Detach again with Ctrl+A, D)"
    
else
    echo "🚀 Launching in FOREGROUND..."
    
    # Run P2P in background task of this shell
    $LB_BIN $DATA_ARG run-p2p --host 0.0.0.0 --port $P2P_PORT &
    P2P_PID=$!

    # Run Sync Daemon in background task
    $LB_BIN $DATA_ARG run-sync-daemon &
    SYNC_PID=$!
    
    echo "   P2P Server running (PID: $P2P_PID)"
    echo "   Sync Daemon running (PID: $SYNC_PID)"
    echo "   Press Ctrl+C to stop."
    
    # Wait for processes
    wait $P2P_PID $SYNC_PID
fi
