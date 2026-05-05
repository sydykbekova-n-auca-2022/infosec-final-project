#!/usr/bin/env bash
# Start both IDS monitors in the background and tail the alert log.
# Stop with Ctrl+C — this script will clean up child processes.

set -e
cd "$(dirname "$0")"

if [ ! -d venv ]; then
  echo "venv/ not found. Run: python3 -m venv venv && source venv/bin/activate && pip install -r requirements.txt"
  exit 1
fi

PYTHON="$PWD/venv/bin/python3"

# Auth monitor needs sudo for /var/log/auth.log
sudo -v  # cache sudo password upfront

echo "Starting auth_monitor.py (sudo)..."
sudo "$PYTHON" auth_monitor.py &
AUTH_PID=$!

echo "Starting process_monitor.py..."
"$PYTHON" process_monitor.py &
PROC_PID=$!

cleanup() {
  echo
  echo "Shutting down..."
  sudo kill "$AUTH_PID" 2>/dev/null || true
  kill "$PROC_PID" 2>/dev/null || true
  wait 2>/dev/null
  echo "Stopped."
}
trap cleanup EXIT INT TERM

echo "Both monitors running. Tailing alerts.log (Ctrl+C to stop everything)."
echo "----"
touch alerts.log
tail -f alerts.log