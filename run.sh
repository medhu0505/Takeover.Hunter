#!/bin/bash
# TAKEOVER.SH — Setup & Run (fixed for Kali)

set -e

echo ""
echo "================================================"
echo "  TAKEOVER.SH — Subdomain Takeover Hunter"
echo "================================================"
echo ""

# Install missing venv module if needed
if ! python3 -m venv --help &>/dev/null; then
  echo "[*] Installing python3.13-venv..."
  sudo apt update && sudo apt install python3.13-venv -y
fi

# Check Python
if ! command -v python3 &>/dev/null; then
  echo "[ERROR] python3 not found."
  exit 1
fi

# Virtualenv
if [ ! -d "venv" ]; then
  echo "[*] Creating virtual environment..."
  rm -rf venv 2>/dev/null || true
  python3 -m venv venv
fi

# Activate venv (safe way)
if [ -f "venv/bin/activate" ]; then
  source venv/bin/activate
else
  echo "[ERROR] venv activation failed. Recreating..."
  rm -rf venv
  python3 -m venv venv
  source venv/bin/activate
fi

echo "[*] Installing dependencies..."
pip install -q -r requirements.txt

echo ""
echo "[*] Optional recon tools:"
for tool in subfinder assetfinder amass; do
  if command -v $tool &>/dev/null; then
    echo " [OK] $tool found"
  else
    echo " [--] $tool not found (install manually if needed)"
  fi
done

echo ""
echo "[*] Starting server at http://127.0.0.1:5000"
echo "[*] Press Ctrl+C to stop"
echo ""

python3 app.py