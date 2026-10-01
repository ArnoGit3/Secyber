#!/bin/bash
# ARNTECH CYBER LAB - Installation Script
# ==========================================
set -e

GREEN='\033[0;32m'
CYAN='\033[0;36m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${GREEN}"
echo "╔══════════════════════════════════════════════════════╗"
echo "║              ARNTECH CYBER LAB - INSTALLER            ║"
echo "╚══════════════════════════════════════════════════════╝"
echo -e "${NC}"

# 1. Check Python
echo -e "${CYAN}[*] Checking for Python 3...${NC}"
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}[-] python3 not found. Please install Python 3.9+ and re-run this script.${NC}"
    exit 1
fi
PYVER=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
echo -e "${GREEN}[+] Found Python ${PYVER}${NC}"

# 2. Create virtual environment
echo -e "${CYAN}[*] Creating virtual environment (venv/)...${NC}"
if [ ! -d "venv" ]; then
    python3 -m venv venv
    echo -e "${GREEN}[+] Virtual environment created.${NC}"
else
    echo -e "${CYAN}[*] venv/ already exists, skipping.${NC}"
fi

# 3. Activate and install dependencies
echo -e "${CYAN}[*] Installing dependencies from requirements.txt...${NC}"
source venv/bin/activate
pip install --upgrade pip -q
pip install -r requirements.txt -q
echo -e "${GREEN}[+] Dependencies installed.${NC}"

# 4. Create required directories
echo -e "${CYAN}[*] Creating data directories...${NC}"
mkdir -p data/synthetic_data data/logs reports
echo -e "${GREEN}[+] Directories ready.${NC}"

# 5. Initialize database
echo -e "${CYAN}[*] Initializing training database...${NC}"
python3 -c "from lab_server.database import init_db; init_db()"
echo -e "${GREEN}[+] Database initialized at data/lab.db${NC}"

# 6. Done
echo -e "${GREEN}"
echo "╔══════════════════════════════════════════════════════╗"
echo "║            INSTALLATION COMPLETE                      ║"
echo "╠══════════════════════════════════════════════════════╣"
echo "║  Next steps:                                          ║"
echo "║    source venv/bin/activate                           ║"
echo "║    python3 cli.py                                     ║"
echo "╚══════════════════════════════════════════════════════╝"
echo -e "${NC}"
