#!/usr/bin/env bash
set -euo pipefail

BLUE='\033[0;34m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${BLUE}======================================${NC}"
echo -e "${BLUE}  FALCOHIVE                           ${NC}"
echo -e "${BLUE}  Container Security Attack Lab       ${NC}"
echo -e "${BLUE}======================================${NC}"
echo ""

echo -e "${YELLOW}Building all Docker images...${NC}"
docker compose build
echo -e "${GREEN}Images built.${NC}"
echo ""

echo -e "${YELLOW}Starting dashboard (ai-agent only)...${NC}"
docker compose up -d ai-agent

# Read port from .env or default to 3001
AI_AGENT_PORT=$(grep -oP '^AI_AGENT_PORT=\K.*' .env 2>/dev/null || echo "3001")

echo -e "${YELLOW}Waiting for dashboard to be ready...${NC}"
for i in {1..15}; do
    if curl -s "http://localhost:${AI_AGENT_PORT}/api/events" 2>/dev/null | grep -q "events"; then
        echo -e "${GREEN}Dashboard is ready!${NC}"
        break
    fi
    echo -n "."
    sleep 2
done
echo ""

echo -e "${GREEN}======================================${NC}"
echo -e "${GREEN}  FalcoHive is ready!                 ${NC}"
echo -e "${GREEN}======================================${NC}"
echo ""
echo -e "  Dashboard:     ${BLUE}http://localhost:${AI_AGENT_PORT}${NC}"
echo -e ""
echo -e "${YELLOW}To start the full pipeline:${NC}"
echo -e "  Open http://localhost:${AI_AGENT_PORT} and click ${GREEN}\"Run Full Pipeline\"${NC}"
echo -e "  This starts all infrastructure, runs attacks, detects with Falco,"
echo -e "  analyzes with AI, and reports results."
echo -e ""
echo -e "${YELLOW}Requirements:${NC}"
echo -e "  Set ${GREEN}CLAUDE_API_KEY${NC} in .env (see Step 2 in README)"
echo -e ""
echo -e "${YELLOW}To stop everything:${NC}"
echo -e "  docker compose down"
echo ""
