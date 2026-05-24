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
echo -e "${BLUE}  Falco + Sidekick + ES + Kibana     ${NC}"
echo -e "${BLUE}  AI-Powered Security Orchestration   ${NC}"
echo -e "${BLUE}======================================${NC}"
echo ""

MODE="${1:-standard}"

echo -e "${YELLOW}[1/3] Building images...${NC}"
docker compose build

echo ""
echo -e "${YELLOW}[2/3] Starting infrastructure (ES, Kibana, Falco, Sidekick, targets)...${NC}"
docker compose up -d elasticsearch kibana falco falcosidekick falcosidekick-ui redis postgres target-app ai-agent

echo -e "${YELLOW}Waiting for Elasticsearch to be ready...${NC}"
for i in {1..30}; do
    if curl -s http://localhost:9200/_cluster/health 2>/dev/null | grep -q "yellow\|green"; then
        echo -e "${GREEN}Elasticsearch is ready!${NC}"
        break
    fi
    echo -n "."
    sleep 2
done
echo ""

echo -e "${YELLOW}Waiting for Kibana...${NC}"
for i in {1..15}; do
    if curl -s http://localhost:5601/api/status 2>/dev/null | grep -q "available"; then
        echo -e "${GREEN}Kibana is ready!${NC}"
        break
    fi
    echo -n "."
    sleep 2
done
echo ""

echo -e "${YELLOW}Waiting for AI Agent...${NC}"
for i in {1..15}; do
    if curl -s http://localhost:3000/api/events 2>/dev/null | grep -q "events"; then
        echo -e "${GREEN}AI Agent is ready!${NC}"
        break
    fi
    echo -n "."
    sleep 2
done
echo ""

if [ "$MODE" = "ai" ]; then
    echo ""
    echo -e "${YELLOW}[AI MODE] Triggering AI Orchestration Pipeline...${NC}"
    echo -e "${YELLOW}The AI agent will set up, attack, detect, analyze, and report.${NC}"
    echo -e "${YELLOW}Check the dashboard at http://localhost:3000 for progress.${NC}"
    curl -s -X POST http://localhost:3000/api/orchestrate \
        -H "Content-Type: application/json" \
        -d '{"goal": "Set up the full container security lab: start all infrastructure, launch all attacks, detect them with Falco, analyze with AI, and report results."}'
    echo ""
    echo -e "${GREEN}Orchestration started! View progress at:${NC}"
    echo -e "  Dashboard:     ${BLUE}http://localhost:3000${NC}"
else
    echo ""
    echo -e "${YELLOW}[3/3] Running attacker (unique attacks)...${NC}"
    docker compose up attacker

    echo ""
    echo -e "${GREEN}All attacks completed!${NC}"
fi

echo ""
echo -e "${GREEN}======================================${NC}"
echo -e "${GREEN}  Lab is ready!                       ${NC}"
echo -e "${GREEN}======================================${NC}"
echo ""
echo -e "  Dashboard:     ${BLUE}http://localhost:3000${NC}"
echo -e "  Kibana:        ${BLUE}http://localhost:5601${NC}"
echo -e "  Elasticsearch: ${BLUE}http://localhost:9200${NC}"
echo -e "  Target App:    ${BLUE}http://localhost:8090${NC}"
echo ""
echo -e "${YELLOW}Usage:${NC}"
echo -e "  ./run.sh          - Traditional mode (bash-driven setup + attacks)"
echo -e "  ./run.sh ai       - AI-driven mode (Claude orchestrates everything)"
echo ""
echo -e "${YELLOW}To re-run attacks:${NC}"
echo -e "  docker compose up attacker"
echo ""
echo -e "${YELLOW}To stop everything:${NC}"
echo -e "  docker compose down"
echo ""
echo -e "${YELLOW}To re-run AI orchestration:${NC}"
echo -e "  curl -X POST http://localhost:3000/api/orchestrate"
echo ""
