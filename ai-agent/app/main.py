import os
import json
import logging
import time
import asyncio
import uuid
from datetime import datetime, timezone
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from elasticsearch import Elasticsearch
from dotenv import load_dotenv

from app.analysis_agent import AnalysisAgent
from app.remediation_agent import RemediationAgent
from app.infra_agent import InfraAgent
from app.attack_agent import AttackAgent
from app.monitor_agent import MonitorAgent
from app.orchestrator_agent import OrchestratorAgent

load_dotenv()

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
log = logging.getLogger("ai-agent")

ES_HOST = os.getenv("ES_HOST", "http://elasticsearch:9200")
CLAUDE_API_KEY = os.getenv("CLAUDE_API_KEY", "")
CLAUDE_MODEL = os.getenv("CLAUDE_MODEL", "claude-sonnet-4-20250514")

es = Elasticsearch(ES_HOST)
analysis_agent = AnalysisAgent(api_key=CLAUDE_API_KEY, model=CLAUDE_MODEL)
remediation_agent = RemediationAgent(api_key=CLAUDE_API_KEY, model=CLAUDE_MODEL)
infra_agent = InfraAgent()
attack_agent = AttackAgent()
monitor_agent = MonitorAgent(es_host=ES_HOST)
orchestrator_agent = OrchestratorAgent(
    api_key=CLAUDE_API_KEY,
    model=CLAUDE_MODEL,
    infra_agent=infra_agent,
    attack_agent=attack_agent,
    monitor_agent=monitor_agent,
    analysis_agent=analysis_agent,
    remediation_agent=remediation_agent,
)

ANALYSIS_INDEX = "ai-attack-analysis"
REMEDIATION_INDEX = "ai-remediation-actions"
ORCHESTRATION_INDEX = "ai-orchestration-sessions"

orchestration_sessions: dict[str, dict] = {}

@asynccontextmanager
async def lifespan(app: FastAPI):
    for idx in [ANALYSIS_INDEX, REMEDIATION_INDEX, ORCHESTRATION_INDEX]:
        if not es.indices.exists(index=idx):
            es.indices.create(index=idx)
            log.info(f"Created index: {idx}")
    yield

app = FastAPI(title="FalcoHive", lifespan=lifespan)

STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

class AnalyzeRequest(BaseModel):
    event_id: str = ""
    analyze_all: bool = False

class RemediateRequest(BaseModel):
    analysis_id: str
    step_index: int

class OrchestrateRequest(BaseModel):
    goal: str = "Set up the full container security lab: start all infrastructure, launch all attacks, detect them with Falco, analyze with AI, and report results."
    run_id: str = ""

@app.get("/", response_class=HTMLResponse)
async def dashboard():
    with open(os.path.join(STATIC_DIR, "index.html")) as f:
        return f.read()

@app.get("/api/events")
async def get_events():
    try:
        result = es.search(
            index="falco-events-*",
            body={"size": 50, "sort": [{"time": {"order": "desc"}}]},
        )
        events = []
        for hit in result["hits"]["hits"]:
            src = hit["_source"]
            events.append({
                "id": hit["_id"],
                "index": hit["_index"],
                "rule": src.get("rule", "unknown"),
                "priority": src.get("priority", "info"),
                "time": src.get("time", ""),
                "output": src.get("output", ""),
                "output_fields": src.get("output_fields", {}),
            })
        return {"events": events, "total": result["hits"]["total"]["value"]}
    except Exception:
        return {"events": [], "total": 0}

@app.get("/api/analyses")
async def get_analyses():
    try:
        result = es.search(
            index=ANALYSIS_INDEX,
            body={"size": 50, "sort": [{"analyzed_at": {"order": "desc"}}]},
        )
        analyses = []
        for hit in result["hits"]["hits"]:
            analyses.append({"_id": hit["_id"], "_source": hit["_source"]})
        return {"analyses": analyses, "total": result["hits"]["total"]["value"]}
    except Exception:
        return {"analyses": [], "total": 0}

@app.get("/api/remediations")
async def get_remediations():
    try:
        result = es.search(
            index=REMEDIATION_INDEX,
            body={"size": 50, "sort": [{"executed_at": {"order": "desc"}}]},
        )
        items = []
        for hit in result["hits"]["hits"]:
            items.append({"_id": hit["_id"], "_source": hit["_source"]})
        return {"remediations": items, "total": result["hits"]["total"]["value"]}
    except Exception:
        return {"remediations": [], "total": 0}

@app.post("/api/analyze")
async def analyze_event(req: AnalyzeRequest, background_tasks: BackgroundTasks):
    if req.analyze_all:
        result = es.search(
            index="falco-events-*",
            body={"size": 50, "sort": [{"time": {"order": "desc"}}]},
        )
        events = [h["_source"] for h in result["hits"]["hits"]]
        background_tasks.add_task(run_analysis_batch, events)
        return {"status": "started", "message": f"Analyzing {len(events)} events in background"}

    if req.event_id:
        try:
            result = es.get(index="falco-events-*", id=req.event_id)
            event = result["_source"]
        except:
            raise HTTPException(404, "Event not found")
    else:
        result = es.search(
            index="falco-events-*",
            body={"size": 1, "sort": [{"time": {"order": "desc"}}]},
        )
        if not result["hits"]["hits"]:
            raise HTTPException(404, "No events found")
        event = result["hits"]["hits"][0]["_source"]

    analysis = await analysis_agent.analyze(event)
    es.index(index=ANALYSIS_INDEX, document=analysis)
    return {"status": "complete", "analysis": analysis}

@app.post("/api/remediate")
async def remediate(req: RemediateRequest):
    try:
        result = es.get(index=ANALYSIS_INDEX, id=req.analysis_id)
        analysis = result["_source"]
    except:
        raise HTTPException(404, "Analysis not found")

    steps = analysis.get("remediation_steps", [])
    if req.step_index < 0 or req.step_index >= len(steps):
        raise HTTPException(400, f"Invalid step index. Valid range: 0-{len(steps)-1}")

    step = steps[req.step_index]
    log.info(f"Executing remediation step {req.step_index}: {step.get('title', step.get('command', 'unknown'))}")

    result_data = await remediation_agent.execute(step, analysis)

    remediation_record = {
        "analysis_id": req.analysis_id,
        "step_index": req.step_index,
        "step_title": step.get("title", step.get("command", "")),
        "result": result_data,
        "executed_at": datetime.now(timezone.utc).isoformat(),
    }
    es.index(index=REMEDIATION_INDEX, document=remediation_record)

    return {"status": "complete", "remediation": remediation_record}

@app.delete("/api/clear")
async def clear_all():
    orchestration_sessions.clear()
    indices_to_clear = ["falco-events-*", "falcohive-*", ANALYSIS_INDEX, REMEDIATION_INDEX, ORCHESTRATION_INDEX]
    cleared = []
    for idx in indices_to_clear:
        try:
            matching = es.indices.get(index=idx)
            for name in matching:
                es.indices.delete(index=name)
                cleared.append(name)
        except Exception as e:
            log.error(f"Failed to clear index {idx}: {e}")
    log.info(f"Cleared {len(cleared)} indices: {cleared}")
    return {"status": "cleared", "indices": cleared}

@app.post("/api/orchestrate")
async def start_orchestration(req: OrchestrateRequest, background_tasks: BackgroundTasks):
    session_id = req.run_id or str(uuid.uuid4())[:8]
    session = {
        "id": session_id,
        "status": "running",
        "phase": "initializing",
        "goal": req.goal,
        "logs": [],
        "started_at": datetime.now(timezone.utc).isoformat(),
        "completed_at": None,
        "results": {},
    }
    orchestration_sessions[session_id] = session
    log.info(f"Starting orchestration session {session_id}: {req.goal[:100]}")

    background_tasks.add_task(run_orchestration_pipeline, session)
    return {"session_id": session_id, "status": "started"}

@app.get("/api/orchestrate/sessions")
async def list_sessions():
    active = {k: {"id": v["id"], "status": v["status"], "phase": v["phase"], "started_at": v["started_at"]}
              for k, v in orchestration_sessions.items()}
    return {"sessions": list(active.values())}

@app.get("/api/orchestrate/{session_id}")
async def get_orchestration_status(session_id: str):
    session = orchestration_sessions.get(session_id)
    if not session:
        raise HTTPException(404, f"Session {session_id} not found")
    return {
        "session_id": session_id,
        "status": session["status"],
        "phase": session["phase"],
        "goal": session["goal"],
        "logs": session["logs"][-100:],
        "started_at": session["started_at"],
        "completed_at": session["completed_at"],
        "results": {k: v.get("summary", str(v)[:200]) if isinstance(v, dict) else str(v)[:200]
                     for k, v in session.get("results", {}).items()},
    }

async def run_analysis_batch(events):
    log.info(f"Analyzing batch of {len(events)} events")
    sem = asyncio.Semaphore(5)

    async def analyze_one(event):
        async with sem:
            try:
                analysis = await analysis_agent.analyze(event)
                es.index(index=ANALYSIS_INDEX, document=analysis)
                log.info(f"Analyzed event: {event.get('rule', 'unknown')}")
            except Exception as e:
                log.error(f"Failed to analyze event: {e}")

    tasks = [analyze_one(e) for e in events]
    await asyncio.gather(*tasks)
    log.info("Batch analysis complete")

async def run_orchestration_pipeline(session: dict):
    session_id = session["id"]

    async def on_event(event_type: str, agent: str, data: str):
        entry = {
            "type": event_type,
            "agent": agent,
            "data": data,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        session["logs"].append(entry)
        if event_type == "phase":
            session["phase"] = data
        elif event_type == "error":
            log.error(f"[{session_id}] {agent}: {data}")
        elif event_type == "tool_end":
            log.info(f"[{session_id}] {agent} completed: {data[:100]}")

        try:
            es.index(index=ORCHESTRATION_INDEX, document={
                "session_id": session_id,
                "event_type": event_type,
                "agent": agent,
                "data": data,
                "goal": session["goal"],
                "timestamp": entry["timestamp"],
            })
        except Exception:
            pass

    try:
        await on_event("phase", "orchestrator", "Setting up infrastructure...")
        result = await orchestrator_agent.run(session["goal"], on_event)
        session["status"] = result.get("status", "complete")
        session["results"] = result.get("results", {})
        session["phase"] = result.get("phase", "complete")
    except Exception as e:
        log.error(f"Orchestration pipeline failed: {e}")
        await on_event("error", "system", f"Pipeline failed: {e}")
        session["status"] = "failed"
        session["phase"] = "error"

    session["completed_at"] = datetime.now(timezone.utc).isoformat()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=3000)
