import json
import logging
import os
from datetime import datetime, timezone

from anthropic import AsyncAnthropic

log = logging.getLogger("orchestrator-agent")


class OrchestratorAgent:
    def __init__(self, api_key, model, infra_agent, attack_agent, monitor_agent, analysis_agent, remediation_agent):
        self.client = AsyncAnthropic(api_key=api_key) if api_key else None
        self.model = model
        self.infra = infra_agent
        self.attacker = attack_agent
        self.monitor = monitor_agent
        self.analyzer = analysis_agent
        self.remediator = remediation_agent

        self.tools = [
            {
                "name": "setup_infrastructure",
                "description": "Build and start all Docker infrastructure services (Elasticsearch, Kibana, Falco, Falcosidekick, Redis, PostgreSQL, target-app) and wait for them to be healthy. Call this first to set up the lab environment. Skips services already running.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "services": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Services to start. Empty for all services.",
                        }
                    },
                },
            },
            {
                "name": "launch_attacks",
                "description": "Build the attacker image and run all 6 security attacks (Cgroup Escape, OverlayFS Tamper, io_uring Bypass, ARP Spoof, BPF Rootkit, Userfaultfd Exploit) against the target application.",
                "input_schema": {
                    "type": "object",
                    "properties": {},
                },
            },
            {
                "name": "wait_for_falco_events",
                "description": "Poll Elasticsearch and wait for Falco security events to be detected and indexed. Use this after launching attacks to confirm detection worked.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "timeout_seconds": {
                            "type": "number",
                            "description": "Maximum time to wait in seconds (default 120)",
                        },
                        "min_events": {
                            "type": "number",
                            "description": "Minimum number of events to wait for (default 1)",
                        },
                    },
                },
            },
            {
                "name": "analyze_events",
                "description": "Run AI-powered security analysis on all Falco events. Maps each event to CVEs, MITRE ATT&CK techniques, calculates risk scores with explanations, and generates remediation steps.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "analyze_all": {
                            "type": "boolean",
                            "description": "Set to true to analyze all events",
                        }
                    },
                },
            },
            {
                "name": "execute_remediation",
                "description": "Execute a remediation step for an analyzed attack. Runs the docker command to fix the vulnerability.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "analysis_id": {
                            "type": "string",
                            "description": "ID of the analysis from analysis results",
                        },
                        "step_index": {
                            "type": "number",
                            "description": "Which remediation step to execute (0-based)",
                        },
                    },
                },
            },
            {
                "name": "check_system_status",
                "description": "Check the status of all services (running containers, Elasticsearch health, Falco events count, analyses count)",
                "input_schema": {
                    "type": "object",
                    "properties": {},
                },
            },
            {
                "name": "get_analysis_results",
                "description": "Get the current AI analysis results from Elasticsearch with CVE/MITRE mappings and risk scores",
                "input_schema": {
                    "type": "object",
                    "properties": {},
                },
            },
        ]

    async def run(self, goal: str, on_event):
        if not self.client:
            await on_event("error", "orchestrator", "No Claude API key configured")
            return {"status": "failed", "error": "No Claude API key"}

        messages = [
            {
                "role": "user",
                "content": f"""You are orchestrating a container security attack lab. Your goal:

{goal}

You have tools to set up infrastructure, launch attacks, monitor for events, analyze them with AI, and execute remediation.

Follow this workflow:
1. setup_infrastructure - start all services and wait for readiness
2. launch_attacks - run the security attack scenarios
3. wait_for_falco_events - confirm events reached Elasticsearch
4. analyze_events - run AI analysis on detected events
5. get_analysis_results - review analysis findings
6. Optionally execute_remediation to fix vulnerabilities
7. Report final status with check_system_status

Call ONE tool at a time. Wait for the result before deciding the next step. Explain what you're doing at each step.""",
            }
        ]

        session = {
            "status": "running",
            "phase": "planning",
            "logs": [],
            "started_at": datetime.now(timezone.utc).isoformat(),
            "results": {},
        }

        await on_event("phase", "orchestrator", "Starting orchestration pipeline...")

        MAX_ITERATIONS = 30
        for iteration in range(MAX_ITERATIONS):
            try:
                response = await self.client.messages.create(
                    model=self.model,
                    max_tokens=4000,
                    tools=self.tools,
                    messages=messages,
                )

                tool_called = False
                for block in response.content:
                    if block.type == "text" and block.text.strip():
                        log.info(f"Orchestrator: {block.text[:300]}")
                        await on_event("thought", "orchestrator", block.text)

                    elif block.type == "tool_use":
                        tool_called = True
                        tool_name = block.name
                        tool_input = block.input

                        log.info(f"Tool call: {tool_name}({tool_input})")
                        session["phase"] = tool_name
                        await on_event("tool_start", tool_name, json.dumps(tool_input))

                        result = await self._execute_tool(tool_name, tool_input)
                        session["results"][tool_name] = result

                        await on_event("tool_end", tool_name, json.dumps(result))

                        msg_entry = {"role": "assistant", "content": response.content}
                        messages.append(msg_entry)
                        messages.append({
                            "role": "user",
                            "content": [
                                {
                                    "type": "tool_result",
                                    "tool_use_id": block.id,
                                    "content": json.dumps(result),
                                }
                            ],
                        })
                        break

                if not tool_called:
                    final_text = ""
                    for block in response.content:
                        if block.type == "text":
                            final_text += block.text
                    await on_event("complete", "orchestrator", final_text or "Pipeline complete!")
                    session["status"] = "complete"
                    session["phase"] = "complete"
                    session["completed_at"] = datetime.now(timezone.utc).isoformat()
                    return session

            except Exception as e:
                log.error(f"Orchestrator error: {e}")
                await on_event("error", "orchestrator", str(e))
                session["status"] = "failed"
                session["phase"] = "error"
                session["error"] = str(e)
                return session

        await on_event("error", "orchestrator", "Max iterations reached")
        session["status"] = "failed"
        session["phase"] = "timeout"
        return session

    async def _execute_tool(self, name, inputs):
        try:
            if name == "setup_infrastructure":
                services = inputs.get("services") or []
                status = await self.monitor.check_system_status()
                containers_up = len([c for c in status.get("containers", []) if "Up" in c])

                build_result = {"summary": "Skipped - images pre-built by run.sh", "success": True, "skipped": True}
                log.info(f"Starting all infrastructure services ({containers_up} currently running)...")
                start_result = await self.infra.start_services(services)

                es_ready = await self.infra.wait_for_elasticsearch()
                kibana_ready = await self.infra.wait_for_kibana()
                return {
                    "summary": f"Infrastructure ready. ES: {es_ready['ready']}, Kibana: {kibana_ready['ready']}",
                    "pre_check": {"containers_running_before": containers_up},
                    "build": build_result,
                    "start": start_result,
                    "elasticsearch": es_ready,
                    "kibana": kibana_ready,
                }

            elif name == "launch_attacks":
                build_result = await self.attacker.build_attacker()
                if not build_result["success"]:
                    return build_result
                result = await self.attacker.run_all()
                return result

            elif name == "wait_for_falco_events":
                timeout = inputs.get("timeout_seconds", 120)
                min_events = inputs.get("min_events", 1)
                result = await self.monitor.wait_for_events(timeout=timeout, min_events=min_events)
                return result

            elif name == "analyze_events":
                result = await self.monitor.analyze_all_events(self.analyzer)
                return result

            elif name == "execute_remediation":
                analysis_id = inputs.get("analysis_id", "")
                step_index = inputs.get("step_index", 0)
                from elasticsearch import Elasticsearch
                es = Elasticsearch(os.getenv("ES_HOST", "http://elasticsearch:9200"))
                try:
                    doc = es.get(index="ai-attack-analysis", id=analysis_id)
                    analysis = doc["_source"]
                except Exception as e:
                    return {"error": f"Analysis not found: {e}"}
                steps = analysis.get("remediation_steps", [])
                if not steps or step_index < 0 or step_index >= len(steps):
                    return {"error": f"Invalid step index {step_index}, have {len(steps)} steps"}
                step = steps[step_index]
                result_data = await self.remediator.execute(step, analysis)
                record = {
                    "analysis_id": analysis_id,
                    "step_index": step_index,
                    "step_title": step.get("title", ""),
                    "result": result_data,
                    "executed_at": datetime.now(timezone.utc).isoformat(),
                }
                es.index(index="ai-remediation-actions", document=record)
                return {
                    "summary": f"Executed step {step_index}: {step.get('title', '')} - {'Success' if result_data.get('executed') else 'Failed'}",
                    "success": result_data.get("executed", False),
                    "details": result_data,
                }

            elif name == "check_system_status":
                result = await self.monitor.check_system_status()
                return result

            elif name == "get_analysis_results":
                result = await self.monitor.get_analysis_summary()
                return result

            return {"error": f"Unknown tool: {name}"}
        except Exception as e:
            log.error(f"Tool {name} failed: {e}")
            return {"error": str(e), "summary": f"Tool {name} failed: {str(e)[:200]}"}