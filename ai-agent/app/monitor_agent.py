import asyncio
import logging
import os
from datetime import datetime, timezone
from elasticsearch import Elasticsearch

log = logging.getLogger("monitor-agent")


class MonitorAgent:
    def __init__(self, es_host=None):
        self.es = Elasticsearch(es_host or os.getenv("ES_HOST", "http://elasticsearch:9200"))
        self.analysis_index = "ai-attack-analysis"
        self.remediation_index = "ai-remediation-actions"

    async def check_elasticsearch(self):
        try:
            health = self.es.cluster.health()
            return {
                "status": health.get("status", "unknown"),
                "nodes": health.get("number_of_nodes", 0),
                "indices": health.get("active_primary_shards", 0),
            }
        except Exception as e:
            return {"status": "unreachable", "error": str(e)}

    async def get_falco_events(self, size=50):
        try:
            result = self.es.search(
                index="falco-events-*",
                body={"size": size, "sort": [{"time": {"order": "desc"}}]},
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
                })
            return {
                "total": result["hits"]["total"]["value"],
                "events": events,
            }
        except Exception as e:
            return {"error": str(e), "total": 0, "events": []}

    async def wait_for_events(self, timeout=120, min_events=1):
        log.info(f"Waiting for at least {min_events} Falco events (timeout: {timeout}s)...")
        polls = []
        for i in range(timeout // 3):
            result = await self.get_falco_events(size=50)
            polls.append({"attempt": i + 1, "total": result.get("total", 0)})
            if not result.get("error") and result["total"] >= min_events:
                return {
                    "ready": True,
                    "total_events": result["total"],
                    "attempts": i + 1,
                    "polls": polls,
                    "events_summary": [e["rule"] for e in result["events"][:10]],
                }
            await asyncio.sleep(3)
        result = await self.get_falco_events(size=50)
        return {
            "ready": False,
            "total_events": result.get("total", 0),
            "attempts": len(polls),
            "polls": polls,
            "error": f"Only {result.get('total', 0)} events found after timeout",
            "events_summary": [e["rule"] for e in result.get("events", [])[:5]],
        }

    async def _analyze_single_event(self, event_data, analyzer, sem):
        async with sem:
            try:
                analysis = await analyzer.analyze({
                    "rule": event_data["rule"],
                    "priority": event_data["priority"],
                    "time": event_data["time"],
                    "output": event_data["output"],
                    "output_fields": {},
                })
                self.es.index(index=self.analysis_index, document=analysis)
                return {
                    "success": True,
                    "rule": event_data["rule"],
                    "risk_score": analysis.get("risk_score", 0),
                    "attack_name": analysis.get("attack_name", ""),
                }
            except Exception as e:
                log.error(f"Analysis failed for event {event_data.get('id', 'unknown')}: {e}")
                return {
                    "success": False,
                    "rule": event_data.get("rule", "unknown"),
                    "error": str(e),
                }

    async def analyze_all_events(self, analyzer):
        events_result = await self.get_falco_events(size=50)
        if events_result.get("error") or events_result["total"] == 0:
            return {"error": "No events to analyze", "analyzed": 0}
        events = events_result["events"]
        sem = asyncio.Semaphore(5)
        tasks = [self._analyze_single_event(e, analyzer, sem) for e in events]
        results = await asyncio.gather(*tasks)
        analyzed_count = sum(1 for r in results if r.get("success"))
        analysis_summaries = [r for r in results if r.get("success")]
        errors = [r for r in results if not r.get("success")]
        return {
            "analyzed": analyzed_count,
            "total_events": events_result["total"],
            "summaries": analysis_summaries,
            "errors": errors,
            "summary": f"Analyzed {analyzed_count}/{events_result['total']} events (with {len(errors)} errors)",
        }

    async def get_analysis_summary(self):
        try:
            result = self.es.search(
                index=self.analysis_index,
                body={"size": 50, "sort": [{"analyzed_at": {"order": "desc"}}]},
            )
            analyses = []
            for hit in result["hits"]["hits"]:
                s = hit["_source"]
                analyses.append({
                    "id": hit["_id"],
                    "attack_name": s.get("attack_name", ""),
                    "risk_score": s.get("risk_score", 0),
                    "cve": s.get("cve_mapping", []),
                    "mitre": s.get("mitre_attack", []),
                })
            return {
                "total": result["hits"]["total"]["value"],
                "analyses": analyses,
                "summary": f"{len(analyses)} analyses completed",
            }
        except Exception as e:
            return {"error": str(e), "total": 0, "analyses": []}

    async def check_system_status(self):
        es_status = await self.check_elasticsearch()
        events = await self.get_falco_events(size=5)
        analyses = await self.get_analysis_summary()

        try:
            proc = await asyncio.create_subprocess_exec(
                "docker", "ps", "--format", "{{.Names}} ({{.Status}})",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
            containers = stdout.decode().strip().split("\n") if stdout else []
        except Exception as e:
            containers = [f"Error: {e}"]

        return {
            "elasticsearch": es_status,
            "containers": containers,
            "falco_events": events.get("total", 0),
            "analyses": analyses.get("total", 0),
        }