import asyncio
import logging
import os

log = logging.getLogger("infra-agent")

COMPOSE_FILE = "/workspace/docker-compose.yml"
PROJECT_DIR = "/workspace"

class InfraAgent:
    def __init__(self):
        pass

    async def _run_compose(self, *args):
        cmd = ["docker", "compose", "-f", COMPOSE_FILE] + list(args)
        log.info(f"Running: {' '.join(cmd)}")
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=PROJECT_DIR,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=180)
        return {
            "returncode": proc.returncode,
            "stdout": stdout.decode().strip() if stdout else "",
            "stderr": stderr.decode().strip() if stderr else "",
        }

    async def _run_docker(self, *args):
        cmd = ["docker"] + list(args)
        log.info(f"Running: {' '.join(cmd)}")
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=60)
        return {
            "returncode": proc.returncode,
            "stdout": stdout.decode().strip() if stdout else "",
            "stderr": stderr.decode().strip() if stderr else "",
        }

    async def build_all(self):
        log.info("Building all images...")
        result = await self._run_compose("build")
        return {
            "summary": "All images built" if result["returncode"] == 0 else f"Build failed: {result['stderr'][:200]}",
            "success": result["returncode"] == 0,
            "details": result,
        }

    async def start_services(self, services=None):
        if not services or not services[0]:
            services = ["elasticsearch", "kibana", "falco", "falcosidekick", "falcosidekick-ui", "redis", "postgres", "target-app"]
        log.info(f"Starting services: {services}")
        result = await self._run_compose("up", "-d", *services)
        return {
            "summary": f"Started {len(services)} services",
            "success": result["returncode"] == 0,
            "services": services,
            "details": result,
        }

    async def stop_all(self):
        log.info("Stopping all services...")
        result = await self._run_compose("down", "--timeout", "15")
        return {
            "summary": "All services stopped",
            "success": result["returncode"] == 0,
            "details": result,
        }

    async def check_service(self, name):
        result = await self._run_docker(
            "ps", "--filter", f"name=unique-{name}", "--format", "{{.Names}}|{{.Status}}"
        )
        running = False
        status = "not found"
        if result["stdout"]:
            parts = result["stdout"].split("|")
            if len(parts) == 2:
                status = parts[1]
                running = "Up" in parts[1]
        return {"name": name, "running": running, "status": status}

    async def check_all_services(self):
        services = ["es", "kibana", "falco", "falcosidekick", "falcosidekick-ui", "redis", "postgres", "target-app", "ai-agent"]
        results = []
        for svc in services:
            status = await self.check_service(svc)
            results.append(status)
        running_count = sum(1 for r in results if r["running"])
        return {
            "summary": f"{running_count}/{len(services)} services running",
            "services": results,
        }

    async def wait_for_service(self, name, timeout=60):
        for i in range(timeout // 2):
            status = await self.check_service(name)
            if status["running"]:
                return {"ready": True, "attempts": i + 1, "service": name}
            await asyncio.sleep(2)
        return {"ready": False, "error": f"Timeout waiting for {name}"}

    async def wait_for_elasticsearch(self, timeout=120):
        log.info("Waiting for Elasticsearch...")
        for i in range(timeout // 2):
            proc = await asyncio.create_subprocess_exec(
                "curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
                "http://elasticsearch:9200/_cluster/health",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=5)
            if stdout.decode().strip() in ["200"]:
                return {"ready": True, "attempts": i + 1}
            await asyncio.sleep(2)
        return {"ready": False, "error": "Elasticsearch not ready after timeout"}

    async def wait_for_kibana(self, timeout=60):
        log.info("Waiting for Kibana...")
        for i in range(timeout // 2):
            proc = await asyncio.create_subprocess_exec(
                "curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
                "http://kibana:5601/api/status",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=5)
            if stdout.decode().strip() in ["200"]:
                return {"ready": True, "attempts": i + 1}
            await asyncio.sleep(2)
        return {"ready": False, "error": "Kibana not ready after timeout"}
