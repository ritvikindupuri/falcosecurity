import asyncio
import logging

log = logging.getLogger("attack-agent")


class AttackAgent:
    def __init__(self):
        self._last_result = None

    async def _run_compose(self, *args):
        cmd = ["docker", "compose", "-f", "/workspace/docker-compose.yml"] + list(args)
        log.info(f"Running: {' '.join(cmd)}")
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd="/workspace",
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=300)
        return {
            "returncode": proc.returncode,
            "stdout": stdout.decode().strip() if stdout else "",
            "stderr": stderr.decode().strip() if stderr else "",
        }

    async def build_attacker(self):
        log.info("Building attacker image...")
        result = await self._run_compose("build", "attacker")
        return {
            "summary": "Attacker image built" if result["returncode"] == 0 else f"Build failed: {result['stderr'][:200]}",
            "success": result["returncode"] == 0,
        }

    async def run_all(self):
        log.info("Running attacker container...")
        result = await self._run_compose("up", "attacker")
        self._last_result = result
        lines = result["stdout"].split("\n") if result["stdout"] else []
        attack_lines = [l for l in lines if any(k in l.lower() for k in ["attack", "escape", "spoof", "rootkit", "bypass", "exploit", "tamper", "triggered", "simulated", "event"])]
        summary_lines = attack_lines[-10:] if attack_lines else lines[-5:]
        return {
            "summary": f"Attacker finished (exit: {result['returncode']}). Key events: {' | '.join(summary_lines)}",
            "success": True,
            "exit_code": result["returncode"],
            "attack_logs": summary_lines,
            "full_output": result["stdout"][-2000:],
            "stderr": result["stderr"][-500:],
        }

    async def get_last_run_logs(self):
        return self._last_result
