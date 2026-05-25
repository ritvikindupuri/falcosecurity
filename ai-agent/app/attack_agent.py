import asyncio
import logging

log = logging.getLogger("attack-agent")

IMAGE_NAME = "attacker:latest"
CONTAINER_NAME = "unique-attacker"


class AttackAgent:
    def __init__(self):
        self._last_result = None

    async def _run_docker(self, *args):
        cmd = ["docker"] + list(args)
        log.info(f"Running: {' '.join(cmd)}")
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=300)
        return {
            "returncode": proc.returncode,
            "stdout": stdout.decode().strip() if stdout else "",
            "stderr": stderr.decode().strip() if stderr else "",
        }

    async def build_attacker(self):
        log.info("Checking for existing attacker image...")
        check = await self._run_docker("image", "inspect", IMAGE_NAME)
        if check["returncode"] == 0:
            log.info(f"Image {IMAGE_NAME} already exists, skipping build")
            return {
                "summary": f"Skipped - {IMAGE_NAME} already built",
                "success": True,
                "skipped": True,
            }
        log.info(f"Image {IMAGE_NAME} not found. Build must be run from the host.")
        return {
            "summary": f"Cannot build from inside container. Run 'docker compose build' from project root on the host first.",
            "success": False,
            "skipped": False,
        }

    async def run_all(self):
        log.info("Running attacker container via docker run...")
        # Stop and remove any leftover container with the same name
        await self._run_docker("rm", "-f", CONTAINER_NAME)

        result = await self._run_docker(
            "run", "--rm", "--name", CONTAINER_NAME,
            "--privileged",
            "-v", "/var/run/docker.sock:/var/run/docker.sock",
            "--cap-add", "SYS_ADMIN",
            "--cap-add", "NET_ADMIN",
            "--cap-add", "SYS_PTRACE",
            "--cap-add", "SYS_RAWIO",
            "--cap-add", "BPF",
            "--cap-add", "SYS_MODULE",
            "--cap-add", "DAC_READ_SEARCH",
            "--network", "unique-net",
            IMAGE_NAME,
        )
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
