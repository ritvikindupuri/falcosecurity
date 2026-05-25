import time
import logging
import sys
import urllib.request
import json

logging.basicConfig(level=logging.INFO, format="[ATTACKER] %(asctime)s %(message)s")
log = logging.getLogger(__name__)

ATTACK_DELAY = 5

TARGET_URL = "http://unique-target:8080"


def hit_target(method, path, body=None):
    url = f"{TARGET_URL}{path}"
    try:
        data = json.dumps(body).encode() if body else None
        req = urllib.request.Request(url, data=data, method=method)
        if data:
            req.add_header("Content-Type", "application/json")
        resp = urllib.request.urlopen(req, timeout=5)
        log.info(f"[TARGET] {method} {path} -> {resp.status}")
        return json.loads(resp.read().decode())
    except Exception as e:
        log.info(f"[TARGET] {method} {path} -> ERROR: {e}")
        return None


def run_attack(module_path, name, target_endpoints, description):
    log.info(f"")
    log.info(f"{'='*70}")
    log.info(f"  ATTACK: {name}")
    log.info(f"  TARGET: {', '.join(f'{m} {p}' for m, p in target_endpoints)}")
    log.info(f"  IMPACT: {description}")
    log.info(f"{'='*70}")
    for method, path in target_endpoints:
        hit_target(method, path)
    try:
        mod = __import__(module_path, fromlist=["run"])
        log.info(f"  [EXECUTING] Running {name}...")
        mod.run()
        log.info(f"  [COMPLETE]  {name} finished")
    except Exception as e:
        log.error(f"  [FAILED]    {name} - {e}")
    for method, path in target_endpoints:
        hit_target(method, path)
    log.info(f"{'='*70}")
    log.info(f"")


def main():
    log.info("=" * 70)
    log.info("  ATTACKER CONTAINER READY")
    log.info("  Target: unique-target:8080")
    log.info("  Launching 6 attack scenarios...")
    log.info("=" * 70)
    time.sleep(10)

    attacks = [
        ("attacks.cgroup_escape",
         "Cgroup notify_on_release Escape (CVE-2022-0492)",
         [("GET", "/config")],
         "Attempts container escape via cgroup release_agent to read host files. Targets /config to steal credentials."),
        ("attacks.overlayfs_tamper",
         "OverlayFS Whiteout Tampering (CVE-2021-31433)",
         [("GET", "/internal")],
         "Creates overlayfs whiteout files to hide malicious artifacts. Targets /internal to cover tracks."),
        ("attacks.iouring_bypass",
         "io_uring Seccomp Bypass (CVE-2022-25362)",
         [("POST", "/admin")],
         "Uses io_uring syscalls to bypass seccomp filters. Targets /admin for privilege escalation."),
        ("attacks.arp_spoof",
         "ARP Cache Poisoning MITM",
         [("POST", "/login")],
         "Poisons ARP cache to intercept traffic between target-app and other services. Targets /login to capture credentials."),
        ("attacks.bpf_rootkit",
         "eBPF Rootkit Load Attempt",
         [("POST", "/api/internal")],
         "Loads eBPF programs to install a rootkit for kernel-level persistence. Targets internal API for data exfil."),
        ("attacks.userfaultfd_exploit",
         "Userfaultfd Race Condition (CVE-2022-2588)",
         [("POST", "/upload")],
         "Exploits userfaultfd syscall for a race condition to corrupt memory. Targets /upload for file manipulation."),
    ]

    for module_path, name, endpoints, desc in attacks:
        run_attack(module_path, name, endpoints, desc)
        time.sleep(ATTACK_DELAY)

    log.info("=" * 70)
    log.info("  ALL 6 ATTACKS COMPLETED")
    log.info("  Sending synthetic Falco events to Sidekick...")
    log.info("=" * 70)
    from attacks.event_generator import send_events
    send_events()

    log.info("=" * 70)
    log.info("  PIPELINE COMPLETE")
    log.info("  Check dashboard: http://localhost:3000")
    log.info("  Check Kibana:    http://localhost:5601")
    log.info("  Check Target:    http://localhost:8090 (live attack feed)")
    log.info("=" * 70)


if __name__ == "__main__":
    main()