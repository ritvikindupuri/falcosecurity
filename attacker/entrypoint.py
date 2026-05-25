import time
import logging
import sys
import urllib.request
import json

logging.basicConfig(level=logging.INFO, format="[ATTACKER] %(asctime)s %(message)s")
log = logging.getLogger(__name__)

ATTACK_DELAY = 5

TARGET_URL = "http://unique-target:8080"


def hit_target(method, path, attack_context=None):
    url = f"{TARGET_URL}{path}"
    body = attack_context or {}
    use_method = "POST" if attack_context else method
    try:
        data = json.dumps(body).encode()
        req = urllib.request.Request(url, data=data, method=use_method)
        req.add_header("Content-Type", "application/json")
        resp = urllib.request.urlopen(req, timeout=5)
        log.info(f"[TARGET] {use_method} {path} -> {resp.status} ({body.get('phase', 'normal')})")
        return json.loads(resp.read().decode())
    except Exception as e:
        log.info(f"[TARGET] {use_method} {path} -> ERROR: {e} ({body.get('phase', 'normal')})")
        return None


def run_attack(module_path, name, target_endpoints, description, cve, mitre):
    cve_str = cve or "N/A"
    mitre_str = mitre or "N/A"
    log.info(f"")
    log.info(f"{'='*70}")
    log.info(f"  ATTACK: {name}")
    log.info(f"  CVE:    {cve_str}")
    log.info(f"  MITRE:  {mitre_str}")
    log.info(f"  TARGET: {', '.join(f'{m} {p}' for m, p in target_endpoints)}")
    log.info(f"  IMPACT: {description}")
    log.info(f"{'='*70}")

    for method, path in target_endpoints:
        hit_target(method, path, {
            "attack": name,
            "cve": cve_str,
            "mitre": mitre_str,
            "impact": description,
            "phase": "pre-exploit probe",
            "detail": f"Probing {path} to assess target availability and response before launching {name}"
        })

    try:
        mod = __import__(module_path, fromlist=["run"])
        log.info(f"  [EXECUTING] Running {name}...")
        hit_target("POST", target_endpoints[0][1], {
            "attack": name,
            "cve": cve_str,
            "mitre": mitre_str,
            "impact": description,
            "phase": "exploitation",
            "detail": f"Exploiting vulnerability: {description.split('.')[0]}"
        })
        mod.run()
        log.info(f"  [COMPLETE]  {name} finished")
    except Exception as e:
        log.error(f"  [FAILED]    {name} - {e}")

    for method, path in target_endpoints:
        hit_target(method, path, {
            "attack": name,
            "cve": cve_str,
            "mitre": mitre_str,
            "impact": description,
            "phase": "post-exploit verification",
            "detail": f"Verifying exploit success by re-accessing {path} — confirming data exposure/access"
        })

    log.info(f"{'='*70}")
    log.info(f"")


def reset_target():
    try:
        data = json.dumps({}).encode()
        req = urllib.request.Request(f"{TARGET_URL}/api/reset", data=data, method="POST")
        req.add_header("Content-Type", "application/json")
        resp = urllib.request.urlopen(req, timeout=5)
        log.info(f"[RESET] Target state cleared ({resp.status})")
    except Exception as e:
        log.warning(f"[RESET] Could not clear target state: {e}")


def main():
    log.info("=" * 70)
    log.info("  ATTACKER CONTAINER READY")
    log.info("  Target: unique-target:8080")
    log.info("  Launching 6 attack scenarios...")
    log.info("=" * 70)
    time.sleep(5)
    reset_target()
    time.sleep(2)

    attacks = [
        ("attacks.cgroup_escape",
         "Cgroup notify_on_release Escape (CVE-2022-0492)",
         [("GET", "/config")],
         "Escapes container via cgroup release_agent to read host filesystem. Steals database credentials and secret keys from /config.",
         "CVE-2022-0492",
         "T1611"),
        ("attacks.overlayfs_tamper",
         "OverlayFS Whiteout Tampering (CVE-2021-31433)",
         [("GET", "/internal")],
         "Creates overlayfs whiteout files (.wh.*) to hide malicious artifacts from filesystem scans. Covers tracks by accessing sensitive internal data.",
         "CVE-2021-31433",
         "T1564"),
        ("attacks.iouring_bypass",
         "io_uring Seccomp Bypass (CVE-2022-25362)",
         [("POST", "/admin")],
         "Uses io_uring syscalls to bypass seccomp filters and gain admin privileges. Escalates to admin access on the target app.",
         "CVE-2022-25362",
         "T1562"),
        ("attacks.arp_spoof",
         "ARP Cache Poisoning MITM",
         [("POST", "/login")],
         "Poisons ARP cache on the Docker bridge network to intercept traffic. Captures login credentials via MITM between target-app and other services.",
         "N/A",
         "T1557"),
        ("attacks.bpf_rootkit",
         "eBPF Rootkit Load Attempt",
         [("POST", "/api/internal")],
         "Loads malicious eBPF programs to hook syscalls for kernel-level persistence. Exfiltrates internal API data while hiding from detection.",
         "N/A",
         "T1562"),
        ("attacks.userfaultfd_exploit",
         "Userfaultfd Race Condition (CVE-2022-2588)",
         [("POST", "/upload")],
         "Exploits userfaultfd syscall to create a race condition in memory management. Corrupts file upload handling to overwrite application files.",
         "CVE-2022-2588",
         "T1574"),
    ]

    for module_path, name, endpoints, desc, cve, mitre in attacks:
        run_attack(module_path, name, endpoints, desc, cve, mitre)
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