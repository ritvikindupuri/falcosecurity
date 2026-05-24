import time
import logging
import sys

logging.basicConfig(level=logging.INFO, format="[ATTACKER] %(asctime)s %(message)s")
log = logging.getLogger(__name__)

ATTACK_DELAY = 5

def run_attack(module_path, name):
    log.info(f"=== STAGING: {name} ===")
    try:
        mod = __import__(module_path, fromlist=["run"])
        log.info(f"--- EXECUTING: {name} ---")
        mod.run()
        log.info(f"=== COMPLETED: {name} ===")
    except Exception as e:
        log.error(f"=== FAILED: {name} - {e} ===")

def main():
    log.info("Attacker container ready. Launching unique attack scenarios...")
    time.sleep(10)

    attacks = [
        ("attacks.cgroup_escape",       "Cgroup notify_on_release Escape (CVE-2022-0492)"),
        ("attacks.overlayfs_tamper",    "OverlayFS Whiteout Tampering (CVE-2021-31433)"),
        ("attacks.iouring_bypass",      "io_uring Seccomp Bypass (CVE-2022-25362)"),
        ("attacks.arp_spoof",           "ARP Cache Poisoning MITM"),
        ("attacks.bpf_rootkit",         "eBPF Rootkit Load Attempt"),
        ("attacks.userfaultfd_exploit", "Userfaultfd Race Condition (CVE-2022-2588)"),
    ]

    for module_path, name in attacks:
        run_attack(module_path, name)
        time.sleep(ATTACK_DELAY)

    log.info("All attacks completed. Now sending Falco-format events to Sidekick...")
    from attacks.event_generator import send_events
    send_events()

    log.info("Pipeline complete. Check Kibana (http://localhost:5601) for Falco alerts.")

if __name__ == "__main__":
    main()
