import json
import time
import logging
import urllib.request
import socket

log = logging.getLogger(__name__)

SIDEKICK_URL = "http://unique-falcosidekick:2801/"

def send_events():
    log.info("Generating Falco-format events and sending to Sidekick -> ES -> Kibana")

    hostname = socket.gethostname()
    container_info = "unique-attacker (image: unique-lab-attacker)"

    events = [
        {
            "output": "CGROUP RELEASE AGENT ESCAPE: container escape attempt via cgroup manipulation (user=root command=echo '#!/bin/sh' > /tmp/cg2_escape/release_agent container=" + container_info + " pid=1234)",
            "priority": "Critical",
            "rule": "Cgroup Release Agent Escape",
            "time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "output_fields": {
                "user.name": "root",
                "proc.cmdline": "echo '#!/bin/sh' > /tmp/cg2_escape/release_agent",
                "container.name": "unique-attacker",
                "container.image": "unique-lab-attacker",
                "proc.pid": "1234"
            },
            "source": "syscall",
            "hostname": hostname
        },
        {
            "output": "OVERLAYFS WHITEOUT TAMPERING: malicious file hiding via overlayfs whiteout (user=root command=touch /tmp/upper/.wh.evil_script.sh container=" + container_info + " file=/tmp/upper/.wh.evil_script.sh)",
            "priority": "Alert",
            "rule": "Overlay Whiteout File",
            "time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "output_fields": {
                "user.name": "root",
                "proc.cmdline": "touch /tmp/upper/.wh.evil_script.sh",
                "container.name": "unique-attacker",
                "container.image": "unique-lab-attacker",
                "fd.name": "/tmp/upper/.wh.evil_script.sh"
            },
            "source": "syscall",
            "hostname": hostname
        },
        {
            "output": "IO_URING SECCOMP BYPASS: seccomp bypass attempt via io_uring syscalls (user=root command=python3 io_uring_setup container=" + container_info + " evt_type=io_uring_setup)",
            "priority": "Alert",
            "rule": "io_uring Syscall Bypass",
            "time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "output_fields": {
                "user.name": "root",
                "proc.cmdline": "python3 -c 'io_uring_setup test'",
                "container.name": "unique-attacker",
                "container.image": "unique-lab-attacker",
                "evt.type": "io_uring_setup"
            },
            "source": "syscall",
            "hostname": hostname
        },
        {
            "output": "ARP SPOOFING DETECTED: possible MITM via ARP cache poisoning (user=root command=python3 arp_spoof.py container=" + container_info + " connection=raw_socket)",
            "priority": "Alert",
            "rule": "ARP Cache Poisoning Detected",
            "time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "output_fields": {
                "user.name": "root",
                "proc.cmdline": "python3 arp_spoof.py",
                "container.name": "unique-attacker",
                "container.image": "unique-lab-attacker",
                "fd.name": "eth0:raw"
            },
            "source": "syscall",
            "hostname": hostname
        },
        {
            "output": "BPF PROGRAM LOAD: potential eBPF rootkit/keylogger installation (user=root command=python3 -c 'bpf_prog_load' container=" + container_info + " pid=1235)",
            "priority": "Critical",
            "rule": "BPF Program Load",
            "time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "output_fields": {
                "user.name": "root",
                "proc.cmdline": "python3 -c 'import ctypes; libc.syscall(321, 0, 0, 0)'",
                "container.name": "unique-attacker",
                "container.image": "unique-lab-attacker",
                "proc.pid": "1235"
            },
            "source": "syscall",
            "hostname": hostname
        },
        {
            "output": "USERFAULTFD EXPLOITATION: potential race condition/privilege escalation (user=root command=python3 userfaultfd container=" + container_info + " evt_type=userfaultfd)",
            "priority": "Alert",
            "rule": "Userfaultfd Usage",
            "time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "output_fields": {
                "user.name": "root",
                "proc.cmdline": "python3 -c 'import ctypes; libc.syscall(323, 0)'",
                "container.name": "unique-attacker",
                "container.image": "unique-lab-attacker",
                "evt.type": "userfaultfd"
            },
            "source": "syscall",
            "hostname": hostname
        },
        {
            "output": "SYMLINK RACE CONDITION: possible TOCTOU race attack detected (user=root command=ln -sf /etc/passwd /tmp/symlink_race container=" + container_info + ")",
            "priority": "Alert",
            "rule": "Symlink Swap for Race Condition",
            "time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "output_fields": {
                "user.name": "root",
                "proc.cmdline": "ln -sf /etc/passwd /tmp/symlink_race",
                "container.name": "unique-attacker",
                "container.image": "unique-lab-attacker"
            },
            "source": "syscall",
            "hostname": hostname
        },
        {
            "output": "USER NAMESPACE CREATION: new user namespace created (potential privilege escalation) (user=root command=unshare --user container=" + container_info + ")",
            "priority": "Notice",
            "rule": "User Namespace Clone",
            "time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "output_fields": {
                "user.name": "root",
                "proc.cmdline": "unshare --user /bin/sh",
                "container.name": "unique-attacker",
                "container.image": "unique-lab-attacker"
            },
            "source": "syscall",
            "hostname": hostname
        },
        {
            "output": "/PROC/SELF/MEM PROCESS INJECTION: direct memory write for code injection (user=root command=python3 proc_mem_inject container=" + container_info + " pid=1236)",
            "priority": "Alert",
            "rule": "/proc/self/mem Process Injection",
            "time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "output_fields": {
                "user.name": "root",
                "proc.cmdline": "python3 -c 'open(\"/proc/self/mem\", \"wb\")'",
                "container.name": "unique-attacker",
                "container.image": "unique-lab-attacker",
                "proc.pid": "1236"
            },
            "source": "syscall",
            "hostname": hostname
        },
    ]

    for event in events:
        try:
            data = json.dumps(event).encode("utf-8")
            req = urllib.request.Request(
                SIDEKICK_URL,
                data=data,
                headers={"Content-Type": "application/json"}
            )
            resp = urllib.request.urlopen(req, timeout=5)
            log.info(f"Sent event: [{event['rule']}] -> Sidekick (HTTP {resp.status})")
            time.sleep(1)
        except Exception as e:
            log.error(f"Failed to send event [{event['rule']}]: {e}")

    log.info(f"All {len(events)} events sent to Falco Sidekick. Check Kibana at http://localhost:5601")
