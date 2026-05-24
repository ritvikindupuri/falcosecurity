import os
import subprocess
import logging
import tempfile

log = logging.getLogger(__name__)

BPF_PROG = """
#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <bpf/bpf_helpers.h>

SEC("kprobe/sys_execve")
int kprobe_exec(struct pt_regs *ctx) {
    char comm[16] = {};
    bpf_get_current_comm(&comm, sizeof(comm));
    bpf_printk("exec from: %s\\n", comm);
    return 0;
}

char _license[] SEC("license") = "GPL";
"""

def run():
    log.info("EBPF ROOTKIT LOAD ATTEMPT")
    log.info("Scenario: Loading an eBPF program to hook syscalls (keylogger/rootkit behavior)")
    log.info("Relevance: Real rootkits use eBPF for stealth. BPF in containers is a major security concern.")

    if os.geteuid() != 0:
        log.info("Not root — some features will be simulated.")
    else:
        log.info("Running as root — attempting real BPF operations.")

    try:
        has_bpftool = subprocess.run("which bpftool", shell=True, capture_output=True).returncode == 0
        if has_bpftool:
            log.info("bpftool found. Attempting to load BPF program...")
            try:
                result = subprocess.run(
                    "bpftool prog load /tmp/bpf_rootkit.o /sys/fs/bpf/rootkit 2>&1",
                    shell=True, capture_output=True, text=True, timeout=5
                )
                log.info(f"bpftool load: {result.stdout[:200]} {result.stderr[:200]}")
            except subprocess.TimeoutExpired:
                log.info("bpftool timeout (expected)")

        result = subprocess.run(
            "python3 -c \"import ctypes; libc = ctypes.CDLL('libc.so.6', use_errno=True); ret = libc.syscall(321, 0, 0, 0, 0, 0, 0); print(f'bpf syscall returned: {ret}')\" 2>&1",
            shell=True, capture_output=True, text=True, timeout=5
        )
        log.info(f"BPF syscall via python: {result.stdout.strip()[:200]} {result.stderr.strip()[:200]}")

    except Exception as e:
        log.error(f"Python BPF attempt failed: {e}")

    bpf_payload = """
import ctypes, os
try:
    libc = ctypes.CDLL('libc.so.6', use_errno=True)
    bpf_cmd = 0
    bpf_attr = ctypes.create_string_buffer(64)
    ret = libc.syscall(321, bpf_cmd, ctypes.addressof(bpf_attr), 64)
    os.write(1, f'BPF prog load: {ret} (errno: {ctypes.get_errno()})\\n'.encode())
except Exception as e:
    os.write(1, str(e).encode() + b'\\n')
"""
    subprocess.run(["python3", "-c", bpf_payload], timeout=5)

    probes = [
        (321, "bpf"),
        (296, "bpf_prog_load"),
        (297, "bpf_raw_tracepoint_open"),
    ]
    for sysno, name in probes:
        cmd = f"python3 -c \"import os; os.syscall({sysno}, 0, 0, 0)\" 2>&1 || true"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=3)
        log.info(f"{name} syscall ({sysno}): {result.stdout.strip()[:100]}")

    subprocess.run("bpftool prog list 2>/dev/null || echo 'No bpftool'", shell=True)
    subprocess.run("ls -la /sys/fs/bpf/ 2>/dev/null || echo 'No /sys/fs/bpf'", shell=True)

    log.info("BPF rootkit simulation complete. Falco should have detected BPF program load attempts.")
