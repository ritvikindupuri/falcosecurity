import os
import ctypes
import struct
import logging
import subprocess

log = logging.getLogger(__name__)

SYS_io_uring_setup = 425
SYS_io_uring_enter = 426
SYS_io_uring_register = 427

def syscall_io_uring_setup(entries, params):
    if hasattr(os, 'syscall'):
        try:
            ret = os.syscall(SYS_io_uring_setup, entries, params)
            return ret
        except OSError as e:
            return -e.errno
        except AttributeError:
            return -1
    return -1

def run():
    log.info("IO_URING SECCOMP BYPASS (CVE-2022-25362)")
    log.info("Scenario: Using io_uring to perform syscalls that bypass seccomp filters")
    log.info("Relevance: io_uring bypasses seccomp because operations execute in kernel context, not user context.")

    try:
        ret = subprocess.run(
            "python3 -c 'import os; print(os.syscall(425, 4, 0))' 2>&1 || echo FAIL",
            shell=True, capture_output=True, text=True
        )
        log.info(f"io_uring_setup direct syscall: {ret.stdout.strip()[:200]}")

        if ret.returncode != 0 or ret.stdout.strip() == "FAIL":
            log.info("Direct syscall not available. Using ctypes approach...")
            try:
                libc = ctypes.CDLL("libc.so.6", use_errno=True)
                if not hasattr(libc, "syscall"):
                    libc = ctypes.CDLL("libc.so.6")
            except OSError:
                libc = None

            if libc:
                try:
                    result = libc.syscall(SYS_io_uring_setup, 4, 0)
                    errno = ctypes.get_errno()
                    log.info(f"io_uring_setup via ctypes: {result} (errno: {errno})")
                except Exception as e:
                    log.info(f"ctypes io_uring failed: {e}")

        log.info("Performing seccomp bypass simulation...")

        payload = """
import ctypes, os
SYS_io_uring_setup = 425
try:
    libc = ctypes.CDLL('libc.so.6', use_errno=True)
    sq = ctypes.create_string_buffer(128)
    ret = libc.syscall(SYS_io_uring_setup, 4, ctypes.addressof(sq))
    os.write(1, f'io_uring returned: {ret}\\n'.encode())
except Exception as e:
    os.write(1, f'io_uring failed: {e} (expected without CAP_SYS_ADMIN)\\n'.encode())
"""
        subprocess.run(["python3", "-c", payload], timeout=10)

        subprocess.run("opencir 2>/dev/null || echo 'open(uring) sim'", shell=True)
        subprocess.run("echo '/dev/io_uring' > /tmp/iouring_check 2>/dev/null || true", shell=True)
        subprocess.run("cat /proc/self/maps | grep -i 'io_uring\|aio' 2>/dev/null || true", shell=True)

        log.info("io_uring attack simulation complete. Falco should have detected io_uring_setup syscall usage.")

    except Exception as e:
        log.error(f"io_uring error: {e}")
