import json
import logging
from datetime import datetime, timezone

from anthropic import AsyncAnthropic

log = logging.getLogger("analysis-agent")

ANALYSIS_PROMPT = """You are a cybersecurity analysis AI. Analyze this Falco security alert and provide structured output.

## Falco Alert
Rule: {rule}
Priority: {priority}
Time: {time}
Output: {output}
Output Fields: {output_fields}

## Requirements
Return a JSON object with these exact keys:
1. "attack_name": Short name of the attack
2. "description": What the attack does in simple terms
3. "cve_mapping": List of relevant CVE IDs (e.g., ["CVE-2022-0492"]) or empty list if none
4. "mitre_attack": List of MITRE ATT&CK technique IDs (e.g., ["T1611", "T1204"]) or empty list
5. "affected_infrastructure": What infrastructure this affects (e.g., ["container runtime", "host OS", "network", "seccomp"])
6. "risk_score": Integer 1-10 (10=most severe)
7. "risk_explanation": Why this score was assigned
8. "remediation_steps": List of objects, each with "title" (short), "command" (shell command to fix), and "description" (explanation). Commands should use docker exec targeting container names.
   IMPORTANT: All remediation commands should use this format:
   - For container fixes: use `docker <action>` commands
   - For network fixes: use `iptables` or `docker network` commands
   - For system fixes: explain what to do on the host

Return ONLY valid JSON, no markdown, no other text."""


class AnalysisAgent:
    def __init__(self, api_key: str, model: str = "claude-sonnet-4-20250514"):
        self.client = AsyncAnthropic(api_key=api_key) if api_key else None
        self.model = model
        if not api_key:
            log.warning("No Claude API key provided. Analysis will use rule-based fallback.")

    async def analyze(self, event: dict) -> dict:
        rule = event.get("rule", "Unknown")
        priority = event.get("priority", "info")
        time_val = event.get("time", "")
        output = event.get("output", "")
        output_fields = event.get("output_fields", {})

        if self.client:
            try:
                prompt = ANALYSIS_PROMPT.format(
                    rule=rule,
                    priority=priority,
                    time=time_val,
                    output=output,
                    output_fields=json.dumps(output_fields, indent=2),
                )
                response = await self.client.messages.create(
                    model=self.model,
                    max_tokens=2000,
                    temperature=0.1,
                    messages=[{"role": "user", "content": prompt}],
                )
                text = response.content[0].text.strip()
                text = text.strip("`").strip()
                if text.startswith("json"):
                    text = text[4:].strip()
                analysis = json.loads(text)
            except Exception as e:
                log.error(f"Claude analysis failed: {e}")
                analysis = self._fallback_analysis(rule, priority, output)
        else:
            analysis = self._fallback_analysis(rule, priority, output)

        analysis["original_event"] = {
            "rule": rule,
            "priority": priority,
            "time": time_val,
            "output": output,
            "output_fields": output_fields,
        }
        analysis["analyzed_at"] = datetime.now(timezone.utc).isoformat()
        return analysis

    def _fallback_analysis(self, rule: str, priority: str, output: str) -> dict:
        cve_map = {
            "Cgroup Release Agent": ["CVE-2022-0492"],
            "Overlay Whiteout": ["CVE-2021-31433"],
            "io_uring": ["CVE-2022-25362"],
            "Userfaultfd": ["CVE-2022-2588"],
            "ARP Cache Poisoning": [],
            "BPF Program Load": [],
            "Symlink Swap": [],
            "User Namespace Clone": [],
            "proc/self/mem": [],
        }
        mitre_map = {
            "Cgroup Release Agent": ["T1611"],
            "Overlay Whiteout": ["T1564"],
            "io_uring": ["T1562"],
            "Userfaultfd": ["T1574"],
            "ARP Cache Poisoning": ["T1557"],
            "BPF Program Load": ["T1562"],
            "Symlink Swap": ["T1574"],
            "User Namespace Clone": ["T1611"],
            "proc/self/mem": ["T1055"],
        }
        risk_map = {
            "Critical": 9,
            "Alert": 7,
            "Error": 5,
            "Warning": 4,
            "Notice": 3,
            "Info": 1,
        }

        matched_key = None
        for key in cve_map:
            if key.lower() in rule.lower():
                matched_key = key
                break

        base_risk = risk_map.get(priority, 5)
        return {
            "attack_name": rule,
            "description": output,
            "cve_mapping": cve_map.get(matched_key, []),
            "mitre_attack": mitre_map.get(matched_key, []),
            "affected_infrastructure": ["container"],
            "risk_score": base_risk,
            "risk_explanation": f"Priority '{priority}' maps to risk score {base_risk}/10. See remediation steps below.",
            "remediation_steps": self._get_remediation_steps(matched_key or rule),
        }

    def _get_remediation_steps(self, attack: str) -> list:
        steps = {
            "Cgroup Release Agent": [
                {"title": "Verify cgroup noexec mount", "command": "docker exec unique-attacker mount | grep cgroup", "description": "Check if cgroup filesystems are mounted with noexec"},
                {"title": "Remove cgroup release_agent", "command": "docker exec unique-attacker sh -c 'echo \"\" > /sys/fs/cgroup/release_agent 2>/dev/null || true'", "description": "Clear the release agent to prevent escape"},
            ],
            "Overlay Whiteout": [
                {"title": "Scan for whiteout files", "command": "docker exec unique-attacker find / -name '.wh.*' 2>/dev/null", "description": "Find hidden overlayfs whiteout files"},
                {"title": "Remove malicious whiteout files", "command": "docker exec unique-attacker sh -c 'find /tmp/upper -name \".wh.*\" -delete 2>/dev/null; echo \"done\"'", "description": "Remove discovered whiteout files"},
            ],
            "io_uring": [
                {"title": "Check io_uring kernel config", "command": "docker exec unique-attacker sh -c 'cat /proc/sys/kernel/io_uring_disabled 2>/dev/null || echo \"not available\"'", "description": "Verify io_uring is disabled at kernel level"},
                {"title": "Restrict io_uring via seccomp", "command": "echo 'To restrict io_uring: add \"seccomp=unconfined\" to container run args or use a custom seccomp profile that blocks io_uring syscalls'", "description": "Apply seccomp profile blocking io_uring"},
            ],
            "ARP Cache Poisoning": [
                {"title": "Check ARP table", "command": "docker exec unique-attacker arp -a", "description": "View current ARP table for suspicious entries"},
                {"title": "Flush ARP cache", "command": "docker exec unique-attacker sh -c 'ip neigh flush all 2>/dev/null || arp -d 172.21.0.1 2>/dev/null || true'", "description": "Clear poisoned ARP cache entries"},
                {"title": "Enable ARP spoofing protection", "command": "docker exec unique-attacker sh -c 'echo 1 > /proc/sys/net/ipv4/conf/all/arp_ignore 2>/dev/null; echo 2 > /proc/sys/net/ipv4/conf/all/arp_announce 2>/dev/null'", "description": "Harden ARP settings on the container"},
            ],
            "BPF Program Load": [
                {"title": "Check BPF restrictions", "command": "docker exec unique-attacker sh -c 'cat /proc/sys/kernel/unprivileged_bpf_disabled 2>/dev/null || echo \"not available\"'", "description": "Verify BPF is restricted"},
                {"title": "Lock down BPF", "command": "docker exec unique-attacker sh -c 'echo 1 > /proc/sys/kernel/unprivileged_bpf_disabled 2>/dev/null; echo 1 > /proc/sys/net/core/bpf_jit_enable 2>/dev/null'", "description": "Disable unprivileged BPF and enable JIT"},
            ],
            "Userfaultfd": [
                {"title": "Check userfaultfd availability", "command": "docker exec unique-attacker sh -c 'ls -la /dev/userfaultfd 2>/dev/null || echo \"not present\"'", "description": "Verify userfaultfd device exists"},
                {"title": "Restrict userfaultfd", "command": "docker exec unique-attacker sh -c 'echo 0 > /proc/sys/vm/unprivileged_userfaultfd 2>/dev/null || true'", "description": "Disable unprivileged userfaultfd"},
            ],
            "Symlink Swap": [
                {"title": "Find suspicious symlinks", "command": "docker exec unique-attacker find /tmp -type l -ls 2>/dev/null", "description": "Find suspicious symlinks in temp directories"},
            ],
            "User Namespace Clone": [
                {"title": "Check namespace config", "command": "docker exec unique-attacker sh -c 'cat /proc/sys/user/max_user_namespaces 2>/dev/null || echo \"not available\"'", "description": "Check user namespace limits"},
                {"title": "Restrict user namespaces", "command": "docker exec unique-attacker sh -c 'echo 0 > /proc/sys/user/max_user_namespaces 2>/dev/null || true'", "description": "Disable user namespaces"},
            ],
            "proc/self/mem": [
                {"title": "Check ptrace scope", "command": "docker exec unique-attacker sh -c 'cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null || echo \"not available\"'", "description": "Check ptrace restrictions"},
                {"title": "Enable ptrace hardening", "command": "docker exec unique-attacker sh -c 'echo 1 > /proc/sys/kernel/yama/ptrace_scope 2>/dev/null || true'", "description": "Restrict ptrace to prevent /proc/self/mem injection"},
            ],
        }
        for key in steps:
            if key.lower() in attack.lower():
                return steps[key]
        return [{"title": "Investigate alert", "command": f"docker logs unique-falco 2>&1 | grep '{attack}'", "description": "Check Falco logs for details on this alert"}]
