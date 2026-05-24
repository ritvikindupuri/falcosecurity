import asyncio
import logging
import json

from anthropic import AsyncAnthropic

log = logging.getLogger("remediation-agent")

REMEDIATION_PROMPT = """You are a remediation execution AI. You will be given a remediation step and the context of a security attack. Execute the remediation by providing the exact commands needed.

## Attack Context
{attack_context}

## Remediation Step
Title: {step_title}
Command: {step_command}
Description: {step_description}

## Requirements
Return a JSON object with these exact keys:
1. "executed": boolean - whether the command was successfully executed
2. "output": string - what the command output would be (simulate if needed)
3. "effectiveness": string - "high", "medium", or "low" - how effective this remediation is
4. "notes": string - any additional notes about this remediation step

Return ONLY valid JSON, no markdown, no other text."""


class RemediationAgent:
    def __init__(self, api_key: str, model: str = "claude-sonnet-4-20250514"):
        self.client = AsyncAnthropic(api_key=api_key) if api_key else None
        self.model = model
        if not api_key:
            log.warning("No Claude API key provided. Remediation will use command execution only.")

    async def execute(self, step: dict, analysis: dict) -> dict:
        title = step.get("title", "Unknown")
        command = step.get("command", "")
        description = step.get("description", "")

        attack_name = analysis.get("attack_name", "Unknown")
        attack_context = json.dumps(analysis.get("original_event", {}), indent=2)

        if self.client:
            try:
                prompt = REMEDIATION_PROMPT.format(
                    attack_context=attack_context,
                    step_title=title,
                    step_command=command,
                    step_description=description,
                )
                response = await self.client.messages.create(
                    model=self.model,
                    max_tokens=1000,
                    temperature=0.1,
                    messages=[{"role": "user", "content": prompt}],
                )
                text = response.content[0].text.strip()
                text = text.strip("`").strip()
                if text.startswith("json"):
                    text = text[4:].strip()
                result = json.loads(text)
            except Exception as e:
                log.error(f"Claude remediation analysis failed: {e}")
                result = await self._execute_command(command, title)
        else:
            result = await self._execute_command(command, title)

        result["title"] = title
        result["command"] = command
        return result

    async def _execute_command(self, command: str, title: str) -> dict:
        if not command or command.startswith("echo"):
            return {
                "executed": False,
                "output": "No actionable command provided",
                "effectiveness": "low",
                "notes": "This step requires manual intervention or is informational only",
            }

        if command.startswith("docker"):
            try:
                proc = await asyncio.create_subprocess_shell(
                    command,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=15)
                output = stdout.decode().strip() if stdout else ""
                error = stderr.decode().strip() if stderr else ""
                combined = output + ("\n" + error if error else "")

                return {
                    "executed": proc.returncode == 0,
                    "output": combined if combined else "Command completed with no output",
                    "effectiveness": "high" if proc.returncode == 0 else "low",
                    "notes": f"Exit code: {proc.returncode}" if proc.returncode != 0 else "Command executed successfully",
                }
            except asyncio.TimeoutError:
                return {
                    "executed": False,
                    "output": "Command timed out after 15 seconds",
                    "effectiveness": "low",
                    "notes": "Timeout - command may have hung",
                }
            except Exception as e:
                return {
                    "executed": False,
                    "output": f"Execution error: {e}",
                    "effectiveness": "low",
                    "notes": f"Failed to execute: {e}",
                }
        else:
            return {
                "executed": False,
                "output": f"Command type not supported for direct execution: {command[:100]}",
                "effectiveness": "medium",
                "notes": "This command requires manual execution or elevated privileges",
            }
