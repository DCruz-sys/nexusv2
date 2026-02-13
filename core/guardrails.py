from typing import Any, Dict

from core.telemetry import telemetry


class SecurityGuardrails:
    """Minimal guardrails: block dangerous out-of-scope actions."""

    def __init__(self, nim_provider: Any):
        self.nim = nim_provider

    async def validate_action_plan(self, action_plan: Dict[str, Any]) -> bool:
        if not action_plan.get("steps"):
            telemetry.record_guardrail_block(reason="missing_steps")
            return False
        if action_plan.get("risk_level", "low") == "critical":
            telemetry.record_guardrail_block(reason="risk_level_critical")
            return False
        return True
