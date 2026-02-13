from typing import Any, Dict


class SecurityGuardrails:
    """Minimal guardrails: block dangerous out-of-scope actions."""

    def __init__(self, nim_provider: Any):
        self.nim = nim_provider

    async def validate_action_plan(self, action_plan: Dict[str, Any]) -> bool:
        if not action_plan.get("steps"):
            return False
        if action_plan.get("risk_level", "low") == "critical":
            return False
        return True
