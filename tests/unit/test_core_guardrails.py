import asyncio

from core.guardrails import SecurityGuardrails


class DummyNIM:
    pass


def test_validate_action_plan_blocks_empty_steps_and_critical_risk():
    guardrails = SecurityGuardrails(DummyNIM())

    assert asyncio.run(guardrails.validate_action_plan({"steps": []})) is False
    assert asyncio.run(guardrails.validate_action_plan({"steps": ["a"], "risk_level": "critical"})) is False
    assert asyncio.run(guardrails.validate_action_plan({"steps": ["a"], "risk_level": "low"})) is True
