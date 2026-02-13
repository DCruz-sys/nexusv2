import unittest

from app.ai.guardrails import guardrails_manager


class GuardrailsTests(unittest.TestCase):
    def test_redacts_sensitive_tokens(self):
        raw = "password=supersecret Authorization: Bearer abc.def.ghi api_key=XYZ12345"
        cleaned = guardrails_manager.redact_sensitive(raw)
        self.assertIn("password=[REDACTED]", cleaned)
        self.assertIn("Authorization: Bearer [REDACTED]", cleaned)
        self.assertIn("api_key=[REDACTED]", cleaned)

    def test_planner_schema_validation(self):
        payload = {
            "run_id": "run-12345678",
            "created_at": "2026-02-12T00:00:00+00:00",
            "tasks": [
                {
                    "task_id": "t1",
                    "agent_role": "coordinator",
                    "objective": "Plan a scoped assessment",
                    "dependencies": [],
                    "risk_level": "low",
                    "timeout_sec": 30,
                    "retry_policy": {"max_attempts": 1, "backoff_sec": 0},
                    "allowed_tools": ["nmap"],
                    "hitl_required": False,
                    "success_criteria": ["plan generated"],
                    "output_contract": {"format": "json", "fields": ["phases"]},
                }
            ],
        }
        ok, reason = guardrails_manager.validate_planner_task_graph(payload)
        self.assertTrue(ok, reason)

        bad = {"run_id": "x", "created_at": "2026-02-12T00:00:00+00:00", "tasks": []}
        ok, reason = guardrails_manager.validate_planner_task_graph(bad)
        self.assertFalse(ok)
        self.assertIn("schema", reason)
