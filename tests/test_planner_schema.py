import json
import unittest
from pathlib import Path


class PlannerSchemaTests(unittest.TestCase):
    def test_planner_schema_exists_and_has_required_keys(self):
        schema_path = Path("schemas/planner_task_graph.schema.json")
        self.assertTrue(schema_path.exists())
        payload = json.loads(schema_path.read_text(encoding="utf-8"))
        self.assertEqual(payload.get("title"), "PlannerTaskGraph")
        self.assertEqual(payload.get("type"), "object")
        self.assertIn("tasks", payload.get("properties", {}))

