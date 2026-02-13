import unittest

from app.ai.model_router import model_router
from app.config import MODELS


class ModelRouterActionsTests(unittest.TestCase):
    def test_forced_model_preserves_scan_task_type(self):
        # When a user pins a model, routing should still classify actions (e.g. scan).
        forced_model = next(iter(MODELS.keys()))
        model_key, task_type = model_router.route("scan https://example.com", force_model=forced_model)
        self.assertEqual(model_key, forced_model)
        self.assertEqual(task_type, "scan")

