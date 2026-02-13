import unittest
from pathlib import Path


class FrontendAssetsTests(unittest.TestCase):
    def test_index_contains_auth_modal_and_targets_page(self):
        html = Path("app/static/index.html").read_text(encoding="utf-8")
        self.assertIn('id="auth-modal"', html)
        self.assertIn('id="page-targets"', html)
        self.assertIn('id="page-swarm-runs"', html)
        self.assertIn('id="allowlist-row"', html)

    def test_app_js_does_not_use_prompt_auth(self):
        js = Path("app/static/js/app.js").read_text(encoding="utf-8")
        self.assertNotIn("window.prompt(", js)
        self.assertIn("showAuthModal", js)
        self.assertIn("CHAT_SESSION_STORAGE_KEY", js)
        self.assertIn("restoreChatHistory", js)
