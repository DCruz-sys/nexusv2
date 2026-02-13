import unittest

from app.routes.reports import _sanitize_report_html


class ReportSanitizationTests(unittest.TestCase):
    def test_script_tags_removed(self):
        raw = "<p>Hello</p><script>alert(1)</script><strong>World</strong>"
        cleaned = _sanitize_report_html(raw)
        self.assertIn("<p>Hello</p>", cleaned)
        self.assertIn("<strong>World</strong>", cleaned)
        self.assertNotIn("<script>", cleaned)
        self.assertNotIn("alert(1)", cleaned)
