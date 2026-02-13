import unittest

from app.routes.chat import _normalize_scan_type


class ChatScanDefaultsTests(unittest.TestCase):
    def test_defaults_to_quick(self):
        self.assertEqual(_normalize_scan_type("scan https://example.com"), "quick")
        self.assertEqual(_normalize_scan_type("go on and scan example.com"), "quick")

    def test_explicit_full_wins(self):
        self.assertEqual(_normalize_scan_type("full scan https://example.com"), "full")

    def test_explicit_quick(self):
        self.assertEqual(_normalize_scan_type("quick scan https://example.com"), "quick")

