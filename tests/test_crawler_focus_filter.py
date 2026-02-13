import unittest

from app.learning.crawler import _allow_domain_for_run


class CrawlerFocusFilterTests(unittest.TestCase):
    def test_allows_any_domain_when_unfocused(self):
        self.assertTrue(_allow_domain_for_run("example.com", set()))
        self.assertTrue(_allow_domain_for_run("sub.example.com", set()))

    def test_restricts_to_focus_domains(self):
        focus = {"book.hacktricks.wiki"}
        self.assertTrue(_allow_domain_for_run("book.hacktricks.wiki", focus))
        self.assertFalse(_allow_domain_for_run("owasp.org", focus))

