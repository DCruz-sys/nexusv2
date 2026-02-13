import unittest

from app.learning.crawler import _is_public_hostname, _is_public_ip


class CrawlerSafetyTests(unittest.TestCase):
    def test_private_and_loopback_ips_blocked(self):
        self.assertFalse(_is_public_ip("127.0.0.1"))
        self.assertFalse(_is_public_ip("10.0.0.5"))
        self.assertFalse(_is_public_ip("192.168.1.10"))

    def test_public_ip_allowed(self):
        self.assertTrue(_is_public_ip("1.1.1.1"))

    def test_localhost_hostname_blocked(self):
        self.assertFalse(_is_public_hostname("localhost"))
