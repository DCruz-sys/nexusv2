import unittest

from app.security.allowlist import parse_target, target_matches_rule


class AllowlistMatchingTests(unittest.TestCase):
    def test_domain_rule_matches_subdomain(self):
        target = parse_target("https://api.example.com/login")
        rule = {"type": "domain", "pattern": "example.com"}
        self.assertTrue(target_matches_rule(target, rule))

    def test_ip_rule_matches_exact(self):
        target = parse_target("10.10.10.5")
        rule = {"type": "ip", "pattern": "10.10.10.5"}
        self.assertTrue(target_matches_rule(target, rule))

    def test_cidr_rule_matches_range(self):
        target = parse_target("10.10.10.45")
        rule = {"type": "cidr", "pattern": "10.10.10.0/24"}
        self.assertTrue(target_matches_rule(target, rule))

    def test_domain_rule_does_not_match_other_domain(self):
        target = parse_target("evil.com")
        rule = {"type": "domain", "pattern": "example.com"}
        self.assertFalse(target_matches_rule(target, rule))

