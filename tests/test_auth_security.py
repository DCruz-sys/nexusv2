import unittest

from app.security.auth import _principal_from_token, has_role, hash_api_key, issue_access_token


class AuthSecurityTests(unittest.TestCase):
    def test_token_roundtrip(self):
        token = issue_access_token("alice", "operator", scopes=["scan:run"], ttl_minutes=5)
        principal = _principal_from_token(token)
        self.assertEqual(principal.id, "alice")
        self.assertEqual(principal.role, "operator")
        self.assertTrue("scan:run" in principal.scopes)

    def test_role_hierarchy(self):
        token = issue_access_token("admin1", "admin", scopes=["*"], ttl_minutes=5)
        principal = _principal_from_token(token)
        self.assertTrue(has_role(principal, "viewer"))
        self.assertTrue(has_role(principal, "operator"))
        self.assertTrue(has_role(principal, "admin"))

    def test_api_key_hash_is_deterministic(self):
        self.assertEqual(hash_api_key("abc"), hash_api_key("abc"))
        self.assertNotEqual(hash_api_key("abc"), hash_api_key("xyz"))
