import unittest

from app.engine.executor import build_command, validate_command


class ExecutorValidationTests(unittest.TestCase):
    def test_build_command_normalizes_host_only_tools(self):
        cmd = build_command("nmap", "http://scanme.nmap.org/")
        self.assertIn("scanme.nmap.org", cmd)
        self.assertNotIn("http://", cmd)

    def test_blocks_dangerous_pattern(self):
        ok, reason = validate_command("nmap 10.0.0.1 && rm -rf /")
        self.assertFalse(ok)
        self.assertIn("blocked", reason)

    def test_blocks_shell_control_tokens(self):
        ok, _ = validate_command("nmap 10.0.0.1 | grep 80")
        self.assertFalse(ok)

    def test_blocks_non_allowlisted_binary(self):
        ok, _ = validate_command("python3 -c 'print(1)'")
        self.assertFalse(ok)
