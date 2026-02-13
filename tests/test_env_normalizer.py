import tempfile
import unittest
from pathlib import Path

from app.system.env_normalizer import normalize_env_file


class EnvNormalizerTests(unittest.TestCase):
    def test_blank_credentials_are_filled_with_admin(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            env_path = Path(tmpdir) / ".env"
            env_path.write_text(
                "\n".join(
                    [
                        "AUTH_ADMIN_PASSWORD=",
                        "AUTH_BOOTSTRAP_API_KEY=",
                        "AUTH_JWT_SECRET=already-set",
                        "MEMORY_WRITE_SECRET=",
                        "NVIDIA_API_KEY=",
                        "",
                    ]
                ),
                encoding="utf-8",
            )
            changed = normalize_env_file(env_path)
            content = env_path.read_text(encoding="utf-8")
            self.assertIn("AUTH_ADMIN_PASSWORD=admin", content)
            self.assertIn("AUTH_BOOTSTRAP_API_KEY=admin", content)
            self.assertIn("AUTH_JWT_SECRET=already-set", content)
            self.assertIn("MEMORY_WRITE_SECRET=admin", content)
            self.assertIn("NVIDIA_API_KEY=", content)
            self.assertIn("AUTH_ADMIN_PASSWORD", changed)
            self.assertIn("AUTH_BOOTSTRAP_API_KEY", changed)
            self.assertIn("MEMORY_WRITE_SECRET", changed)
            self.assertNotIn("AUTH_JWT_SECRET", changed)
