"""Local-first guardrails with optional NeMo Guardrails integration."""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from app.config import BASE_DIR, NEMO_GUARDRAILS_CONFIG_PATH, NEMO_GUARDRAILS_ENABLED

try:
    from jsonschema import ValidationError, validate  # type: ignore
except Exception:  # pragma: no cover - optional dependency
    ValidationError = Exception  # type: ignore

    def validate(*_args, **_kwargs):  # type: ignore
        return None


try:  # pragma: no cover - optional dependency
    from nemoguardrails import LLMRails, RailsConfig  # type: ignore
except Exception:  # pragma: no cover
    LLMRails = None  # type: ignore
    RailsConfig = None  # type: ignore

_PLANNER_SCHEMA_PATH = Path(BASE_DIR) / "schemas" / "planner_task_graph.schema.json"

_SENSITIVE_PATTERNS = [
    re.compile(r"(api[_-]?key\s*[:=]\s*)([A-Za-z0-9_\-]{6,})", re.IGNORECASE),
    re.compile(r"(authorization\s*:\s*bearer\s+)([A-Za-z0-9\-._~+/]+=*)", re.IGNORECASE),
    re.compile(r"(password\s*[:=]\s*)(\S+)", re.IGNORECASE),
    re.compile(r"(secret\s*[:=]\s*)(\S+)", re.IGNORECASE),
]
_POLICY_BLOCKLIST = {
    "exfiltrate credentials",
    "steal secrets",
    "disable target allowlist",
    "ignore all safety policies",
}


@dataclass
class GuardrailsStatus:
    enabled: bool
    nemo_loaded: bool
    config_path: str


class GuardrailsManager:
    """Applies policy checks for agent outputs and planner graphs."""

    def __init__(self):
        self.enabled = bool(NEMO_GUARDRAILS_ENABLED)
        self.config_path = str(NEMO_GUARDRAILS_CONFIG_PATH or "app/ai/rails")
        self.nemo_loaded = False
        self._rails = None
        if self.enabled:
            self._init_nemo()

    def _init_nemo(self):
        if not LLMRails or not RailsConfig:
            return
        cfg_dir = Path(self.config_path)
        if not cfg_dir.is_absolute():
            cfg_dir = Path(BASE_DIR) / cfg_dir
        if not cfg_dir.exists():
            return
        try:  # pragma: no cover - optional runtime
            config = RailsConfig.from_path(str(cfg_dir))
            self._rails = LLMRails(config)
            self.nemo_loaded = True
        except Exception:
            self._rails = None
            self.nemo_loaded = False

    @staticmethod
    def redact_sensitive(text: str) -> str:
        value = str(text or "")
        for pattern in _SENSITIVE_PATTERNS:
            value = pattern.sub(r"\1[REDACTED]", value)
        return value

    def enforce_output_policy(self, text: str) -> tuple[str, list[str]]:
        redacted = self.redact_sensitive(text)
        lowered = redacted.lower()
        violations = [item for item in _POLICY_BLOCKLIST if item in lowered]
        if violations:
            return (
                "Response blocked by guardrails policy due to unsafe content request.",
                violations,
            )
        return redacted, []

    def validate_planner_task_graph(self, payload: dict[str, Any]) -> tuple[bool, str]:
        if not payload:
            return False, "empty_planner_payload"
        try:
            schema = json.loads(_PLANNER_SCHEMA_PATH.read_text(encoding="utf-8"))
        except Exception as exc:
            return False, f"schema_unavailable:{exc}"
        try:
            validate(instance=payload, schema=schema)
            return True, "ok"
        except ValidationError as exc:
            return False, f"schema_validation_failed:{exc.message}"
        except Exception as exc:
            return False, f"schema_validation_error:{exc}"

    def status(self) -> GuardrailsStatus:
        return GuardrailsStatus(
            enabled=self.enabled,
            nemo_loaded=self.nemo_loaded,
            config_path=self.config_path,
        )


guardrails_manager = GuardrailsManager()
