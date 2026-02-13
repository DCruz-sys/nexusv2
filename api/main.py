"""Deprecated API entrypoint.

This module is kept as a temporary compatibility shim and will be removed after
one release cycle. Use `app.main:app` as the canonical runtime module.
"""

import warnings

from app.main import app

warnings.warn(
    "api.main is deprecated; run uvicorn app.main:app instead.",
    DeprecationWarning,
    stacklevel=2,
)
