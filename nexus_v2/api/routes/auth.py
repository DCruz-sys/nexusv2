"""Auth routes (v2)."""

from __future__ import annotations

import os

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from nexus_v2.api.auth import AuthPrincipal, issue_access_token, require_viewer
from nexus_v2.config import get_settings


router = APIRouter(prefix="/api/v2/auth", tags=["auth"])


class TokenRequest(BaseModel):
    username: str = Field(min_length=1, max_length=128)
    password: str = Field(min_length=0, max_length=512)


@router.post("/token")
async def issue_token(req: TokenRequest):
    settings = get_settings()
    if not settings.auth_enabled:
        return {"access_token": "auth-disabled", "token_type": "bearer"}

    admin_user = os.getenv("AUTH_ADMIN_USERNAME", "admin")
    admin_pass = os.getenv("AUTH_ADMIN_PASSWORD", "")
    if req.username != admin_user or (admin_pass and req.password != admin_pass):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    token = issue_access_token(principal_id=req.username, role="admin", scopes=["*"])
    return {"access_token": token, "token_type": "bearer"}


@router.get("/whoami")
async def whoami(principal: AuthPrincipal = Depends(require_viewer)):
    return {"id": principal.id, "role": principal.role, "scopes": principal.scopes, "auth_type": principal.auth_type}

