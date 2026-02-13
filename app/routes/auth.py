"""Authentication and API key management routes."""
from __future__ import annotations

import secrets
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from app.config import (
    AUTH_ACCESS_TOKEN_MIN,
    AUTH_ADMIN_PASSWORD,
    AUTH_ADMIN_USERNAME,
    AUTH_ENABLED,
)
from app.database import list_api_keys, revoke_api_key, upsert_api_key
from app.security.auth import AuthPrincipal, issue_access_token, require_admin, require_viewer

router = APIRouter(tags=["auth"])


class TokenRequest(BaseModel):
    username: str = Field(min_length=1, max_length=128)
    password: str = Field(min_length=1, max_length=256)


class RotateKeyRequest(BaseModel):
    name: str = Field(default="rotated-admin-key", min_length=3, max_length=128)
    role: str = Field(default="operator")
    scopes: list[str] = Field(default_factory=list)
    revoke_existing_name: Optional[str] = None


@router.post("/auth/token")
async def api_issue_token(req: TokenRequest):
    if not AUTH_ENABLED:
        raise HTTPException(
            status_code=409,
            detail={"code": "auth_disabled", "message": "Authentication is disabled.", "details": {}},
        )
    if not AUTH_ADMIN_PASSWORD:
        raise HTTPException(
            status_code=503,
            detail={
                "code": "auth_not_bootstrapped",
                "message": "Admin password is not configured.",
                "details": {"env": "AUTH_ADMIN_PASSWORD"},
            },
        )
    if req.username != AUTH_ADMIN_USERNAME or req.password != AUTH_ADMIN_PASSWORD:
        raise HTTPException(
            status_code=401,
            detail={"code": "invalid_credentials", "message": "Invalid username or password.", "details": {}},
        )

    token = issue_access_token(
        principal_id=req.username,
        role="admin",
        scopes=["*"],
        ttl_minutes=AUTH_ACCESS_TOKEN_MIN,
    )
    return {
        "access_token": token,
        "token_type": "bearer",
        "expires_in_seconds": max(60, AUTH_ACCESS_TOKEN_MIN * 60),
        "role": "admin",
    }


@router.get("/auth/me")
async def api_me(principal: AuthPrincipal = Depends(require_viewer)):
    return {
        "id": principal.id,
        "role": principal.role,
        "scopes": principal.scopes,
        "auth_type": principal.auth_type,
    }


@router.post("/auth/rotate-key")
async def api_rotate_key(req: RotateKeyRequest, _principal: AuthPrincipal = Depends(require_admin)):
    role = (req.role or "operator").strip().lower()
    if role not in {"viewer", "operator", "admin"}:
        raise HTTPException(
            status_code=400,
            detail={"code": "invalid_role", "message": "Role must be viewer|operator|admin.", "details": {}},
        )

    plaintext_key = f"nexus_{secrets.token_urlsafe(36)}"
    row_id = await upsert_api_key(name=req.name, plaintext_key=plaintext_key, role=role, scopes=req.scopes)
    revoked = 0
    if req.revoke_existing_name:
        revoked = await revoke_api_key(req.revoke_existing_name)

    return {
        "id": row_id,
        "name": req.name,
        "role": role,
        "api_key": plaintext_key,
        "revoked_entries": revoked,
    }


@router.get("/auth/keys")
async def api_list_keys(_principal: AuthPrincipal = Depends(require_admin)):
    keys = await list_api_keys(limit=500)
    return {"keys": keys}
