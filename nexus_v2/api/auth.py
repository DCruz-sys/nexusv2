"""Authentication / authorization (v2)."""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Iterable

import jwt
from fastapi import Depends, Header, HTTPException, Security, WebSocket, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from nexus_v2.config import get_settings
from nexus_v2.infra.repos.api_keys import get_api_key_by_hash, hash_api_key


ROLE_ORDER = {"viewer": 10, "operator": 20, "admin": 30}
BEARER = HTTPBearer(auto_error=False)


@dataclass
class AuthPrincipal:
    id: str
    role: str
    scopes: list[str]
    auth_type: str = "token"


def _unauthorized(message: str = "Authentication required.") -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail={"code": "auth_required", "message": message, "details": {}},
        headers={"WWW-Authenticate": "Bearer"},
    )


def _forbidden(message: str = "Insufficient role for this action.") -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail={"code": "auth_forbidden", "message": message, "details": {}},
    )


def _token_payload(
    *,
    principal_id: str,
    role: str,
    scopes: Iterable[str] | None,
    ttl_minutes: int,
) -> dict:
    now = int(time.time())
    ttl = max(1, int(ttl_minutes)) * 60
    return {
        "sub": principal_id,
        "role": (role or "viewer").lower(),
        "scopes": list(scopes or []),
        "iat": now,
        "exp": now + ttl,
    }


def issue_access_token(
    *,
    principal_id: str,
    role: str,
    scopes: Iterable[str] | None = None,
    ttl_minutes: int | None = None,
) -> str:
    settings = get_settings()
    ttl = int(ttl_minutes) if ttl_minutes is not None else int(settings.auth_access_token_min)
    payload = _token_payload(principal_id=principal_id, role=role, scopes=scopes, ttl_minutes=ttl)
    return jwt.encode(payload, settings.auth_jwt_secret, algorithm=settings.auth_jwt_alg)


def _principal_from_token(token: str) -> AuthPrincipal:
    settings = get_settings()
    try:
        payload = jwt.decode(token, settings.auth_jwt_secret, algorithms=[settings.auth_jwt_alg])
    except jwt.ExpiredSignatureError as exc:
        raise _unauthorized("Access token expired.") from exc
    except jwt.PyJWTError as exc:
        raise _unauthorized("Invalid access token.") from exc

    principal_id = str(payload.get("sub") or "").strip()
    role = str(payload.get("role") or "viewer").strip().lower()
    scopes = payload.get("scopes") or []
    if not principal_id:
        raise _unauthorized("Invalid token payload.")
    if role not in ROLE_ORDER:
        role = "viewer"
    if not isinstance(scopes, list):
        scopes = []
    return AuthPrincipal(id=principal_id, role=role, scopes=[str(s) for s in scopes], auth_type="token")


async def _principal_from_api_key(api_key: str) -> AuthPrincipal:
    key_hash = hash_api_key(api_key)
    row = await get_api_key_by_hash(key_hash)
    if not row:
        raise _unauthorized("Invalid API key.")
    role = str(row.get("role") or "viewer").lower()
    if role not in ROLE_ORDER:
        role = "viewer"
    scopes = row.get("scopes") or []
    if not isinstance(scopes, list):
        scopes = []
    return AuthPrincipal(
        id=str(row.get("name") or row.get("id") or "api-key"),
        role=role,
        scopes=[str(x) for x in scopes],
        auth_type="api_key",
    )


def has_role(principal: AuthPrincipal, required_role: str) -> bool:
    current = ROLE_ORDER.get((principal.role or "viewer").lower(), 0)
    required = ROLE_ORDER.get((required_role or "viewer").lower(), 0)
    return current >= required


async def get_current_principal(
    credentials: HTTPAuthorizationCredentials | None = Security(BEARER),
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
) -> AuthPrincipal:
    settings = get_settings()
    if not settings.auth_enabled:
        return AuthPrincipal(id="auth-disabled", role="admin", scopes=["*"], auth_type="disabled")

    if credentials and credentials.scheme.lower() == "bearer" and credentials.credentials:
        return _principal_from_token(credentials.credentials)

    if x_api_key:
        return await _principal_from_api_key(x_api_key)

    raise _unauthorized()


def require_role(required_role: str):
    async def _dependency(principal: AuthPrincipal = Depends(get_current_principal)) -> AuthPrincipal:
        if not has_role(principal, required_role):
            raise _forbidden()
        return principal

    return _dependency


require_viewer = require_role("viewer")
require_operator = require_role("operator")
require_admin = require_role("admin")


async def authenticate_websocket(websocket: WebSocket, required_role: str = "viewer") -> AuthPrincipal | None:
    settings = get_settings()
    if not settings.auth_enabled:
        return AuthPrincipal(id="auth-disabled", role="admin", scopes=["*"], auth_type="disabled")

    token = websocket.query_params.get("token")
    api_key = websocket.query_params.get("api_key") or websocket.headers.get("x-api-key")
    auth_header = websocket.headers.get("authorization", "")
    if not token and auth_header.lower().startswith("bearer "):
        token = auth_header[7:].strip()

    try:
        if token:
            principal = _principal_from_token(token)
        elif api_key:
            principal = await _principal_from_api_key(api_key)
        else:
            await websocket.close(code=4401)
            return None

        if not has_role(principal, required_role):
            await websocket.close(code=4403)
            return None
        return principal
    except HTTPException:
        await websocket.close(code=4401)
        return None

