"""Keycloak OpenID Connect authentication for the MLflow RBAC app.

Configure this module through the environment variables documented in
``docs/docs/self-hosting/security/keycloak-sso.mdx``. Only the authorization
code callback provisions users; API bearer tokens must name an existing user.
"""

from __future__ import annotations

import base64
import functools
import hashlib
import json
import os
import secrets
import time
from dataclasses import dataclass
from urllib.parse import urlencode, urlparse

import jwt
import requests
from flask import Response, jsonify, make_response, redirect, request, session
from werkzeug.datastructures import Authorization

from mlflow import MlflowException
from mlflow.server.auth.routes import HOME
from mlflow.utils.workspace_utils import DEFAULT_WORKSPACE_NAME

AUTHORIZATION_FUNCTION = "mlflow.server.auth.keycloak:authenticate_request"
COOKIE_NAME = "mlflow-keycloak-id-token"
LOGIN_PATH = "/oauth/keycloak/login"
CALLBACK_PATH = "/oauth/keycloak/callback"
LOGOUT_PATH = "/oauth/keycloak/logout"
_TIMEOUT = 5


@dataclass(frozen=True)
class KeycloakConfig:
    issuer: str
    client_id: str
    client_secret: str
    public_url: str
    role_map: dict[str, tuple[str, str]]
    admin_role: str | None


@functools.lru_cache(maxsize=1)
def get_config() -> KeycloakConfig:
    def required(name: str) -> str:
        value = os.environ.get(name, "").strip()
        if not value:
            raise ValueError(f"{name} must be set for Keycloak SSO")
        return value

    issuer = required("MLFLOW_KEYCLOAK_ISSUER").rstrip("/")
    public_url = required("MLFLOW_KEYCLOAK_PUBLIC_URL").rstrip("/")
    for name, value in (("issuer", issuer), ("public URL", public_url)):
        parsed = urlparse(value)
        if parsed.scheme != "https" and not (
            parsed.scheme == "http" and parsed.hostname in {"localhost", "127.0.0.1"}
        ):
            raise ValueError(f"Keycloak {name} must use HTTPS (HTTP is allowed on localhost)")
        if not parsed.netloc or parsed.query or parsed.fragment or parsed.username:
            raise ValueError(f"Invalid Keycloak {name}: {value}")
    raw_role_map = json.loads(os.environ.get("MLFLOW_KEYCLOAK_ROLE_MAP", "{}"))
    if not isinstance(raw_role_map, dict):
        raise ValueError("MLFLOW_KEYCLOAK_ROLE_MAP must be a JSON object")
    role_map = {}
    for source, target in raw_role_map.items():
        if isinstance(target, str):
            target = {"workspace": DEFAULT_WORKSPACE_NAME, "role": target}
        if not (
            isinstance(source, str)
            and source.startswith(("realm:", "client:", "group:"))
            and isinstance(target, dict)
            and isinstance(target.get("workspace"), str)
            and target["workspace"]
            and isinstance(target.get("role"), str)
            and target["role"].startswith("keycloak:")
        ):
            raise ValueError("Invalid MLFLOW_KEYCLOAK_ROLE_MAP entry")
        role_map[source] = (target["workspace"], target["role"])
    return KeycloakConfig(
        issuer=issuer,
        client_id=required("MLFLOW_KEYCLOAK_CLIENT_ID"),
        client_secret=required("MLFLOW_KEYCLOAK_CLIENT_SECRET"),
        public_url=public_url,
        role_map=role_map,
        admin_role=os.environ.get("MLFLOW_KEYCLOAK_ADMIN_ROLE") or None,
    )


@functools.lru_cache(maxsize=1)
def _metadata() -> dict:
    config = get_config()
    res = requests.get(f"{config.issuer}/.well-known/openid-configuration", timeout=_TIMEOUT)
    res.raise_for_status()
    metadata = res.json()
    if not isinstance(metadata, dict):
        raise ValueError("Invalid Keycloak discovery document")
    if metadata.get("issuer") != config.issuer:
        raise ValueError("Keycloak discovery issuer does not match configuration")
    for key in ("authorization_endpoint", "token_endpoint", "jwks_uri", "end_session_endpoint"):
        endpoint = metadata.get(key, "")
        if not endpoint.startswith(config.issuer + "/"):
            raise ValueError(f"Invalid Keycloak {key}")
    return metadata


@functools.lru_cache(maxsize=1)
def _jwks_client() -> jwt.PyJWKClient:
    return jwt.PyJWKClient(
        _metadata()["jwks_uri"], cache_jwk_set=True, lifespan=300, timeout=_TIMEOUT
    )


def _verify(token: str, *, nonce: str | None = None) -> dict:
    config = get_config()
    key = _jwks_client().get_signing_key_from_jwt(token).key
    claims = jwt.decode(
        token,
        key,
        algorithms=["RS256"],
        audience=config.client_id,
        issuer=config.issuer,
        options={"require": ["exp", "iat", "iss", "sub", "aud"]},
        leeway=30,
    )
    if claims.get("typ") != "Bearer" and claims.get("azp", config.client_id) != config.client_id:
        raise jwt.InvalidTokenError("Invalid OIDC authorized party")
    if nonce is not None and not secrets.compare_digest(str(claims.get("nonce", "")), nonce):
        raise jwt.InvalidTokenError("Invalid OIDC nonce")
    return claims


def _url(path: str) -> str:
    return get_config().public_url + path


def _cookie_path() -> str:
    return urlparse(get_config().public_url).path or "/"


def _realm_roles(claims: dict) -> set[str]:
    realm_access = claims.get("realm_access")
    roles = realm_access.get("roles", []) if isinstance(realm_access, dict) else []
    if isinstance(roles, list) and all(isinstance(role, str) for role in roles):
        return set(roles)
    return set()


def _client_roles(claims: dict) -> set[str]:
    resource_access = claims.get("resource_access")
    if not isinstance(resource_access, dict):
        return set()
    client_access = resource_access.get(get_config().client_id)
    roles = client_access.get("roles", []) if isinstance(client_access, dict) else []
    if isinstance(roles, list) and all(isinstance(role, str) for role in roles):
        return set(roles)
    return set()


def _is_admin(claims: dict) -> bool:
    role = get_config().admin_role
    if not role:
        return False
    if role.startswith("client:"):
        return role.removeprefix("client:") in _client_roles(claims)
    # Preserve existing realm-role configuration without a prefix.
    return role.removeprefix("realm:") in _realm_roles(claims)


def _mapped_roles(claims: dict) -> set[tuple[str, str]]:
    config = get_config()
    groups = claims.get("groups", [])
    group_names = set()
    if isinstance(groups, list) and all(isinstance(group, str) for group in groups):
        group_names = set(groups)
    sources = (
        {f"realm:{role}" for role in _realm_roles(claims)}
        | {f"client:{role}" for role in _client_roles(claims)}
        | {f"group:{group}" for group in group_names}
    )
    return {config.role_map[source] for source in sources if source in config.role_map}


def _username(claims: dict) -> str:
    # Stable Keycloak subject, namespaced to prevent collision with local users.
    subject = claims["sub"]
    if not isinstance(subject, str) or not subject or len(subject) > 240:
        raise ValueError("Invalid Keycloak subject")
    return f"keycloak:{subject}"


def _display_name(claims: dict) -> str | None:
    for claim in ("email", "preferred_username"):
        value = claims.get(claim)
        if isinstance(value, str) and (value := value.strip()) and len(value) <= 255:
            return value
    return None


def _sync_user(claims: dict) -> str:
    from mlflow.server import auth

    username = _username(claims)
    if not auth.store.has_user(username, use_primary=True):
        try:
            auth.store.create_user(username, secrets.token_urlsafe(32))
        except MlflowException:
            # Another worker may have created the same user during this callback.
            if not auth.store.has_user(username, use_primary=True):
                raise
    user = auth.store.get_user(username)
    is_admin = _is_admin(claims)
    display_name = _display_name(claims)
    desired = _mapped_roles(claims)
    existing = {
        (role.workspace, role.name): role
        for role in auth.store.list_user_roles(user.id)
        if role.name.startswith("keycloak:")
    }
    updates = {}
    if user.is_admin != is_admin:
        updates["is_admin"] = is_admin
    if display_name is not None and user.display_name != display_name:
        updates["display_name"] = display_name
    if updates:
        auth.store.update_user(username, **updates)
    for key in existing.keys() - desired:
        auth.store.unassign_role_from_user(user.id, existing[key].id)
    for workspace, name in desired - existing.keys():
        role = auth.store.get_role_by_name(workspace, name)
        auth.store.assign_role_to_user(user.id, role.id)
    return username


def _cookie_auth_response() -> Response:
    return make_response(jsonify({"error": "Login with Keycloak is required"}), 401)


def authenticate_request() -> Authorization | Response:
    from mlflow.server import auth

    token = None
    authorization = request.headers.get("Authorization", "")
    using_bearer = authorization.startswith("Bearer ")
    if using_bearer:
        token = authorization[7:]
    elif not authorization or authorization.startswith("Basic "):
        token = request.cookies.get(COOKIE_NAME)
        if token and request.method not in {"GET", "HEAD", "OPTIONS"}:
            # Cookie authentication is ambient; require same-origin browser writes.
            origin = request.headers.get("Origin", "")
            expected = urlparse(get_config().public_url)
            if origin != f"{expected.scheme}://{expected.netloc}":
                return make_response("Invalid request origin", 403)
    if not token:
        return _cookie_auth_response()
    try:
        claims = _verify(token)
        if using_bearer and claims.get("typ") != "Bearer":
            raise jwt.InvalidTokenError("A Keycloak access token is required")
        if not using_bearer and claims.get("typ") == "Bearer":
            raise jwt.InvalidTokenError("A Keycloak ID token is required")
        username = _username(claims)
        auth.store.get_user(username)
    except (jwt.PyJWTError, ValueError, MlflowException):
        return _cookie_auth_response()
    return Authorization("basic", data={"username": username, "password": ""})


def login():
    config = get_config()
    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32)
    verifier = secrets.token_urlsafe(64)
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    )
    session["keycloak_flow"] = {"state": state, "nonce": nonce, "verifier": verifier}
    params = {
        "client_id": config.client_id,
        "redirect_uri": _url(CALLBACK_PATH),
        "response_type": "code",
        "scope": "openid profile email",
        "state": state,
        "nonce": nonce,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }
    return redirect(_metadata()["authorization_endpoint"] + "?" + urlencode(params))


def callback():
    flow = session.pop("keycloak_flow", None)
    if not flow or not request.args.get("state") or not secrets.compare_digest(
        request.args["state"], flow["state"]
    ):
        return make_response("Invalid login state", 400)
    if not (code := request.args.get("code")):
        return make_response("Keycloak login failed", 400)
    config = get_config()
    try:
        res = requests.post(
            _metadata()["token_endpoint"],
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": _url(CALLBACK_PATH),
                "code_verifier": flow["verifier"],
            },
            auth=(config.client_id, config.client_secret),
            timeout=_TIMEOUT,
        )
        res.raise_for_status()
        id_token = res.json()["id_token"]
        claims = _verify(id_token, nonce=flow["nonce"])
        _sync_user(claims)
    except (
        requests.RequestException,
        KeyError,
        TypeError,
        ValueError,
        jwt.PyJWTError,
        MlflowException,
    ):
        return make_response("Keycloak login could not be completed", 401)
    response = redirect(_url(HOME))
    response.set_cookie(
        COOKIE_NAME,
        id_token,
        httponly=True,
        secure=urlparse(config.public_url).scheme == "https",
        samesite="Lax",
        path=_cookie_path(),
        max_age=max(0, min(int(claims["exp"] - time.time()), 3600)),
    )
    return response


def logout():
    token = request.cookies.get(COOKIE_NAME)
    params = {"client_id": get_config().client_id, "post_logout_redirect_uri": _url(HOME)}
    if token:
        try:
            _verify(token)
            params["id_token_hint"] = token
        except (jwt.PyJWTError, ValueError):
            pass
    try:
        destination = _metadata()["end_session_endpoint"] + "?" + urlencode(params)
    except (requests.RequestException, ValueError):
        destination = _url(HOME)
    response = redirect(destination)
    response.delete_cookie(COOKIE_NAME, path=_cookie_path())
    return response
