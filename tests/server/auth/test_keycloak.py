import time
from types import SimpleNamespace
from urllib.parse import parse_qs, urlparse

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from flask import Flask

from mlflow.server import auth
from mlflow.server.auth import keycloak


@pytest.fixture(autouse=True)
def keycloak_config(monkeypatch):
    monkeypatch.setenv("MLFLOW_KEYCLOAK_ISSUER", "https://keycloak.example/realms/mlflow")
    monkeypatch.setenv("MLFLOW_KEYCLOAK_PUBLIC_URL", "https://mlflow.example")
    monkeypatch.setenv("MLFLOW_KEYCLOAK_CLIENT_ID", "mlflow")
    monkeypatch.setenv("MLFLOW_KEYCLOAK_CLIENT_SECRET", "test-secret")
    monkeypatch.setenv("MLFLOW_KEYCLOAK_ADMIN_ROLE", "client:super-admin")
    monkeypatch.setenv(
        "MLFLOW_KEYCLOAK_ROLE_MAP",
        '{"group:/science":"keycloak:reader",'
        '"realm:editor":{"workspace":"team","role":"keycloak:editor"}}',
    )
    keycloak.get_config.cache_clear()
    yield
    keycloak.get_config.cache_clear()


def test_config_rejects_insecure_public_url(monkeypatch):
    monkeypatch.setenv("MLFLOW_KEYCLOAK_PUBLIC_URL", "http://mlflow.example")
    keycloak.get_config.cache_clear()
    with pytest.raises(ValueError, match="HTTPS"):
        keycloak.get_config()


def test_id_token_checks_signature_issuer_audience_and_nonce(monkeypatch):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    def jwks_client():
        return SimpleNamespace(
            get_signing_key_from_jwt=lambda token: SimpleNamespace(key=private_key.public_key())
        )

    monkeypatch.setattr(keycloak, "_jwks_client", jwks_client)
    claims = {
        "sub": "subject",
        "iss": "https://keycloak.example/realms/mlflow",
        "aud": "mlflow",
        "iat": int(time.time()),
        "exp": int(time.time()) + 300,
        "nonce": "expected",
    }
    token = jwt.encode(claims, private_key, algorithm="RS256")
    assert keycloak._verify(token, nonce="expected")["sub"] == "subject"
    with pytest.raises(jwt.InvalidTokenError):
        keycloak._verify(token, nonce="wrong")
    with pytest.raises(jwt.InvalidAudienceError):
        keycloak._verify(jwt.encode({**claims, "aud": "other"}, private_key, algorithm="RS256"))
    with pytest.raises(jwt.InvalidIssuerError):
        keycloak._verify(
            jwt.encode({**claims, "iss": "https://wrong.example"}, private_key, algorithm="RS256")
        )


def test_login_uses_pkce_state_and_nonce(monkeypatch):
    monkeypatch.setattr(
        keycloak,
        "_metadata",
        lambda: {
            "authorization_endpoint": (
                "https://keycloak.example/realms/mlflow/protocol/openid-connect/auth"
            )
        },
    )
    app = Flask(__name__)
    app.secret_key = "test-secret"
    app.add_url_rule(keycloak.LOGIN_PATH, view_func=keycloak.login)

    with app.test_client() as client:
        response = client.get(keycloak.LOGIN_PATH)
        query = parse_qs(urlparse(response.location).query)
        with client.session_transaction() as session:
            flow = session["keycloak_flow"]
        assert response.status_code == 302
        assert query["state"] == [flow["state"]]
        assert query["nonce"] == [flow["nonce"]]
        assert query["code_challenge_method"] == ["S256"]
        assert query["redirect_uri"] == ["https://mlflow.example/oauth/keycloak/callback"]
        assert "verifier" not in query


def test_callback_rejects_wrong_state_before_token_exchange(monkeypatch):
    app = Flask(__name__)
    app.secret_key = "test-secret"
    app.add_url_rule(keycloak.CALLBACK_PATH, view_func=keycloak.callback)
    with app.test_client() as client:
        with client.session_transaction() as session:
            session["keycloak_flow"] = {"state": "correct", "nonce": "n", "verifier": "v"}
        response = client.get(keycloak.CALLBACK_PATH + "?state=wrong&code=code")
        assert response.status_code == 400


def test_callback_exchanges_code_and_sets_http_only_session_cookie(monkeypatch):
    token_request = {}
    now = int(time.time())
    monkeypatch.setattr(
        keycloak,
        "_metadata",
        lambda: {
            "token_endpoint": "https://keycloak.example/realms/mlflow/protocol/openid-connect/token"
        },
    )

    def post(url, *, data, auth, timeout):
        token_request.update(url=url, data=data, auth=auth, timeout=timeout)
        return SimpleNamespace(raise_for_status=lambda: None, json=lambda: {"id_token": "id-token"})

    monkeypatch.setattr(keycloak.requests, "post", post)
    monkeypatch.setattr(
        keycloak, "_verify", lambda token, *, nonce=None: {"sub": "subject", "exp": now + 300}
    )
    monkeypatch.setattr(keycloak, "_sync_user", lambda claims: "keycloak:subject")
    monkeypatch.setattr(
        auth.store, "get_user", lambda username: SimpleNamespace(username=username)
    )
    app = Flask(__name__)
    app.secret_key = "test-secret"
    app.add_url_rule(keycloak.CALLBACK_PATH, view_func=keycloak.callback)
    app.add_url_rule("/me", view_func=lambda: keycloak.authenticate_request().username)
    with app.test_client() as client:
        with client.session_transaction() as session:
            session["keycloak_flow"] = {"state": "correct", "nonce": "n", "verifier": "v"}
        response = client.get(keycloak.CALLBACK_PATH + "?state=correct&code=code")
        current_user = client.get("/me")

    assert response.status_code == 302
    assert response.location == "https://mlflow.example/"
    assert token_request["data"]["code_verifier"] == "v"
    assert token_request["auth"] == ("mlflow", "test-secret")
    cookie = response.headers.getlist("Set-Cookie")
    assert any(
        keycloak.COOKIE_NAME in value and "HttpOnly" in value and "Secure" in value
        for value in cookie
    )
    assert current_user.get_data(as_text=True) == "keycloak:subject"


def test_keycloak_roles_reconcile_without_touching_local_roles(monkeypatch):
    user = SimpleNamespace(id=7, username="keycloak:subject", is_admin=False, display_name=None)
    reader = SimpleNamespace(id=11, workspace="default", name="keycloak:reader")
    old = SimpleNamespace(id=12, workspace="default", name="keycloak:old")
    local = SimpleNamespace(id=13, workspace="default", name="local-editor")
    editor = SimpleNamespace(id=14, workspace="team", name="keycloak:editor")
    assigned = []
    unassigned = []
    admin_updates = []
    store = SimpleNamespace(
        has_user=lambda username, **kwargs: True,
        get_user=lambda username: user,
        update_user=lambda username, **kwargs: admin_updates.append(kwargs),
        list_user_roles=lambda user_id: [reader, old, local],
        get_role_by_name=lambda workspace, name: editor,
        assign_role_to_user=lambda user_id, role_id: assigned.append(role_id),
        unassign_role_from_user=lambda user_id, role_id: unassigned.append(role_id),
    )
    monkeypatch.setattr(auth, "store", store)

    username = keycloak._sync_user({
        "sub": "subject",
        "email": "person@example.com",
        "groups": ["/science"],
        "realm_access": {"roles": ["editor"]},
        "resource_access": {"mlflow": {"roles": ["super-admin"]}},
    })

    assert username == "keycloak:subject"
    assert assigned == [14]
    assert unassigned == [12]
    assert admin_updates == [{"is_admin": True, "display_name": "person@example.com"}]


def test_keycloak_display_name_prefers_email_and_falls_back_to_username():
    assert keycloak._display_name({"email": "person@example.com", "preferred_username": "person"}) == (
        "person@example.com"
    )
    assert keycloak._display_name({"preferred_username": "person"}) == "person"
    assert keycloak._display_name({"email": " ", "preferred_username": "person"}) == "person"


def test_admin_client_role_must_belong_to_configured_client():
    assert not keycloak._is_admin({"realm_access": {"roles": ["super-admin"]}})
    assert not keycloak._is_admin({"resource_access": {"other": {"roles": ["super-admin"]}}})
    assert keycloak._is_admin({"resource_access": {"mlflow": {"roles": ["super-admin"]}}})


def test_explicit_realm_admin_role_remains_supported(monkeypatch):
    monkeypatch.setenv("MLFLOW_KEYCLOAK_ADMIN_ROLE", "realm:super-admin")
    keycloak.get_config.cache_clear()
    assert keycloak._is_admin({"realm_access": {"roles": ["super-admin"]}})


def test_client_role_claim_maps_to_mlflow_role(monkeypatch):
    monkeypatch.setenv("MLFLOW_KEYCLOAK_ROLE_MAP", '{"client:viewer":"keycloak:reader"}')
    keycloak.get_config.cache_clear()
    assert keycloak._mapped_roles({"resource_access": {"mlflow": {"roles": ["viewer"]}}}) == {
        ("default", "keycloak:reader")
    }


def test_cookie_auth_requires_same_origin_for_writes(monkeypatch):
    monkeypatch.setattr(keycloak, "_verify", lambda token: {"sub": "subject"})
    monkeypatch.setattr(auth.store, "get_user", lambda username: SimpleNamespace(username=username))
    app = Flask(__name__)
    with app.test_request_context(
        "/api/2.0/mlflow/experiments/create",
        method="POST",
        headers={
            "Cookie": f"{keycloak.COOKIE_NAME}=signed-token",
            "Origin": "https://evil.example",
        },
    ):
        assert keycloak.authenticate_request().status_code == 403
    with app.test_request_context(
        "/api/2.0/mlflow/experiments/create",
        method="POST",
        headers={
            "Cookie": f"{keycloak.COOKIE_NAME}=signed-token",
            "Origin": "https://mlflow.example",
            "Authorization": "Basic stale-browser-credentials",
        },
    ):
        assert keycloak.authenticate_request().username == "keycloak:subject"


def test_bearer_rejects_id_token(monkeypatch):
    monkeypatch.setattr(keycloak, "_verify", lambda token: {"sub": "subject"})
    app = Flask(__name__)
    with app.test_request_context(
        "/api/2.0/mlflow/experiments/search", headers={"Authorization": "Bearer id-token"}
    ):
        assert keycloak.authenticate_request().status_code == 401


def test_local_user_mutations_are_blocked_in_keycloak_mode(monkeypatch):
    monkeypatch.setattr(
        auth,
        "auth_config",
        auth.auth_config._replace(authorization_function=keycloak.AUTHORIZATION_FUNCTION),
    )
    app = Flask(__name__)
    with app.test_request_context(
        "/api/2.0/mlflow/users/create",
        method="POST",
        json={"username": "local", "password": "some-long-password"},
    ):
        assert auth.create_user().status_code == 403
    with app.test_request_context(
        "/api/2.0/mlflow/users/update-admin",
        method="PATCH",
        json={"username": "keycloak:subject", "is_admin": True},
    ):
        assert auth.update_user_admin().status_code == 403


def test_managed_role_cannot_be_assigned_through_api(monkeypatch):
    monkeypatch.setattr(
        auth,
        "auth_config",
        auth.auth_config._replace(authorization_function=keycloak.AUTHORIZATION_FUNCTION),
    )
    store = SimpleNamespace(
        get_user=lambda username: SimpleNamespace(id=1),
        get_role=lambda role_id: SimpleNamespace(name="keycloak:reader"),
    )
    monkeypatch.setattr(auth, "store", store)
    app = Flask(__name__)
    with app.test_request_context(
        "/api/3.0/mlflow/roles/assign",
        method="POST",
        json={"username": "keycloak:subject", "role_id": 2},
    ):
        assert auth.assign_role().status_code == 403
