"""FastAPI integration: router endpoints, guards and cookie sessions."""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from conftest import make_container
from pyauthkit import AuthConfig
from pyauthkit.fastapi import build_auth_router, get_current_user, install

PASSWORD = "abcd1234"


class Client:
    """TestClient plus its container, so tests can read emitted one-time codes."""

    def __init__(self, config: AuthConfig) -> None:
        self.container = make_container(config)
        app = FastAPI()
        install(app, self.container)
        app.include_router(build_auth_router(self.container))

        @app.get("/me")
        async def me(user: Annotated[dict[str, Any], Depends(get_current_user)]) -> dict[str, str]:
            return {"sub": str(user["sub"])}

        self.http = TestClient(app)

    def register_and_verify(self, email: str = "user@example.com") -> None:
        created = self.http.post("/auth/register", json={"email": email, "password": PASSWORD, "displayName": "User"})
        assert created.status_code == 201
        code = self.container.email_sender.last_code()
        verified = self.http.post("/auth/verify-email", json={"email": email, "code": code, "password": PASSWORD})
        assert verified.status_code == 200

    def login(self, email: str = "user@example.com") -> dict[str, Any]:
        response = self.http.post("/auth/login", json={"email": email, "password": PASSWORD})
        assert response.status_code == 200, response.text
        return response.json()


def test_register_returns_verification_shape(config: AuthConfig) -> None:
    client = Client(config)
    response = client.http.post(
        "/auth/register", json={"email": "user@example.com", "password": PASSWORD, "displayName": "User"}
    )
    assert response.status_code == 201
    body = response.json()
    assert body["verificationRequired"] is True
    assert body["nextStep"] == "verify-email"
    assert body["email"] != "user@example.com"


def test_login_after_verification_returns_tokens(config: AuthConfig) -> None:
    client = Client(config)
    client.register_and_verify()
    body = client.login()
    assert body["accessToken"]
    assert body["refreshToken"]
    assert body["user"]["email"] == "user@example.com"


def test_login_before_verification_is_403(config: AuthConfig) -> None:
    client = Client(config)
    client.http.post("/auth/register", json={"email": "user@example.com", "password": PASSWORD, "displayName": "User"})
    response = client.http.post("/auth/login", json={"email": "user@example.com", "password": PASSWORD})
    assert response.status_code == 403


def test_wrong_password_is_401(config: AuthConfig) -> None:
    client = Client(config)
    client.register_and_verify()
    response = client.http.post("/auth/login", json={"email": "user@example.com", "password": "wrong9999"})
    assert response.status_code == 401


def test_lockout_returns_429(config: AuthConfig) -> None:
    locked_config = AuthConfig(**{**config.__dict__, "max_failed_attempts": 2})
    client = Client(locked_config)
    client.register_and_verify()
    assert (
        client.http.post("/auth/login", json={"email": "user@example.com", "password": "wrong9999"}).status_code == 401
    )
    assert (
        client.http.post("/auth/login", json={"email": "user@example.com", "password": "wrong9999"}).status_code == 401
    )
    assert client.http.post("/auth/login", json={"email": "user@example.com", "password": PASSWORD}).status_code == 429


def test_protected_route_requires_token(config: AuthConfig) -> None:
    client = Client(config)
    client.register_and_verify()
    assert client.http.get("/me").status_code == 401

    token = client.login()["accessToken"]
    authorized = client.http.get("/me", headers={"Authorization": f"Bearer {token}"})
    assert authorized.status_code == 200
    assert authorized.json()["sub"]


def test_cookie_session_sets_cookie_and_hides_refresh_token(config: AuthConfig) -> None:
    client = Client(config)
    client.register_and_verify()
    headers = {"X-Session-Mode": "cookie", "Origin": "http://testserver"}

    login = client.http.post("/auth/login", json={"email": "user@example.com", "password": PASSWORD}, headers=headers)
    assert login.status_code == 200
    body = login.json()
    assert body["accessToken"]
    assert "refreshToken" not in body
    assert client.container.config.refresh_cookie_name in login.cookies

    logout = client.http.post("/auth/logout", headers=headers)
    assert logout.status_code == 200


def test_cookie_session_from_untrusted_origin_is_403(config: AuthConfig) -> None:
    client = Client(config)
    response = client.http.post(
        "/auth/login",
        json={"email": "user@example.com", "password": PASSWORD},
        headers={"X-Session-Mode": "cookie", "Origin": "http://evil.example"},
    )
    assert response.status_code == 403


def test_refresh_endpoint_rotates(config: AuthConfig) -> None:
    client = Client(config)
    client.register_and_verify()
    refresh_token = client.login()["refreshToken"]

    response = client.http.post("/auth/refresh", json={"refreshToken": refresh_token})
    assert response.status_code == 200
    assert response.json()["refreshToken"] != refresh_token

    replay = client.http.post("/auth/refresh", json={"refreshToken": refresh_token})
    assert replay.status_code == 401
