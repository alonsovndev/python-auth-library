"""End-to-end service flows: register, verify, login, refresh, logout, reset."""

from __future__ import annotations

from dataclasses import dataclass

import jwt
import pytest

from pyauthkit import (
    AuthContainer,
    LoginRequest,
    RegisterRequest,
    ResendRequest,
    ResetPasswordRequest,
    VerifyEmailRequest,
)
from pyauthkit.errors import EmailNotVerifiedError, InvalidCredentialsError
from pyauthkit.services.login import LoginService
from pyauthkit.services.logout import LogoutService
from pyauthkit.services.password_reset import (
    ConfirmPasswordResetService,
    RequestPasswordResetService,
    ResendResetCodeService,
)
from pyauthkit.services.refresh import RefreshTokenService
from pyauthkit.services.register import RegisterService
from pyauthkit.services.verification import ResendVerificationService, VerifyEmailService

PASSWORD = "abcd1234"


@dataclass
class Flows:
    register: RegisterService
    verify: VerifyEmailService
    resend: ResendVerificationService
    login: LoginService
    refresh: RefreshTokenService
    logout: LogoutService
    request_reset: RequestPasswordResetService
    resend_reset: ResendResetCodeService
    confirm_reset: ConfirmPasswordResetService


def build_flows(container: AuthContainer) -> Flows:
    return Flows(
        register=RegisterService(
            container.users,
            container.verification_codes,
            container.email_sender,
            container.email_links,
            container.password_hasher,
            container.password_policy,
            container.registration_builder,
            container.config,
        ),
        verify=VerifyEmailService(
            container.users,
            container.verification_codes,
            container.password_hasher,
            container.password_policy,
            container.config,
            container.on_email_verified,
        ),
        resend=ResendVerificationService(
            container.users,
            container.verification_codes,
            container.email_sender,
            container.email_links,
            container.password_hasher,
            container.config,
        ),
        login=LoginService(
            container.users, container.token_service, container.password_hasher, container.lockout_service
        ),
        refresh=RefreshTokenService(container.users, container.token_service, container.revocation_service),
        logout=LogoutService(container.token_service, container.revocation_service),
        request_reset=RequestPasswordResetService(
            container.users,
            container.reset_codes,
            container.email_sender,
            container.email_links,
            container.password_hasher,
            container.config,
        ),
        resend_reset=ResendResetCodeService(
            container.users,
            container.reset_codes,
            container.email_sender,
            container.email_links,
            container.password_hasher,
            container.config,
        ),
        confirm_reset=ConfirmPasswordResetService(
            container.users,
            container.reset_codes,
            container.password_hasher,
            container.password_policy,
            container.config,
        ),
    )


@pytest.fixture
def flows(container: AuthContainer) -> Flows:
    return build_flows(container)


async def register_and_verify(container: AuthContainer, flows: Flows, email: str = "user@example.com") -> None:
    await flows.register.execute(RegisterRequest(email=email, password=PASSWORD, display_name="User"))
    await flows.verify.execute(
        VerifyEmailRequest(email=email, code=container.email_sender.last_code(), password=PASSWORD)
    )


@pytest.mark.asyncio
async def test_register_then_verify_then_login(container: AuthContainer, flows: Flows) -> None:
    register = await flows.register.execute(
        RegisterRequest(email="user@example.com", password=PASSWORD, display_name="User")
    )
    assert register.verification_required is True
    assert "*" in register.email  # masked

    await flows.verify.execute(
        VerifyEmailRequest(email="user@example.com", code=container.email_sender.last_code(), password=PASSWORD)
    )

    tokens = await flows.login.execute(LoginRequest(email="user@example.com", password=PASSWORD))
    assert tokens.access_token and tokens.refresh_token
    assert tokens.user is not None and tokens.user.email == "user@example.com"


@pytest.mark.asyncio
async def test_login_before_verification_is_rejected(container: AuthContainer, flows: Flows) -> None:
    await flows.register.execute(RegisterRequest(email="user@example.com", password=PASSWORD, display_name="User"))
    with pytest.raises(EmailNotVerifiedError):
        await flows.login.execute(LoginRequest(email="user@example.com", password=PASSWORD))


@pytest.mark.asyncio
async def test_wrong_password_is_rejected(container: AuthContainer, flows: Flows) -> None:
    await register_and_verify(container, flows)
    with pytest.raises(InvalidCredentialsError):
        await flows.login.execute(LoginRequest(email="user@example.com", password="wrong9999"))


@pytest.mark.asyncio
async def test_refresh_rotates_and_rejects_replay(container: AuthContainer, flows: Flows) -> None:
    await register_and_verify(container, flows)
    tokens = await flows.login.execute(LoginRequest(email="user@example.com", password=PASSWORD))

    rotated = await flows.refresh.execute(tokens.refresh_token)
    assert rotated.refresh_token != tokens.refresh_token

    with pytest.raises(jwt.InvalidTokenError):
        await flows.refresh.execute(tokens.refresh_token)


@pytest.mark.asyncio
async def test_logout_revokes_refresh_token(container: AuthContainer, flows: Flows) -> None:
    await register_and_verify(container, flows)
    tokens = await flows.login.execute(LoginRequest(email="user@example.com", password=PASSWORD))

    await flows.logout.execute(tokens.refresh_token)
    with pytest.raises(jwt.InvalidTokenError):
        await flows.refresh.execute(tokens.refresh_token)


@pytest.mark.asyncio
async def test_password_reset_flow(container: AuthContainer, flows: Flows) -> None:
    await register_and_verify(container, flows)

    await flows.request_reset.execute(ResendRequest(email="user@example.com"))
    code = container.email_sender.last_code()

    await flows.confirm_reset.execute(
        ResetPasswordRequest(email="user@example.com", code=code, new_password="newpass123")
    )

    with pytest.raises(InvalidCredentialsError):
        await flows.login.execute(LoginRequest(email="user@example.com", password=PASSWORD))
    tokens = await flows.login.execute(LoginRequest(email="user@example.com", password="newpass123"))
    assert tokens.access_token


@pytest.mark.asyncio
async def test_register_with_verified_email_is_generic(container: AuthContainer, flows: Flows) -> None:
    await register_and_verify(container, flows)
    response = await flows.register.execute(
        RegisterRequest(email="user@example.com", password=PASSWORD, display_name="User")
    )
    assert response.verification_required is True
    # Owner is notified instead; the response is a masked, account-agnostic shape.
    assert "user@example.com" not in response.email
