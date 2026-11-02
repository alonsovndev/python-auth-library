"""Central configuration for pyauthkit.

``AuthConfig`` is a plain, immutable dataclass: it depends on nothing from the host
application so it can be built from environment variables, ``profileconf``, pydantic
settings, or a literal in tests. Pass one instance to the services and the FastAPI router
builder.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

# Excludes 0, 1, O, I (visually ambiguous) so codes survive being read aloud or retyped.
DEFAULT_ONE_TIME_CODE_ALPHABET = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ"
DEFAULT_ONE_TIME_CODE_LENGTH = 6


@dataclass(frozen=True)
class AuthConfig:
    """Everything the toolkit needs to issue, verify and expire credentials.

    Args:
        secret_key: HMAC signing key for JWTs. Enforced to be >= 32 chars and not a known
            weak value unless ``validate_secret`` is False (useful in tests).
        audience: Expected ``aud`` claim. Set it to your service name so a token minted
            for another service is rejected.
        issuer: Expected ``iss`` claim.
        algorithm: JWT signing algorithm (HS256 by default).
        validate_secret: Disable only for tests.
        access_expiration_minutes: Access-token lifetime.
        refresh_expiration_minutes: Standard refresh-token lifetime (sliding window).
        remember_me_expiration_minutes: Extended refresh lifetime when ``remember_me`` is set.
        max_failed_attempts: Consecutive failures before lockout.
        lockout_duration_minutes: Base lockout duration.
        progressive_lockout: Escalate the duration as failures accumulate.
        attempt_window_minutes: Window after which a failure streak resets.
        min_password_length: Minimum length enforced by ``PasswordPolicy``.
        one_time_code_length / alphabet: Generated code shape.
        verification_code_ttl_minutes: TTL for self-registration verification codes.
        invite_verification_code_ttl_minutes: TTL for invited-account verification codes
            (adopted from the reference, where an invitee may open the email much later).
        reset_code_ttl_minutes: TTL for password reset codes.
        max_code_attempts: Wrong guesses allowed against one code before it locks.
        verification_resend_window_minutes / max_verification_codes_per_window: resend cap.
        reset_request_window_minutes / max_reset_codes_per_window: reset-request cap.
        refresh_cookie_name / refresh_cookie_path: browser-session cookie identity.
        cookie_secure / cookie_samesite: cookie hardening.
        trusted_origins: Origins allowed to open a cookie session.
        allow_localhost_origins: Additionally allow ``http://localhost:<port>`` / ``127.0.0.1``.
        frontend_base_url: Base URL used to build links in emails.
    """

    secret_key: str
    audience: str = "pyauthkit"
    issuer: str = "pyauthkit"
    algorithm: str = "HS256"
    validate_secret: bool = True
    access_expiration_minutes: int = 15
    refresh_expiration_minutes: int = 1440
    remember_me_expiration_minutes: int = 10080

    max_failed_attempts: int = 5
    lockout_duration_minutes: int = 15
    progressive_lockout: bool = True
    attempt_window_minutes: int = 15

    min_password_length: int = 8

    one_time_code_length: int = DEFAULT_ONE_TIME_CODE_LENGTH
    one_time_code_alphabet: str = DEFAULT_ONE_TIME_CODE_ALPHABET
    verification_code_ttl_minutes: int = 5
    invite_verification_code_ttl_minutes: int = 1440
    reset_code_ttl_minutes: int = 30
    max_code_attempts: int = 5
    verification_resend_window_minutes: int = 15
    max_verification_codes_per_window: int = 4
    reset_request_window_minutes: int = 15
    max_reset_codes_per_window: int = 3

    refresh_cookie_name: str = "pyauthkit_refresh_token"
    refresh_cookie_path: str = "/auth"
    cookie_secure: bool = True
    cookie_samesite: Literal["lax", "strict", "none"] = "lax"
    trusted_origins: tuple[str, ...] = field(default_factory=tuple)
    allow_localhost_origins: bool = False
    frontend_base_url: str = ""


__all__ = ["DEFAULT_ONE_TIME_CODE_ALPHABET", "DEFAULT_ONE_TIME_CODE_LENGTH", "AuthConfig"]
