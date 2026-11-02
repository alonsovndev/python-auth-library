"""pyauthkit — framework-agnostic authentication toolkit.

Core (always installed): JWT tokens, password hashing, account lockout, single-use refresh
revocation, one-time codes, DTOs, ports and generic services. FastAPI routes/guards live in
the optional ``[fastapi]`` extra; Postgres adapters in the optional ``[sqlalchemy]`` extra.
"""

from importlib.metadata import PackageNotFoundError, version

from pyauthkit.codes import CodeStore, InMemoryCodeStore, OneTimeCode, generate_one_time_code
from pyauthkit.config import AuthConfig
from pyauthkit.container import AuthContainer, EmailVerifiedHook
from pyauthkit.dtos import (
    BrowserTokenPair,
    LoginRequest,
    LogoutResponse,
    MessageResponse,
    RefreshRequest,
    RegisterRequest,
    RegisterResponse,
    ResendRequest,
    ResetPasswordRequest,
    TokenPair,
    UserInfo,
    VerifyEmailRequest,
    VerifyEmailResponse,
)
from pyauthkit.errors import (
    AccountLockedError,
    AuthConfigError,
    AuthenticationError,
    AuthKitError,
    EmailNotVerifiedError,
    InsufficientPermissionsError,
    InvalidCredentialsError,
    InvalidResetCodeError,
    InvalidVerificationCodeError,
    PasswordPolicyError,
    ResetCodeRateLimitedError,
    UnauthorizedError,
    VerificationRateLimitedError,
)
from pyauthkit.lockout import AccountLockoutService, InMemoryLockoutStore, LockoutState, LockoutStore
from pyauthkit.passwords import BcryptPasswordHasher, PasswordHasher, PasswordPolicy
from pyauthkit.ports import AuthUser, EmailSender, RegistrationBuilder, RegistrationData, UserStore
from pyauthkit.revocation import InMemoryRevocationStore, RevocationStore, TokenRevocationService, hash_token
from pyauthkit.services.email_links import EmailLinks
from pyauthkit.services.login import LoginService
from pyauthkit.services.logout import LogoutService
from pyauthkit.services.password_reset import (
    ConfirmPasswordResetService,
    RequestPasswordResetService,
    ResendResetCodeService,
)
from pyauthkit.services.refresh import RefreshTokenService
from pyauthkit.services.register import RegisterService
from pyauthkit.services.revoke_all import RevokeAllSessionsService
from pyauthkit.services.verification import ResendVerificationService, VerifyEmailService
from pyauthkit.tokens import TokenService

try:
    __version__ = version("pyauthkit")
except PackageNotFoundError:  # pragma: no cover - running from a source tree without installation
    __version__ = "0.0.0"

__all__ = [
    "AccountLockedError",
    "AccountLockoutService",
    "AuthConfig",
    "AuthConfigError",
    "AuthContainer",
    "AuthKitError",
    "AuthUser",
    "AuthenticationError",
    "BcryptPasswordHasher",
    "BrowserTokenPair",
    "CodeStore",
    "ConfirmPasswordResetService",
    "EmailLinks",
    "EmailNotVerifiedError",
    "EmailSender",
    "EmailVerifiedHook",
    "InMemoryCodeStore",
    "InMemoryLockoutStore",
    "InMemoryRevocationStore",
    "InsufficientPermissionsError",
    "InvalidCredentialsError",
    "InvalidResetCodeError",
    "InvalidVerificationCodeError",
    "LockoutState",
    "LockoutStore",
    "LoginRequest",
    "LoginService",
    "LogoutResponse",
    "LogoutService",
    "MessageResponse",
    "OneTimeCode",
    "PasswordHasher",
    "PasswordPolicy",
    "PasswordPolicyError",
    "RefreshRequest",
    "RefreshTokenService",
    "RegisterRequest",
    "RegisterResponse",
    "RegisterService",
    "RegistrationBuilder",
    "RegistrationData",
    "RequestPasswordResetService",
    "ResendRequest",
    "ResendResetCodeService",
    "ResendVerificationService",
    "ResetCodeRateLimitedError",
    "ResetPasswordRequest",
    "RevocationStore",
    "RevokeAllSessionsService",
    "TokenPair",
    "TokenRevocationService",
    "TokenService",
    "UnauthorizedError",
    "UserInfo",
    "UserStore",
    "VerificationRateLimitedError",
    "VerifyEmailRequest",
    "VerifyEmailResponse",
    "VerifyEmailService",
    "__version__",
    "generate_one_time_code",
    "hash_token",
]
