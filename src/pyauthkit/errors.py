"""Exception hierarchy for pyauthkit.

Every public error derives from :class:`AuthKitError`, so a consumer can catch the whole
family with one ``except``. Authentication failures derive from
:class:`AuthenticationError`; configuration mistakes raise :class:`AuthConfigError`.
"""

from __future__ import annotations


class AuthKitError(Exception):
    """Base class for every error raised by pyauthkit."""


class AuthConfigError(AuthKitError):
    """Raised when :class:`~pyauthkit.config.AuthConfig` is misconfigured or insecure."""


class AuthenticationError(AuthKitError):
    """Base class for authentication failures."""


class InvalidCredentialsError(AuthenticationError):
    """Raised when a login's email or password is wrong."""

    def __init__(self, message: str = "Invalid credentials") -> None:
        self.message = message
        super().__init__(self.message)


class UnauthorizedError(AuthenticationError):
    """Raised when a request carries no usable identity."""

    def __init__(self, message: str = "Authentication required") -> None:
        self.message = message
        super().__init__(self.message)


class InsufficientPermissionsError(AuthenticationError):
    """Raised when an authenticated user lacks the role a route requires."""

    def __init__(self, message: str = "Insufficient permissions") -> None:
        self.message = message
        super().__init__(self.message)


class AccountLockedError(AuthenticationError):
    """Raised when an account is temporarily locked after too many failed logins."""

    def __init__(
        self,
        message: str = "Account temporarily locked",
        remaining_seconds: int = 0,
        failed_attempts: int = 0,
    ) -> None:
        self.message = message
        self.remaining_seconds = remaining_seconds
        self.failed_attempts = failed_attempts
        super().__init__(self.message)


class EmailNotVerifiedError(AuthenticationError):
    """Raised on login when the password is valid but the email is unconfirmed."""

    def __init__(self, message: str = "Please verify your email before signing in.") -> None:
        self.message = message
        super().__init__(self.message)


class InvalidVerificationCodeError(AuthenticationError):
    """Raised when an email verification code is wrong, expired, used or unknown.

    A single error for every case, so the endpoint cannot be used to learn which emails
    have accounts or which are already verified.
    """

    def __init__(self, message: str = "Invalid or expired verification code") -> None:
        self.message = message
        super().__init__(self.message)


class VerificationRateLimitedError(AuthenticationError):
    """Raised when verification-code issuance or validation exceeds its limit."""

    def __init__(self, message: str = "Too many attempts. Please try again later.") -> None:
        self.message = message
        super().__init__(self.message)


class InvalidResetCodeError(AuthenticationError):
    """Raised when a password reset code is wrong, expired, used or unknown."""

    def __init__(self, message: str = "Invalid or expired reset code") -> None:
        self.message = message
        super().__init__(self.message)


class ResetCodeRateLimitedError(AuthenticationError):
    """Raised when reset-code issuance or validation exceeds its limit."""

    def __init__(self, message: str = "Too many attempts. Please try again later.") -> None:
        self.message = message
        super().__init__(self.message)


class PasswordPolicyError(AuthKitError):
    """Raised when a password fails the configured policy."""

    def __init__(self, message: str) -> None:
        self.message = message
        super().__init__(self.message)


__all__ = [
    "AccountLockedError",
    "AuthConfigError",
    "AuthKitError",
    "AuthenticationError",
    "EmailNotVerifiedError",
    "InsufficientPermissionsError",
    "InvalidCredentialsError",
    "InvalidResetCodeError",
    "InvalidVerificationCodeError",
    "PasswordPolicyError",
    "ResetCodeRateLimitedError",
    "UnauthorizedError",
    "VerificationRateLimitedError",
]
