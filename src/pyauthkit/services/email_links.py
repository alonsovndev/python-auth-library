"""Links embedded in verification and reset emails."""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlencode


@dataclass(frozen=True)
class EmailLinks:
    """Builds the front-end URLs the emails point at.

    Paths are conventional (``/verify-email``, ``/login``, ``/reset-password``); override by
    subclassing if a host uses different routes.
    """

    base_url: str

    def verify_email(self, email: str, code: str, set_password: bool = False) -> str:
        params = {"email": email, "code": code}
        if set_password:
            params["setPassword"] = "1"
        return f"{self._base()}/verify-email?{urlencode(params)}"

    def sign_in(self) -> str:
        return f"{self._base()}/login"

    def reset_password(self, email: str, code: str) -> str:
        return f"{self._base()}/reset-password?{urlencode({'email': email, 'code': code})}"

    def _base(self) -> str:
        return self.base_url.rstrip("/")


__all__ = ["EmailLinks"]
