"""FastAPI integration: guards, cookie sessions and a router builder."""

from pyauthkit.fastapi.exception_handlers import install, register_exception_handlers
from pyauthkit.fastapi.routes import build_auth_router
from pyauthkit.fastapi.security import (
    RequestContext,
    get_container,
    get_current_user,
    get_request_context,
    require_roles,
)
from pyauthkit.fastapi.sessions import (
    BROWSER_SESSION_OPENAPI,
    clear_refresh_cookie,
    is_browser_session,
    refresh_request_token,
    set_refresh_cookie,
)

__all__ = [
    "BROWSER_SESSION_OPENAPI",
    "RequestContext",
    "build_auth_router",
    "clear_refresh_cookie",
    "get_container",
    "get_current_user",
    "get_request_context",
    "install",
    "is_browser_session",
    "refresh_request_token",
    "register_exception_handlers",
    "require_roles",
    "set_refresh_cookie",
]
