from typing import Any, Dict

import air
from clerk_backend_api import Clerk
from clerk_backend_api.security.types import AuthenticateRequestOptions
from fastapi import Depends, status
import httpx
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Environment variable specification"""

    CLERK_PUBLISHABLE_KEY: str
    CLERK_SECRET_KEY: str
    CLERK_JS_SRC: str = (
        "https://cdn.jsdelivr.net/npm/@clerk/clerk-js@5/dist/clerk.browser.js"
    )
    CLERK_LOGIN_ROUTE: str = "/login"
    CLERK_LOGIN_REDIRECT_ROUTE: str = "/"
    CLERK_LOGOUT_ROUTE: str = "/logout"
    CLERK_LOGOUT_REDIRECT_ROUTE: str = "/"


settings = Settings()


router = air.AirRouter()


async def _to_httpx_request(request: air.Request) -> httpx.Request:
    body = await request.body()
    return httpx.Request(
        method=request.method,
        url=str(request.url),
        headers=dict(request.headers),
        content=body,
    )


async def _require_auth(request: air.Request) -> Dict[str, Any]:
    """Require user to be authenticated - raises exception that redirects if not."""
    body = await request.body()
    httpx_request = httpx.Request(
        method=request.method,
        url=str(request.url),
        headers=dict(request.headers),
        content=body,
    )
    origin = f"{request.url.scheme}://{request.url.netloc}"
    with Clerk(bearer_auth=settings.CLERK_SECRET_KEY) as clerk:
        state = clerk.authenticate_request(
            httpx_request,
            AuthenticateRequestOptions(authorized_parties=[origin]),
        )

        if not state.is_signed_in:
            # Store the original URL to redirect back after login
            redirect_after_login = str(request.url.path)
            if request.url.query:
                redirect_after_login += f"?{request.url.query}"

            login_url = f"{login.url()}?next={redirect_after_login}"

            if request.htmx:
                raise air.HTTPException(
                    status_code=status.HTTP_303_SEE_OTHER,
                    headers={"Location": login_url},
                )
            raise air.HTTPException(
                status_code=status.HTTP_303_SEE_OTHER,
                headers={"Location": login_url},
            )
        user_id = getattr(state, "user_id", None) or state.payload.get("sub")
        user = clerk.users.get(user_id=user_id)
        return user


async def _optional_auth(request: air.Request) -> Dict[str, Any] | None:
    """Authenticate user if possible, return None if not authenticated (no redirect)."""
    body = await request.body()
    httpx_request = httpx.Request(
        method=request.method,
        url=str(request.url),
        headers=dict(request.headers),
        content=body,
    )
    origin = f"{request.url.scheme}://{request.url.netloc}"
    with Clerk(bearer_auth=settings.CLERK_SECRET_KEY) as clerk:
        state = clerk.authenticate_request(
            httpx_request,
            AuthenticateRequestOptions(authorized_parties=[origin]),
        )

        if not state.is_signed_in:
            return None

        user_id = getattr(state, "user_id", None) or state.payload.get("sub")
        user = clerk.users.get(user_id=user_id)
        return user


require_auth = Depends(_require_auth)
optional_user = Depends(_optional_auth)


def clerk_scripts(user: Dict[str, Any] | None = None) -> air.Tag:
    """Return Clerk JS script tags with auto-reload on auth state mismatch.

    Include this on pages using optional_user to ensure server/client auth state stays in sync.
    After login, if the server hasn't seen the session cookie yet, this auto-reloads the page.

    Args:
        user: The user object from optional_user. Pass it to enable auto-sync.

    Returns:
        Script tags to include in your page.

    Example:
        @app.page
        def index(user=airclerk.optional_user):
            return air.Tag(
                airclerk.clerk_scripts(user),
                air.H1("Welcome"),
                # ... rest of page
            )
    """
    scripts = [
        air.Script(
            src=settings.CLERK_JS_SRC,
            async_=True,
            crossorigin="anonymous",
            **{"data-clerk-publishable-key": settings.CLERK_PUBLISHABLE_KEY},
        ),
        air.Script(f"""
            document.addEventListener('DOMContentLoaded', async () => {{
                if (!window.Clerk) return;
                await window.Clerk.load();
                
                const serverHasUser = {str(user is not None).lower()};
                const clerkHasUser = !!window.Clerk.user;
                
                // If server and client auth states don't match, reload once
                if (serverHasUser !== clerkHasUser) {{
                    window.location.reload();
                }}
            }});
        """),
    ]

    return air.Tag(*scripts)


@router.get(settings.CLERK_LOGIN_ROUTE)
async def login(request: air.Request, next: str = "/"):
    httpx_request = await _to_httpx_request(request)
    origin = f"{request.url.scheme}://{request.url.netloc}"

    with Clerk(bearer_auth=settings.CLERK_SECRET_KEY) as clerk:
        state = clerk.authenticate_request(
            httpx_request,
            AuthenticateRequestOptions(authorized_parties=[origin]),
        )

        if not state.is_signed_in:
            return air.Tag(
                air.Div(id="sign-in"),
                air.Script(
                    src=settings.CLERK_JS_SRC,
                    async_=True,
                    crossorigin="anonymous",  # allow fetching Clerk script without cookies/sensitive credentials
                    **{"data-clerk-publishable-key": settings.CLERK_PUBLISHABLE_KEY},
                ),
                air.Script(f"""
                    document.addEventListener('DOMContentLoaded', async () => {{
                    if (!window.Clerk) return;

                    await window.Clerk.load();

                    if (window.Clerk.user) {{
                        window.location.assign('{next}');
                        return;
                    }}

                    window.Clerk.mountSignIn(
                        document.getElementById('sign-in'),
                        {{ redirectUrl: '{next}' }}
                    );
                    }});
                    """),
            )

        # User is already authenticated via Clerk JWT
        # Redirect to the 'next' parameter or default redirect route
        return air.RedirectResponse(
            next if next != "/" else settings.CLERK_LOGIN_REDIRECT_ROUTE
        )


@router.get(settings.CLERK_LOGOUT_ROUTE)
async def logout(request: air.Request, user=require_auth):
    # Return a page that triggers client-side logout via Clerk JavaScript SDK
    # This will clear the JWT token from browser cookies
    return air.Tag(
        air.Script(
            src=settings.CLERK_JS_SRC,
            async_=True,
            crossorigin="anonymous",
            **{"data-clerk-publishable-key": settings.CLERK_PUBLISHABLE_KEY},
        ),
        air.Script(f"""
            document.addEventListener('DOMContentLoaded', async () => {{
                if (!window.Clerk) return;
                
                await window.Clerk.load();
                
                // Sign out on the client side (clears cookies/tokens)
                await window.Clerk.signOut();
                
                // Redirect to home page
                window.location.assign('{settings.CLERK_LOGOUT_REDIRECT_ROUTE}');
            }});
        """),
    )
