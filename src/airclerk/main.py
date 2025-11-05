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
    CLERK_JS_SRC: str = "https://cdn.jsdelivr.net/npm/@clerk/clerk-js@5/dist/clerk.browser.js"
    LOGIN_ROUTE: str = '/login'
    LOGOUT_ROUTE: str = '/logout'

settings = Settings()


router = air.AirRouter()

SIGN_IN_SCRIPT = air.Script("""
document.addEventListener('DOMContentLoaded', async () => {
  if (!window.Clerk) return;

  await window.Clerk.load();

  if (window.Clerk.user) {
    window.location.assign('/');
    return;
  }

  window.Clerk.mountSignIn(
    document.getElementById('sign-in'),
    { redirectUrl: '/' }
  );
});
""")


AUTH_SCRIPT = air.Script("""
document.addEventListener('DOMContentLoaded', async () => {
  await window.Clerk.load();
  
  const button = document.getElementById('sign-out');

  button.addEventListener('click', async () => {
    await window.Clerk.signOut({ redirectUrl: '/' });
  });
});
""")

CLERK_SCRIPT = air.Script(
        src=settings.CLERK_JS_SRC,
        async_=True,
        crossorigin="anonymous",  # allow fetching Clerk script without cookies/sensitive credentials
        **{"data-clerk-publishable-key": settings.CLERK_PUBLISHABLE_KEY},
    )

def _signed_out_snippet() -> air.BaseTag:
    return air.Tag(
        air.Div(id="sign-in"),
        CLERK_SCRIPT,
        SIGN_IN_SCRIPT,
    )


def _signed_in_snippet(email: str) -> air.BaseTag:
    clean_email = email or "Unknown user"
    return air.Tag(
        air.Button("Sign out", id="sign-out", type="button"),
        CLERK_SCRIPT,
        AUTH_SCRIPT,
    )

async def _to_httpx_request(request: air.Request) -> httpx.Request:
    body = await request.body()
    return httpx.Request(
        method=request.method,
        url=str(request.url),
        headers=dict(request.headers),
        content=body,
    )

def _extract_primary_email(user: Any) -> str:
    email_addresses = list(getattr(user, "email_addresses", []) or [])
    primary_id = getattr(user, "primary_email_address_id", None)

    for address in email_addresses:
        if getattr(address, "id", None) == primary_id:
            return getattr(address, "email_address", "")

    if email_addresses:
        return getattr(email_addresses[0], "email_address", "")

    return ""



@router.get(settings.LOGIN_ROUTE)
async def login(request: air.Request):
    httpx_request = await _to_httpx_request(request)
    origin = f"{request.url.scheme}://{request.url.netloc}"

    with Clerk(bearer_auth=settings.CLERK_SECRET_KEY) as sdk:
        state = sdk.authenticate_request(
            httpx_request,
            AuthenticateRequestOptions(authorized_parties=[origin]),
        )

        if not state.is_signed_in:
            return _signed_out_snippet()

        user_id = getattr(state, "user_id", None) or state.payload.get("sub")
        # TODO: save user_id to db
        # TODO: save user_id to session
        user = sdk.users.get(user_id=user_id)
        email = _extract_primary_email(user)
        # https://github.com/clerk/clerk-sdk-python/blob/main/docs/models/user.md
        # TODO: save email to session        
        # return _signed_in_page(email)
        return air.RedirectResponse('/dashboard')
    

@router.post(settings.LOGOUT_ROUTE)
async def logout(request: air.Request):
    return air.RedirectResponse('/')


async def _require_auth(request: air.Request) -> Dict[str, Any]:
    """Require user to be authenticated - raises exception if not.

    Additionally, if the authenticated user's row does not have an email we
    redirect them to the add-email form so they can supply one before using
    protected areas of the app.
    """
    body = await request.body()
    httpx_request = httpx.Request(
        method=request.method,
        url=str(request.url),
        headers=dict(request.headers),
        content=body,
    )
    origin = f"{request.url.scheme}://{request.url.netloc}"
    with Clerk(bearer_auth=settings.CLERK_SECRET_KEY) as sdk:
        state = sdk.authenticate_request(
            httpx_request,
            AuthenticateRequestOptions(authorized_parties=[origin]),
        )

        if not state.is_signed_in:
            if request.htmx:
                raise air.HTTPException(
                    status_code=status.HTTP_303_SEE_OTHER,
                    headers={"Location": login.url()},
                )
            raise air.HTTPException(
                status_code=status.HTTP_303_SEE_OTHER,
                headers={"Location": login.url()},
            )            
            return air.RedirectResponse(settings.LOGIN_ROUTE)
        return state

require_auth = Depends(_require_auth)    