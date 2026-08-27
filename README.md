# airclerk

Air + Clerk for user management.

## Environment Variables

AirClerk is driven by the following environment variables:

| Variable | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| `CLERK_PUBLISHABLE_KEY` | str | Yes | - | Clerk publishable API key for client-side authentication |
| `CLERK_SECRET_KEY` | str | Yes | - | Clerk secret API key for server-side operations |
| `CLERK_JS_SRC` | str | No | `https://cdn.jsdelivr.net/npm/@clerk/clerk-js@5/dist/clerk.browser.js` | CDN URL for the Clerk JavaScript library |
| `CLERK_LOGIN_ROUTE` | str | No | `/login` | URL path for the login page |
| `CLERK_LOGOUT_ROUTE` | str | No | `/logout` | URL path for the logout endpoint |
| `CLERK_LOGIN_REDIRECT_ROUTE` | str | No | `/` | Where the user is redirected to after login |
| `CLERK_LOGOUT_REDIRECT_ROUTE` | str | No | `/` | Where the user is redirected to after logout |

You must set the required environment variables for AirClerk to function properly. Optional variables can be customized as needed.

## Usage

To use AirClerk in your Air application, include the middleware and router as shown below:

```python
import air
import airclerk

app = air.Air()
app.add_middleware(air.SessionMiddleware, secret_key="change-me")
app.include_router(airclerk.router)
```

When you run a development OAuth-powered Air application with AirClerk, don't use localhost as your domain, as Clerk does not support it. Use `127.0.0.1` instead.

### Reading user data from session claims

For most routes, use the verified session claims. This avoids a request to
Clerk's Backend API:

```python
@app.page
def protected(claims=airclerk.require_auth_claims):
    user_id = claims["sub"]
    organization_id = claims.get("org_id")
    return air.P(f"Signed in as {user_id} ({organization_id or 'no organization'})")
```

The claims commonly include values such as `sub` (user ID), `sid` (session
ID), and token timestamps. When a user has an active organization, organization
claims may also be present. The exact set depends on your Clerk session token
version and configuration. See Clerk's [session token claims
reference](https://clerk.com/docs/guides/sessions/session-tokens) for the
default claims and [custom session token
guide](https://clerk.com/docs/guides/sessions/customize-session-tokens) for
adding your own.

To see what your instance provides, temporarily log the claims on the server:

```python
@app.page
def inspect_claims(claims=airclerk.require_auth_claims):
    print(sorted(claims))
    return air.P("Claims were printed to the server log.")
```

Do not expose claims or session tokens in a public response or log in
production.

If a route needs fields that are not in the claims, use the full Clerk user
profile dependency:

```python
@app.page
def profile(user=airclerk.require_user):
    return air.P(user.first_name or user.id)
```
