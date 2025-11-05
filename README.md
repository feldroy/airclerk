# airclerk

Air + Clerk for user management.

## Environment Variables

AirClerk is driven by the following environment variables:

| Variable | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| `CLERK_PUBLISHABLE_KEY` | str | Yes | - | Clerk publishable API key for client-side authentication |
| `CLERK_SECRET_KEY` | str | Yes | - | Clerk secret API key for server-side operations |
| `CLERK_JS_SRC` | str | No | `https://cdn.jsdelivr.net/npm/@clerk/clerk-js@5/dist/clerk.browser.js` | CDN URL for the Clerk JavaScript library |
| `LOGIN_ROUTE` | str | No | `/login` | URL path for the login page |
| `LOGOUT_ROUTE` | str | No | `/logout` | URL path for the logout endpoint |

