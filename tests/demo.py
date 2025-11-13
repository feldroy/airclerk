from datetime import datetime

import air
import airclerk

app = air.Air()
app.add_middleware(air.SessionMiddleware, secret_key="change-me")
app.include_router(airclerk.router)


def dump(obj: dict) -> air.BaseTag:
    rows = []
    try:
        data = obj.__dict__.items()
    except AttributeError:
        data = obj.items()
    for k, v in data:
        rows.append(air.Li(air.Strong(k), ": ", v))
    return air.Ul(*rows)


@app.page
def index(request: air.Request, user=airclerk.optional_user):
    links = []
    if user:
        email = (
            user.email_addresses[0].email_address if user.email_addresses else user.id
        )
        links.extend(
            [
                air.Li(f"Logged in as {email}"),
                air.Li(air.A("protected", href=protected.url())),
                air.Li(air.A("logout", hx_post=airclerk.settings.CLERK_LOGOUT_ROUTE)),
            ]
        )
    else:
        links.extend(
            [
                air.Li(air.A("login", href=airclerk.settings.CLERK_LOGIN_ROUTE)),
                air.Li(air.A("protected", href=protected.url())),
            ]
        )

    return air.Tag(
        airclerk.clerk_scripts(user),
        air.layouts.mvpcss(
            air.H1("AirClerk demo"),
            air.Ul(*links),
            air.P("Authentication is handled by Clerk via JWT tokens in cookies."),
        ),
    )


@app.page
def protected(request: air.Request, user=airclerk.require_auth):
    return air.layouts.mvpcss(
        air.H1("Protected view"),
        air.P(air.A("home", href=index.url())),
        air.H2("Clerk user object"),
        air.P(
            air.Strong("Last sign in at: "),
            datetime.fromtimestamp(user.last_sign_in_at / 1000),
        ),
        dump(user),
    )
