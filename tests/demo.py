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
def index(request: air.Request, claims=airclerk.optional_auth_claims):
    links = []
    if claims:
        email = claims.get("email") or claims.get("sub")
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
        airclerk.clerk_scripts(claims),
        air.layouts.mvpcss(
            air.H1("AirClerk demo"),
            air.Ul(*links),
            air.P("Authentication is handled by Clerk via JWT tokens in cookies."),
        ),
    )


@app.page
def protected(request: air.Request, claims=airclerk.require_auth_claims):
    return air.layouts.mvpcss(
        airclerk.clerk_scripts(claims),
        air.H1("Protected view"),
        air.P(air.A("home", href=index.url())),
        air.H2("Clerk session claims"),
        dump(claims),
    )
