import air
import airclerk

app = air.Air()
app.add_middleware(air.SessionMiddleware, secret_key="change-me")
app.include_router(airclerk.router)


@app.page
def index(request: air.Request):
    return air.layouts.mvpcss(
        air.H1('AirClerk demo'),
        air.Ul(
            air.Li(air.A('login', href=airclerk.settings.LOGIN_ROUTE)),
            air.Li(air.A('protected', href=protected.url()))
        ),
        air.Article(air.Aside(str(request.session['user']))),

    )

@app.page
def protected(request: air.Request, user = airclerk.require_auth):
    return air.layouts.mvpcss(
        air.H1('Protected view'),
        air.Article(air.Aside(str(user))),
        air.Hr(),
        air.Article(air.Aside(str(request.session['user']))),
        
    )