import air
import airclerk

app = air.Air()
app.add_middleware(air.SessionMiddleware, secret_key="change-me")
app.include_router(airclerk.router)


@app.page
def index(request: air.Request):
    return air.layouts.mvpcss(
        air.H1('AirClerk demo'),
        air.P(
            air.A(
                'protected', href=protected.url()    
            )
        )

    )

@app.page
def protected(request: air.Request, user = airclerk.require_auth):
    return air.layouts.mvpcss(
        air.H1('Protected view'),
        air.P(str(user))
    )