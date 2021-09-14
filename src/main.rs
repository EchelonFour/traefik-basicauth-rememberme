#[macro_use] extern crate rocket;
use rocket::http::{Cookie, CookieJar, Header};
use rocket::response::content::Html;
use rocket::request::{FromRequest, Outcome, Request};
use rocket::outcome::{try_outcome, IntoOutcome};
use rocket::{Response, State, response};
use rocket::response::Responder;
use htpasswd_verify::Htpasswd;
use http::header::{AUTHORIZATION, WWW_AUTHENTICATE};
use http_auth_basic::Credentials;

struct User {
    id: String,
    from_cookie: bool,
}

#[rocket::async_trait]
impl<'r> Responder<'r, 'static> for User {
    fn respond_to(self, _: &'r Request<'_>) -> response::Result<'static> {
        Response::build()
            .raw_header("x-user", self.id)
            .ok()
    }
}

fn get_cookie_user(request: &'_ Request<'_>) -> Option<User> {
    request.cookies()
        .get_private("remembered_user")
        .and_then(|cookie| cookie.value().parse().ok())
        .map(|user| User { id: user, from_cookie: true })
}
fn get_auth_user(request: &'_ Request<'_>, htpasswd: &State<Htpasswd>) -> Option<User> {
    request.headers()
        .get_one(AUTHORIZATION.as_str())
        .and_then(|auth| Credentials::from_header(auth.to_string()).ok())
        .and_then(|creds| if htpasswd.check(&creds.user_id, &creds.password) { Some(creds.user_id) } else { None })
        .map(|valid_user| User { id: valid_user, from_cookie: false })
} 
#[rocket::async_trait]
impl<'r> FromRequest<'r> for User {
    type Error = ();

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let htpasswd: &State<Htpasswd> = try_outcome!(request.guard::<&State<Htpasswd>>().await);
        get_cookie_user(request).or_else(|| get_auth_user(request, htpasswd)).or_forward(())
    }
}

struct WWWAuthenticate {
    realm: String
}

impl From<WWWAuthenticate> for Header<'static> {
    fn from(www_authenticate: WWWAuthenticate) -> Self {
        Header::new(WWW_AUTHENTICATE.as_str(), format!("Basic realm=\"{}\"", www_authenticate.realm))
    }
}

#[get("/<_..>", rank = 1)]
fn verify_user(user: User, cookies: &CookieJar<'_>) -> User {
    if !user.from_cookie {
        cookies.add_private(Cookie::build("remembered_user", user.id.clone())
            .permanent()
            .finish());
    }
    user
}

#[derive(Responder)]
#[response(status = 401)]
struct AuthChallengeResponse {
    inner: Html<&'static str>,
    header: WWWAuthenticate
}

#[get("/<_..>", rank = 2)]
fn authenticate() -> AuthChallengeResponse {
    AuthChallengeResponse {
        inner: Html("<wow></wow>"),
        header: WWWAuthenticate { realm: "Hey, are you cool?".into() }
    }
}

#[launch]
fn rocket() -> _ {
    let data = "user:$apr1$lZL6V/ci$eIMz/iKDkbtys/uU7LEK00";
    let htpasswd = Htpasswd::new(data);
    rocket::build()
        .attach(rocket::shield::Shield::new())
        .manage(htpasswd)
        .mount("/", routes![verify_user, authenticate])
}