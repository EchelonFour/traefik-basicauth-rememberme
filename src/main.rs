#[macro_use] extern crate rocket;
use rocket::http::{Cookie, CookieJar, Header};
use rocket::response::content::Html;
use rocket::request::{FromRequest, Outcome, Request};
use rocket::outcome::{try_outcome, IntoOutcome};
use rocket::State;
use htpasswd_verify::Htpasswd;
use http::header::{AUTHORIZATION, WWW_AUTHENTICATE};
use http_auth_basic::Credentials;

struct User(String);

#[rocket::async_trait]
impl<'r> FromRequest<'r> for User {
    type Error = ();

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let htpasswd: &State<Htpasswd> = try_outcome!(request.guard::<&State<Htpasswd>>().await);
        request.headers()
            .get_one(AUTHORIZATION.as_str())
            .and_then(|auth| Credentials::from_header(auth.to_string()).ok())
            .and_then(|creds| if htpasswd.check(&creds.user_id, &creds.password) { Some(creds.user_id) } else { None })
            .and_then(|valid_user| Some(User(valid_user)))
            .or_forward(())
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
fn verify_password(user: User, cookies: &CookieJar<'_>) -> () {
    cookies.add_private(Cookie::build("remembered_user", user.0)
        .permanent()
        .finish());
    ()
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
        .mount("/", routes![verify_password, authenticate])
}