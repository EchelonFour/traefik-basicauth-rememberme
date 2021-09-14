#[macro_use] extern crate rocket;
use rocket::http::Header;
use rocket::response::content::Html;

struct WWWAuthenticate {
    realm: String
}

impl From<WWWAuthenticate> for Header<'static> {
    fn from(www_authenticate: WWWAuthenticate) -> Self {
        Header::new("WWW-Authenticate", format!("Basic realm=\"{}\"", www_authenticate.realm))
    }
}

#[derive(Responder)]
#[response(status = 401)]
struct AuthChallengeResponse {
    inner: Html<&'static str>,
    header: WWWAuthenticate
}
#[get("/<_..>")]
fn authenticate() -> AuthChallengeResponse {
    AuthChallengeResponse {
        inner: Html("<wow></wow>"),
        header: WWWAuthenticate { realm: "Hey, are you cool?".to_string()}
    }
}

#[launch]
fn rocket() -> _ {
    let data = "user:$apr1$lZL6V/ci$eIMz/iKDkbtys/uU7LEK00";
    let htpasswd = htpasswd_verify::Htpasswd::new(data);
    rocket::build()
        .attach(rocket::shield::Shield::new())
        .manage(htpasswd)
        .mount("/", routes![authenticate])
}