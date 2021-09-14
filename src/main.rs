#[macro_use] extern crate rocket;
use rocket::http::{Cookie, CookieJar};
use htpasswd_verify::Htpasswd;

mod user;
use user::User;

mod auth_challenge;
use auth_challenge::AuthChallengeResponse;

#[get("/<_..>", rank = 1)]
fn verify_user(user: User, cookies: &CookieJar<'_>) -> User {
    if !user.from_cookie {
        cookies.add_private(Cookie::build("remembered_user", user.id.clone())
            .permanent()
            .finish());
    }
    user
}



#[get("/<_..>", rank = 2)]
fn authenticate(cookies: &CookieJar<'_>) -> AuthChallengeResponse {
    cookies.remove(Cookie::named("remembered_user"));
    AuthChallengeResponse::new("Hey, are you cool?".into()) 
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