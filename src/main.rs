#[macro_use] extern crate rocket;
use rocket::figment::providers::Serialized;
use rocket::http::{Cookie, CookieJar};
use rocket::State;
use rocket::fairing::AdHoc;
use rocket::serde::Deserialize;
use rocket::serde::Serialize;
use htpasswd_verify::Htpasswd;

mod user;
use user::User;

mod auth_challenge;
use auth_challenge::AuthChallengeResponse;

#[derive(Debug, Deserialize, Serialize)]
#[serde(crate = "rocket::serde")]
struct AppConfig {
    realm: String,
    cookie_name: String,
    htpasswd_path: String,
    user_header: String,
}
impl Default for AppConfig {
    fn default() -> Self {
        AppConfig {
            realm: "Please sign in".to_string(),
            cookie_name: "_auth_remember_me".to_string(),
            htpasswd_path: ".htpasswd".to_string(),
            user_header: "x-user".to_string(),
        }
    }
}


#[get("/<_..>", rank = 1)]
fn verify_user(user: User, cookies: &CookieJar<'_>, app_config: &State<AppConfig>) -> User {
    if !user.from_cookie {
        cookies.add_private(Cookie::build(app_config.cookie_name.to_owned(), user.id.to_owned())
            .permanent()
            .finish());
    }
    user
}

#[get("/<_..>", rank = 2)]
fn authenticate(cookies: &CookieJar<'_>, app_config: &State<AppConfig>) -> AuthChallengeResponse {
    cookies.remove(Cookie::named(app_config.cookie_name.to_owned()));
    AuthChallengeResponse::new(app_config.realm.to_owned()) 
}

#[launch]
fn rocket() -> _ {
    let rocket = rocket::build();
    let figment = rocket.figment().clone()
        .join(Serialized::defaults(AppConfig::default()));
    let htpasswd_path_value = figment.find_value("htpasswd_path").expect("no config value for htpasswd_path");
    let htpasswd_path = htpasswd_path_value.as_str().expect("config value for htpasswd_path is invalid (not a string)");
    let htpasswd_contents = std::fs::read_to_string(htpasswd_path).expect("Could not read htpasswd file");
    let htpasswd = Htpasswd::new(htpasswd_contents);
    rocket
        .configure(figment)
        .attach(rocket::shield::Shield::new())
        .attach(AdHoc::config::<AppConfig>())
        .manage(htpasswd)
        .mount("/", routes![verify_user, authenticate])
}