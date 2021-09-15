use rocket::request::{FromRequest, Outcome, Request};
use rocket::outcome::{try_outcome, IntoOutcome};
use rocket::{Response, State, response};
use rocket::response::Responder;
use htpasswd_verify::Htpasswd;
use http::header::AUTHORIZATION;
use http_auth_basic::Credentials;

use crate::AppConfig;

pub struct User {
  pub id: String,
  pub from_cookie: bool,
  header_name: String,
}

fn get_cookie_user(request: &'_ Request<'_>, app_config: &State<AppConfig>) -> Option<User> {
  request.cookies()
      .get_private(&app_config.cookie_name)
      .and_then(|cookie| cookie.value().parse().ok())
      .map(|user| User { id: user, from_cookie: true, header_name: app_config.user_header.to_owned() })
}
fn get_auth_user(request: &'_ Request<'_>, htpasswd: &State<Htpasswd>, app_config: &State<AppConfig>) -> Option<User> {
  request.headers()
      .get_one(AUTHORIZATION.as_str())
      .and_then(|auth| Credentials::from_header(auth.to_string()).ok())
      .and_then(|credentials| if htpasswd.check(&credentials.user_id, &credentials.password) { Some(credentials.user_id) } else { None })
      .map(|valid_user| User { id: valid_user, from_cookie: false, header_name: app_config.user_header.to_owned() })
} 

#[rocket::async_trait]
impl<'r> FromRequest<'r> for User {
  type Error = ();

  async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
      let app_config: &State<AppConfig> = try_outcome!(request.guard::<&State<AppConfig>>().await);
      let htpasswd: &State<Htpasswd> = try_outcome!(request.guard::<&State<Htpasswd>>().await);
      get_cookie_user(request, app_config).or_else(|| get_auth_user(request, htpasswd, app_config)).or_forward(())
  }
}

#[rocket::async_trait]
impl<'r> Responder<'r, 'static> for User {
  fn respond_to(self, _: &'r Request<'_>) -> response::Result<'static> {
      Response::build()
          .raw_header(self.header_name, self.id)
          .ok()
  }
}