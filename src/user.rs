use rocket::request::{FromRequest, Outcome, Request};
use rocket::outcome::{try_outcome, IntoOutcome};
use rocket::{Response, State, response};
use rocket::response::Responder;
use htpasswd_verify::Htpasswd;
use http::header::AUTHORIZATION;
use http_auth_basic::Credentials;

pub struct User {
  pub id: String,
  pub from_cookie: bool,
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
      .and_then(|credentials| if htpasswd.check(&credentials.user_id, &credentials.password) { Some(credentials.user_id) } else { None })
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

#[rocket::async_trait]
impl<'r> Responder<'r, 'static> for User {
  fn respond_to(self, _: &'r Request<'_>) -> response::Result<'static> {
      Response::build()
          .raw_header("x-user", self.id)
          .ok()
  }
}