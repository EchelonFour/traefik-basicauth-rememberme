use http::header::WWW_AUTHENTICATE;
use rocket::{http::Header, response::content::Html};

const AUTH_RESPONSE_BODY: &str = r#"<html>
<head><title>401 Authorization Required</title></head>
<body>
<center><h1>401 Authorization Required</h1></center>
</body>
</html>"#;
struct WWWAuthenticate {
  realm: String
}

impl From<WWWAuthenticate> for Header<'static> {
  fn from(www_authenticate: WWWAuthenticate) -> Self {
      Header::new(WWW_AUTHENTICATE.as_str(), format!("Basic realm=\"{}\"", www_authenticate.realm))
  }
}

#[derive(Responder)]
#[response(status = 401)]
pub struct AuthChallengeResponse {
    inner: Html<&'static str>,
    header: WWWAuthenticate
}

impl AuthChallengeResponse {
    pub fn new(realm: String) -> Self { Self { inner: Html(AUTH_RESPONSE_BODY), header: WWWAuthenticate { realm } } }
}