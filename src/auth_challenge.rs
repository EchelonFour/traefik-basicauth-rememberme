use http::header::{WWW_AUTHENTICATE, SET_COOKIE};
use warp::http::{Response, Result};
use crate::CONFIG;

const AUTH_RESPONSE_BODY: &str = r#"<html>
<head><title>401 Authorization Required</title></head>
<body>
<center><h1>401 Authorization Required</h1></center>
</body>
</html>"#;

pub fn make_challenge_response(cookies: Option<cookie::Delta>) -> Result<Response<&'static str>> {
    let mut response = Response::builder().header(WWW_AUTHENTICATE, format!("Basic realm=\"{}\"", &CONFIG.realm));
    if let Some(cookies_real) = cookies {
        for set_cookie in cookies_real {
            response = response.header(SET_COOKIE, set_cookie.to_string());
        }
    }
    response.body(AUTH_RESPONSE_BODY)
}