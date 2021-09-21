use crate::cookie::Delta;
use crate::CONFIG;
use http::{
    header::{LOCATION, SET_COOKIE, WWW_AUTHENTICATE},
    response::Builder,
    StatusCode,
};
use warp::http::{Response, Result};

const AUTH_RESPONSE_BODY: &str = r#"<html>
<head><title>401 Authorization Required</title></head>
<body>
<center><h1>401 Authorization Required</h1></center>
</body>
</html>"#;

pub fn make_valid_response(user_id: &str) -> Result<Response<&'static str>> {
    Response::builder()
        .header(CONFIG.user_header.as_str(), user_id)
        .body("")
}

pub fn make_cookie_response(redirect_url: &str, cookies: Delta) -> Result<Response<&'static str>> {
    let mut response = Response::builder()
        .status(StatusCode::TEMPORARY_REDIRECT)
        .header(LOCATION, redirect_url);
    response = add_cookies(response, cookies);
    response.body("")
}

pub fn make_challenge_response(cookies: Option<Delta>) -> Result<Response<&'static str>> {
    let mut response = Response::builder().status(StatusCode::UNAUTHORIZED).header(
        WWW_AUTHENTICATE,
        format!("Basic realm=\"{}\"", &CONFIG.realm),
    );
    if let Some(cookies) = cookies {
        response = add_cookies(response, cookies);
    }
    response.body(AUTH_RESPONSE_BODY)
}

fn add_cookies(mut response: Builder, cookies: Delta) -> Builder {
    for set_cookie in cookies {
        response = response.header(SET_COOKIE, set_cookie.to_string());
    }
    response
}
