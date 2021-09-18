#[macro_use]
extern crate lazy_static;

#[macro_use]
extern crate derivative;

use cookie::{Cookie, CookieJar};
use htpasswd_verify::Htpasswd;
use http::header::{AUTHORIZATION, COOKIE, SET_COOKIE};
use http_auth_basic::Credentials;
use warp::http::Response;
use std::error::Error;
use std::{convert::Infallible, sync::Arc};
use tracing::info;
use warp::{Filter, Rejection};

mod config;
pub use crate::config::CONFIG;

fn cookie_jar() -> impl Filter<Extract = (CookieJar,), Error = Rejection> + Copy {
    warp::header::optional(COOKIE.as_str()).and_then(|cookie_header: Option<String>| async {
        let mut jar = CookieJar::new();
        if let Some(cookies_raw) = cookie_header {
            cookies_raw
                .split(';')
                .filter_map(|cookie| Cookie::parse(cookie.to_owned()).ok())
                .for_each(|cookie| jar.add_original(cookie));
        }
        Ok::<_, Infallible>(jar)
    })
}
fn valid_cookie() -> impl Filter<Extract = (String,), Error = Rejection> + Copy {
    cookie_jar().and_then(|jar: CookieJar| async move {
        let private_jar = jar.private(&CONFIG.secret.key);
        jar.get(&CONFIG.cookie_name)
            .and_then(|cookie| private_jar.decrypt(cookie.clone()))
            .map(|cookie| cookie.value().to_string())
            .ok_or_else(warp::reject::not_found)
    })
}

fn auth_header_exists() -> impl Filter<Extract = (Credentials,), Error = Rejection> + Copy {
    warp::header::header(AUTHORIZATION.as_str()).and_then(|auth_header: String| async {
        Credentials::from_header(auth_header).map_err(|auth_error| {
            info!(
                "Invalid authorization header, ignoring. {}",
                error = auth_error
            );
            warp::reject::not_found()
        })
    })
}
#[derive(Debug)]
struct InvalidUser;

impl warp::reject::Reject for InvalidUser {}

fn auth_header_valid(
    htpasswd: Arc<Htpasswd>,
) -> impl Filter<Extract = (String,), Error = Rejection> + Clone {
    auth_header_exists()
        .and(warp::any().map(move || htpasswd.clone()))
        .and_then(|credentials: Credentials, pass: Arc<Htpasswd>| async move {
            if pass.check(&credentials.user_id, &credentials.password) {
                Ok(credentials.user_id)
            } else {
                Err(warp::reject::custom(InvalidUser))
            }
        })
}

fn setup_logging() {
    tracing_subscriber::fmt::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .or_else(|error| {
                    if Some(&std::env::VarError::NotPresent)
                        != error.source().unwrap().downcast_ref::<std::env::VarError>()
                    {
                        println!("Could not parse log options, defaulting ({})", error);
                    }
                    tracing_subscriber::EnvFilter::try_new("info")
                })
                .expect("Could not set up log filter correctly"),
        )
        .init();
}

#[tokio::main]
async fn main() {
    setup_logging();
    let htpasswd_contents = std::fs::read_to_string(&CONFIG.htpasswd_path)
        .expect("Could not read htpasswd file");
    let htpasswd = Arc::new(Htpasswd::new(htpasswd_contents));
    let cookie_route = valid_cookie().map(|user| {
        Response::builder()
            .header(CONFIG.user_header.as_str(), user)
            .body("")

    });
    let auth_route =
        auth_header_valid(htpasswd)
            .and(cookie_jar())
            .map(|auth: String, mut jar: CookieJar| {
                let mut private_jar = jar.private_mut(&CONFIG.secret.key);
                private_jar.add(Cookie::build(CONFIG.cookie_name.to_owned(), auth.to_owned()).finish());
                let mut cookie_delta = jar.delta();
                
                Response::builder()
                    .header(CONFIG.user_header.as_str(), auth)
                    .header(SET_COOKIE, cookie_delta.next().unwrap().to_string())
                    .body("")
            });

    warp::serve(cookie_route.or(auth_route).with(warp::trace::request()))
        .run(CONFIG.listen)
        .await;
}
