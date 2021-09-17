#[macro_use]
extern crate lazy_static;

#[macro_use]
extern crate derivative;

use cookie::{Cookie, CookieJar};
use htpasswd_verify::Htpasswd;
use http::header::{AUTHORIZATION, COOKIE};
use http_auth_basic::Credentials;
use std::error::Error;
use std::{convert::Infallible, sync::Arc};
use tracing::info;
use warp::{Filter, Rejection};

mod config;
pub use crate::config::CONFIG;

fn cookie_jar() -> impl Filter<Extract = (CookieJar,), Error = Rejection> + Copy {
    warp::header::optional(COOKIE.as_str()).and_then(|cookie_header: Option<String>| {
        let mut jar = CookieJar::new();
        if let Some(cookies_raw) = cookie_header {
            let cookies = cookies_raw.split(';').filter_map(|cookie| {
                let cookie = cookie.to_owned();
                let mut cookie = cookie.splitn(2, '=');
                let key = cookie.next()?.trim();
                let val = cookie.next()?.trim();
                Some((key.to_owned(), val.to_owned()))
            });
            for (cookie_key, cookie_value) in cookies {
                jar.add_original(Cookie::new(cookie_key, cookie_value));
            }
        }
        std::future::ready(Ok::<_, Infallible>(jar))
    })
}

fn auth_header_exists() -> impl Filter<Extract = (Credentials,), Error = Rejection> + Copy {
    warp::header::header(AUTHORIZATION.as_str()).and_then(|auth_header: String| {
        std::future::ready(Credentials::from_header(auth_header).map_err(|auth_error| {
            info!(
                "Invalid authorization header, ignoring. {}",
                error = auth_error
            );
            warp::reject::not_found()
        }))
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
        .and_then(|credentials: Credentials, pass: Arc<Htpasswd>| {
            std::future::ready(if pass.check(&credentials.user_id, &credentials.password) {
                Ok(credentials.user_id)
            } else {
                Err(warp::reject::custom(InvalidUser))
            })
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
    let auth_route =
        auth_header_valid(htpasswd)
            .and(cookie_jar())
            .map(|auth, cookie: CookieJar| {
                let actual_cookie = cookie.get("_auth_remember_me");
                format!("{:#?} : {:#?}", auth, actual_cookie)
            });

    warp::serve(auth_route.with(warp::trace::request()))
        .run(CONFIG.listen)
        .await;
}
