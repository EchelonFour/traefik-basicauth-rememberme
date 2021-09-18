#[macro_use]
extern crate lazy_static;

#[macro_use]
extern crate derivative;

use cookie::{Cookie, CookieJar};
use http::header::{AUTHORIZATION, COOKIE, SET_COOKIE};
use http_auth_basic::Credentials;
use std::convert::Infallible;
use std::{borrow::Cow, error::Error};
use tracing::info;
use warp::http::Response;
use warp::{Filter, Rejection};

mod config;
use crate::config::CookieLifetime;
pub use crate::config::CONFIG;

mod auth_challenge;

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

fn auth_header_valid() -> impl Filter<Extract = (String,), Error = Rejection> + Copy {
    auth_header_exists().and_then(|credentials: Credentials| async move {
        if CONFIG
            .htpasswd
            .check(&credentials.user_id, &credentials.password)
        {
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

fn make_auth_cookie<'c, V: Into<Cow<'c, str>>>(value: V) -> Cookie<'c> {
    let mut builder = Cookie::build(CONFIG.cookie_name.to_owned(), value);
    builder = match &CONFIG.cookie_lifetime {
        CookieLifetime::Permanent => builder.permanent(),
        CookieLifetime::Session => builder.expires(cookie::Expiration::Session),
        CookieLifetime::Limited(duration) => builder.max_age(duration.to_owned()),
    };
    if let Some(cookie_domain) = &CONFIG.cookie_domain {
        builder = builder.domain(cookie_domain.to_owned());
    }
    builder.finish()
}

#[tokio::main]
async fn main() {
    setup_logging();

    let cookie_route = valid_cookie().map(|user| {
        Response::builder()
            .header(CONFIG.user_header.as_str(), user)
            .body("")
    });
    let auth_route =
        auth_header_valid()
            .and(cookie_jar())
            .map(|auth: String, mut jar: CookieJar| {
                let mut private_jar = jar.private_mut(&CONFIG.secret.key);
                let cookie = make_auth_cookie(auth.to_owned());
                private_jar.add(cookie);

                let mut response = Response::builder().header(CONFIG.user_header.as_str(), auth);
                for set_cookie in jar.delta() {
                    response = response.header(SET_COOKIE, set_cookie.to_string());
                }
                response.body("")
            });
    let unauthorised = cookie_jar().map(|mut jar: CookieJar| {
        if None != jar.get(&CONFIG.cookie_name) {
            jar.remove(make_auth_cookie(""));
        }
        auth_challenge::make_challenge_response(Some(jar.delta()))
    });

    warp::serve(
        cookie_route
            .or(auth_route)
            .or(unauthorised)
            .recover(|error| async move {
                Ok::<_, Infallible>(warp::reply::with_header(
                    auth_challenge::make_challenge_response(None),
                    "x-error-message",
                    format!("{:?}", error),
                ))
            })
            .with(warp::trace::request()),
    )
    .run(CONFIG.listen)
    .await;
}
