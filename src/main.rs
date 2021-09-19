#[macro_use]
extern crate lazy_static;

#[macro_use]
extern crate derivative;

use cookie::{Cookie, CookieJar};
use http::header::{AUTHORIZATION, COOKIE};
use http_auth_basic::Credentials;
use std::convert::Infallible;
use std::{borrow::Cow, error::Error};
use tracing::info;
use warp::{Filter, Rejection};

mod config;
use crate::config::CookieLifetime;
pub use crate::config::CONFIG;

mod response;

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
fn valid_cookie() -> impl Filter<Extract = (Credentials,), Error = Rejection> + Copy {
    cookie_jar().and_then(|jar: CookieJar| async move {
        let private_jar = jar.private(&CONFIG.secret.key);
        jar.get(&CONFIG.cookie_name)
            .and_then(|cookie| private_jar.decrypt(cookie.clone()))
            .and_then(make_credentials_from_cookie)
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

async fn validate_credentials(credentials: Credentials) -> Result<Credentials, Rejection> {
    if CONFIG
        .htpasswd
        .check(&credentials.user_id, &credentials.password)
    {
        Ok(credentials)
    } else {
        Err(warp::reject::not_found())
    }
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

fn make_auth_cookie_from_credentials<'c>(credentials: Credentials) -> Cookie<'c> {
    make_auth_cookie(format!("{}:{}", credentials.user_id, credentials.password))
}

fn make_credentials_from_cookie(cookie: Cookie<'_>) -> Option<Credentials> {
    let mut split_cookie = cookie.value().splitn(2, ':');
    let user_id = split_cookie.next()?;
    let password = split_cookie.next()?;
    Some(Credentials::new(user_id, password))
}

#[tokio::main]
async fn main() {
    setup_logging();

    let cookie_route = valid_cookie()
        .and_then(validate_credentials)
        .map(|auth: Credentials| response::make_valid_response(&auth.user_id, None));
    let auth_route = auth_header_exists()
        .and_then(validate_credentials)
        .and(cookie_jar())
        .map(|auth: Credentials, mut jar: CookieJar| {
            let mut private_jar = jar.private_mut(&CONFIG.secret.key);
            let user_id = auth.user_id.to_owned();
            let cookie = make_auth_cookie_from_credentials(auth);
            private_jar.add(cookie);
            response::make_valid_response(&user_id, Some(jar.delta()))
        });
    let unauthorised = cookie_jar().map(|mut jar: CookieJar| {
        if None != jar.get(&CONFIG.cookie_name) {
            jar.remove(make_auth_cookie(""));
        }
        response::make_challenge_response(Some(jar.delta()))
    });

    warp::serve(
        cookie_route
            .or(auth_route)
            .or(unauthorised)
            .recover(|error| async move {
                Ok::<_, Infallible>(warp::reply::with_header(
                    response::make_challenge_response(None),
                    "x-error-message",
                    format!("{:?}", error),
                ))
            })
            .with(warp::trace::request()),
    )
    .run(CONFIG.listen)
    .await;
}
