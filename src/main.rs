#[macro_use]
extern crate lazy_static;

#[macro_use]
extern crate derivative;

mod authentication;
mod config;
mod cookie;
mod response;
mod user;

pub use crate::config::CONFIG;
use crate::cookie::{cookie_jar, has_decrypted_cookie, make_auth_cookie, Cookie, CookieJar};
use authentication::auth_header_exists;
use std::convert::{Infallible, TryInto};
use std::error::Error;
use user::User;
use warp::{Filter, Rejection};

async fn validate_credentials(credentials: User) -> Result<User, Rejection> {
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

#[tokio::main]
async fn main() {
    setup_logging();
    let cookie_route = has_decrypted_cookie(&CONFIG.cookie_name)
        .and_then(|cookie: Cookie| {
            std::future::ready(cookie.try_into().map_err(|_| warp::reject::not_found()))
        })
        .and_then(validate_credentials)
        .map(|user: User| response::make_valid_response(&user.user_id, None));
    let auth_route = auth_header_exists()
        .and_then(validate_credentials)
        .and(cookie_jar())
        .map(|user: User, mut jar: CookieJar| {
            let mut private_jar = jar.private_mut();
            let user_id = user.user_id.to_owned();
            private_jar.add(user.into());
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
