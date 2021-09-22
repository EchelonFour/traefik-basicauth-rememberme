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
use tracing::error;
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
                    tracing_subscriber::EnvFilter::try_new("warn")
                })
                .expect("Could not set up log filter correctly"),
        )
        .init();
}

fn get_original_request_url()  -> impl Filter<Extract = (String,), Error = Rejection> + Copy {
    warp::header("x-forwarded-proto")
        .and(warp::header("x-forwarded-host"))
        .and(warp::header("x-forwarded-port"))
        .and(warp::header("x-forwarded-uri"))
        .and_then(|proto: String, host: String, port: String, uri: String| {
            std::future::ready(Ok::<_, Rejection>(format!("{}://{}:{}{}", proto, host, port, uri)))
        })
}
fn is_secure_request()  -> impl Filter<Extract = (bool,), Error = Rejection> + Copy {
    warp::header("x-forwarded-proto")
        .and_then(|proto: String| {
            std::future::ready(Ok::<_, Rejection>(proto == "https"))
        })
}
#[tokio::main]
async fn main() {
    setup_logging();
    let cookie_route = has_decrypted_cookie(&CONFIG.cookie_name)
        .and_then(|cookie: Cookie| {
            std::future::ready(cookie.try_into().map_err(|_| warp::reject::not_found()))
        })
        .and_then(validate_credentials)
        .map(|user: User| response::make_valid_response(&user.user_id));
    let auth_route = get_original_request_url()
        .and(auth_header_exists().and_then(validate_credentials))
        .and(cookie_jar())
        .and(is_secure_request())
        .map(|original_url: String, user: User, mut jar: CookieJar, is_secure: bool| {
            let mut private_jar = jar.private_mut();
            let mut cookie: Cookie = user.into();
            cookie.set_secure(is_secure);
            private_jar.add(cookie);
            response::make_cookie_response(&original_url, jar.delta())
        });
    let unauthorised = cookie_jar().and(is_secure_request()).map(|mut jar: CookieJar, is_secure: bool| {
        if None != jar.get(&CONFIG.cookie_name) {
            jar.remove(make_auth_cookie("", is_secure));
        }
        response::make_challenge_response(Some(jar.delta()))
    });

    warp::serve(
        cookie_route
            .or(auth_route)
            .or(unauthorised)
            .recover(|error| async move {
                error!("Issue validating user. {:?}", error);
                Ok::<_, Infallible>(warp::reply::with_header(
                    response::make_challenge_response(None),
                    "x-error-message",
                    format!("{:?}", error),
                ))
            })
            .with(warp::trace(|info| {
                use tracing::field::{display, Empty};
                let span = tracing::info_span!(
                    "request",
                    remote.addr = Empty,
                    method = %info.method(),
                    path = %info.path(),
                    version = ?info.version(),
                    referer = Empty,
                );
        
                // Record optional fields.
                if let Some(remote_addr) = info.remote_addr() {
                    span.record("remote.addr", &display(remote_addr));
                }
        
                if let Some(referer) = info.referer() {
                    span.record("referer", &display(referer));
                }
                tracing::debug!(parent: &span, "received request");
                tracing::debug!(parent: &span, headers = ?info.request_headers(), "headers");
                span
            })),
    )
    .run(CONFIG.listen)
    .await;
}
