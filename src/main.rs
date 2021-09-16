use std::convert::Infallible;
use std::error::Error;
use http_auth_basic::Credentials;
use tracing::info;
use warp::{Filter, Rejection};
use cookie::{Cookie, CookieJar};
use http::header::{AUTHORIZATION, COOKIE};

mod config;
use crate::config::AppConfig;

fn cookie_jar() -> impl Filter<Extract = (CookieJar,), Error = Rejection> + Copy {
  warp::header::optional(COOKIE.as_str()).and_then(|cookie_header: Option<String>| {
    let mut jar = CookieJar::new();
    if let Some(cookies_raw) = cookie_header {
      let cookies = cookies_raw.split(';')
        .filter_map(|cookie| {
          let cookie = cookie.to_owned();
          let mut cookie = cookie.splitn(2, "=");
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

fn auth_header() -> impl Filter<Extract = (Option<Credentials>,), Error = Rejection> + Copy {
  warp::header::optional(AUTHORIZATION.as_str())
    .and_then(|auth_header: Option<String>| {
      std::future::ready(match auth_header.map(Credentials::from_header) {
        Some(parsed_header) => match parsed_header {
          Ok(good_parsed_header) => Ok::<_, Rejection>(Some(good_parsed_header)),
          Err(_error) => Ok::<_, Rejection>(None),
        },
        None => Ok::<_, Rejection>(None),
      })
    })
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::fmt()
      .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env()
        .or_else(|error| {
          if Some(&std::env::VarError::NotPresent) != error.source().unwrap().downcast_ref::<std::env::VarError>() {
            println!("Could not parse log options, defaulting ({})", error);
          }
          tracing_subscriber::EnvFilter::try_new("info")
        })
        .expect("Could not set up log filter correctly"))
      .init();
    let config = AppConfig::new().expect("Could not load config");
    let auth_route = auth_header().and(cookie_jar())
    .map(|auth, cookie: CookieJar| {
      let actual_cookie = cookie.get("_auth_remember_me");
      format!("{:#?} : {:#?}", auth, actual_cookie)
    });

    warp::serve(auth_route.with(warp::log("auth"))).run(config.listen).await;
}