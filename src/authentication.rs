use http::header::AUTHORIZATION;
use http_auth_basic::Credentials;
use tracing::info;
use warp::{Filter, Rejection};

use crate::user::User;

pub fn auth_header_exists() -> impl Filter<Extract = (User,), Error = Rejection> + Copy {
    warp::header::header(AUTHORIZATION.as_str()).and_then(|auth_header: String| async {
        Credentials::from_header(auth_header)
            .map(|creds| creds.into())
            .map_err(|auth_error| {
                info!(
                    "Invalid authorization header, ignoring. {}",
                    error = auth_error
                );
                warp::reject::not_found()
            })
    })
}
