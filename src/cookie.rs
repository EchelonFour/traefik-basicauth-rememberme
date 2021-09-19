pub use cookie::{Cookie, Delta, PrivateJar};
use http::header::COOKIE;
use std::borrow::Cow;
use std::convert::Infallible;
use warp::{Filter, Rejection};

use crate::config::CookieLifetime;
use crate::CONFIG;

pub struct CookieJar(cookie::CookieJar);

impl CookieJar {
    fn new() -> Self {
        CookieJar(cookie::CookieJar::new())
    }
    pub fn private(&'_ self) -> PrivateJar<&'_ cookie::CookieJar> {
        self.0.private(&CONFIG.secret.key)
    }
    pub fn private_mut(&'_ mut self) -> PrivateJar<&'_ mut cookie::CookieJar> {
        self.0.private_mut(&CONFIG.secret.key)
    }
}
impl std::ops::Deref for CookieJar {
    type Target = cookie::CookieJar;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl std::ops::DerefMut for CookieJar {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
pub fn cookie_jar() -> impl Filter<Extract = (CookieJar,), Error = Rejection> + Copy {
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
pub fn has_decrypted_cookie(
    cookie_name: &str,
) -> impl Filter<Extract = (Cookie,), Error = Rejection> + Copy {
    cookie_jar().and_then(move |jar: CookieJar| async move {
        let private_jar = jar.private();
        jar.get(cookie_name)
            .and_then(|cookie| private_jar.decrypt(cookie.clone()))
            .ok_or_else(warp::reject::not_found)
    })
}

pub fn make_auth_cookie<'c, V: Into<Cow<'c, str>>>(value: V) -> Cookie<'c> {
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
