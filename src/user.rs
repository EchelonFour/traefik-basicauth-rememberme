use crate::cookie::make_auth_cookie;
use cookie::Cookie;
use http_auth_basic::Credentials;
use std::convert::TryFrom;

pub struct User {
    pub user_id: String,
    pub password: String,
}
impl<'c> TryFrom<Cookie<'c>> for User {
    type Error = &'static str;
    fn try_from(cookie: Cookie<'c>) -> Result<Self, Self::Error> {
        let cookie_value = cookie.value().to_owned();
        let mut split_cookie = cookie_value.splitn(2, ':');
        let user_id = split_cookie.next().ok_or("invalid cookie")?;
        let password = split_cookie.next().ok_or("invalid cookie")?;
        Ok(User {
            user_id: user_id.to_string(),
            password: password.to_string(),
        })
    }
}

impl<'c> From<User> for Cookie<'c> {
    fn from(user: User) -> Self {
        make_auth_cookie(format!("{}:{}", user.user_id, user.password), false)
    }
}

impl From<Credentials> for User {
    fn from(credentials: Credentials) -> Self {
        User {
            user_id: credentials.user_id,
            password: credentials.password,
        }
    }
}

impl From<User> for Credentials {
    fn from(user: User) -> Self {
        Credentials::new(&user.user_id, &user.password)
    }
}
