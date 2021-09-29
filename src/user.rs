use crate::CONFIG;
use cookie::Cookie;
use http_auth_basic::Credentials;
use std::convert::TryFrom;

pub struct User {
    pub user_id: String,
    pub password: String,
    pub no_save: bool,
}

impl User {
    pub fn into_cookie_contents(self) -> String {
        format!("{}:{}", self.user_id, self.password)
    }
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
            no_save: false,
        })
    }
}

impl From<Credentials> for User {
    fn from(credentials: Credentials) -> Self {
        let mut no_save = false;
        let mut user_id = credentials.user_id.to_owned();
        if CONFIG.no_save_enabled {
            if let Some(real_user_id) = credentials.user_id.strip_suffix("-nosave") {
                no_save = true;
                user_id = real_user_id.to_string();
            }
        }
        User {
            user_id,
            password: credentials.password,
            no_save,
        }
    }
}

impl From<User> for Credentials {
    fn from(user: User) -> Self {
        Credentials::new(&user.user_id, &user.password)
    }
}
