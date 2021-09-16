use std::{env, net::SocketAddr};
use config::{ConfigError, Config, File, Environment};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(default)]
pub struct AppConfig {
    pub realm: String,
    pub cookie_name: String,
    pub htpasswd_path: String,
    pub user_header: String,
    pub listen: SocketAddr,
}
impl Default for AppConfig {
    fn default() -> Self {
        AppConfig {
            realm: "Please sign in".to_string(),
            cookie_name: "_auth_remember_me".to_string(),
            htpasswd_path: ".htpasswd".to_string(),
            user_header: "x-user".to_string(),
            listen: ([0, 0, 0, 0], 8000).into(),
        }
    }
}

impl AppConfig {
  pub fn new() -> Result<Self, ConfigError> {
      let mut c = Config::default();

      c.merge(File::with_name("config/default").required(false))?;

      let env = env::var("RUN_MODE").unwrap_or_else(|_| "development".into());
      c.merge(File::with_name(&format!("config/{}", env)).required(false))?;

      c.merge(File::with_name("config/local").required(false))?;

      c.merge(Environment::with_prefix("app"))?;

      c.try_into()
  }
}