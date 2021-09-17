use std::{env, net::SocketAddr};
use config::{ConfigError, Config, File, Environment};
use cookie::Key;
use serde::Deserialize;
use tracing::warn;

lazy_static! {
    pub static ref CONFIG: AppConfig = AppConfig::new().expect("Could not load config");
}

#[derive(Derivative)]
#[derivative(Debug)]
pub struct Secret {
    #[derivative(Debug="ignore")]
    pub inner: Key,
    default: bool,
}

#[derive(Debug, Deserialize)]
#[serde(default)]
pub struct AppConfig {
    pub realm: String,
    pub cookie_name: String,
    pub htpasswd_path: String,
    pub user_header: String,
    pub listen: SocketAddr,
    pub secret: Secret,
}

impl Default for AppConfig {
    fn default() -> Self {
        AppConfig {
            realm: "Please sign in".to_string(),
            cookie_name: "_auth_remember_me".to_string(),
            htpasswd_path: ".htpasswd".to_string(),
            user_header: "x-user".to_string(),
            listen: ([0, 0, 0, 0], 8000).into(),
            secret: Secret { inner: cookie::Key::generate(), default: true },
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

      let final_config = c.try_into();
      if Some(true) == final_config.as_ref().map(|x: &AppConfig| x.secret.default).ok() {
          warn!("Using randomly generated secret. Be sure to set a 32 byte, base64 string in the settings.")
      }
      final_config
  }
}

impl<'de> Deserialize<'de> for Secret {
    fn deserialize<D: serde::de::Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        use base64::decode;
        let secret_base64 = String::deserialize(de)?;
        let secret_bytes = decode(secret_base64)
            .map_err(|error| serde::de::Error::custom(format!("failed to parse base64 {}", error)))?;
        if secret_bytes.len() < 32 {
            return Err(serde::de::Error::invalid_length(secret_bytes.len(), &"more than 32 bytes"));
        }
        Ok(Secret {
            inner: Key::derive_from(&secret_bytes),
            default: false,
        })
    }
}