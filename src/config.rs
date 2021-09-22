use config::{Config, ConfigError, Environment, File};
use cookie::Key;
use htpasswd_verify::Htpasswd;
use serde::Deserialize;
use std::{convert::TryInto, env, net::SocketAddr};
use tracing::warn;

lazy_static! {
    pub static ref CONFIG: AppConfig = AppConfig::new().expect("Could not load config");
}

#[derive(Derivative)]
#[derivative(Debug)]
pub struct Secret {
    #[derivative(Debug = "ignore")]
    pub key: Key,
    default: bool,
}

#[derive(Debug)]
pub enum CookieLifetime {
    Permanent,
    Limited(time::Duration),
    Session,
}

#[derive(Derivative, Deserialize)]
#[derivative(Debug)]
#[serde(default)]
pub struct AppConfig {
    pub realm: String,
    pub cookie_name: String,
    pub cookie_domain: Option<String>,
    pub cookie_lifetime: CookieLifetime,
    pub htpasswd_path: String,
    pub user_header: String,
    pub listen: SocketAddr,
    pub secret: Secret,
    pub htpasswd_contents: Option<String>,
    #[serde(skip)]
    #[derivative(Debug = "ignore")]
    pub htpasswd: Htpasswd,
}

impl Default for AppConfig {
    fn default() -> Self {
        AppConfig {
            realm: "Please sign in".to_string(),
            cookie_name: "_auth_remember_me".to_string(),
            cookie_domain: None,
            cookie_lifetime: CookieLifetime::Permanent,
            htpasswd_path: ".htpasswd".to_string(),
            user_header: "x-user".to_string(),
            listen: ([0, 0, 0, 0], 80).into(),
            secret: Secret {
                key: cookie::Key::generate(),
                default: true,
            },
            htpasswd_contents: None,
            htpasswd: Htpasswd::new(""),
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

        let mut parsed_config: AppConfig = c.try_into()?;

        if parsed_config.secret.default {
            warn!("Using randomly generated secret. Be sure to set a 32 byte, base64 string in the settings.")
        }
        parsed_config.htpasswd = Htpasswd::new(
            if let Some(htpasswd_contents) = &parsed_config.htpasswd_contents {
                htpasswd_contents.to_owned().replace(",", "\n")
            } else {
                std::fs::read_to_string(&parsed_config.htpasswd_path).map_err(|io_error| {
                    ConfigError::Message(format!("failed to read htpasswd file {}. {}", &parsed_config.htpasswd_path, io_error))
                })?
            },
        );
        Ok(parsed_config)
    }
}

impl<'de> Deserialize<'de> for Secret {
    fn deserialize<D: serde::de::Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        use base64::decode;
        let secret_base64 = String::deserialize(de)?;
        let secret_bytes = decode(secret_base64).map_err(|error| {
            serde::de::Error::custom(format!("failed to parse base64 {}", error))
        })?;
        if secret_bytes.len() < 32 {
            return Err(serde::de::Error::invalid_length(
                secret_bytes.len(),
                &"more than 32 bytes",
            ));
        }
        Ok(Secret {
            key: Key::derive_from(&secret_bytes),
            default: false,
        })
    }
}
impl<'de> Deserialize<'de> for CookieLifetime {
    fn deserialize<D: serde::de::Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        let value = String::deserialize(de)?.to_lowercase();

        Ok(match value.as_str() {
            "permanent" => CookieLifetime::Permanent,
            "session" => CookieLifetime::Session,
            limited => CookieLifetime::Limited(
                humantime::parse_duration(limited)
                    .map_err(|error| {
                        serde::de::Error::custom(format!(
                            "failed to parse limited duration {}",
                            error
                        ))
                    })?
                    .try_into()
                    .map_err(|error| {
                        serde::de::Error::custom(format!(
                            "failed to parse limited duration {}",
                            error
                        ))
                    })?,
            ),
        })
    }
}
