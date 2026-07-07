//! clean_config.rs — configuration + credential loader for a vehicle service.
//!
//! Negative control: secrets come from the environment, queries are
//! parameterised, external input is parsed with proper error handling (no
//! panics), and there is no unsafe code or shell execution.

use std::env;

pub struct Config {
    pub broker_host: String,
    pub broker_port: u16,
    pub api_token: String,
}

#[derive(Debug)]
pub enum ConfigError {
    Missing(&'static str),
    BadPort,
}

/// Load configuration from the environment, returning an error (never
/// panicking) when something required is absent or malformed.
pub fn load() -> Result<Config, ConfigError> {
    let broker_host = env::var("BROKER_HOST").map_err(|_| ConfigError::Missing("BROKER_HOST"))?;
    let port_str = env::var("BROKER_PORT").map_err(|_| ConfigError::Missing("BROKER_PORT"))?;
    let broker_port: u16 = port_str.parse().map_err(|_| ConfigError::BadPort)?;
    let api_token = env::var("FLEET_API_TOKEN").map_err(|_| ConfigError::Missing("FLEET_API_TOKEN"))?;

    Ok(Config { broker_host, broker_port, api_token })
}

/// A minimal parameter-binding query interface (no string interpolation).
pub trait BoundQuery {
    fn execute(&self, sql: &str, params: &[&str]) -> Vec<String>;
}

/// Look up a vehicle by VIN using a bound parameter.
pub fn get_vehicle(db: &dyn BoundQuery, vin: &str) -> Vec<String> {
    db.execute("SELECT * FROM vehicles WHERE vin = ?1", &[vin])
}

/// Clamp a client-provided limit into a safe range without panicking.
pub fn parse_limit(raw: &str) -> usize {
    match raw.parse::<usize>() {
        Ok(v) => v.min(1000),
        Err(_) => 100,
    }
}

/// Constant-time equality for secret comparison.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut acc = 0u8;
    for i in 0..a.len() {
        acc |= a[i] ^ b[i];
    }
    acc == 0
}
