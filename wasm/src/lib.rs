use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2, Params,
};
use wasm_bindgen::prelude::*;
use log::error;
use serde::{Serialize, Deserialize};
use thiserror::Error;
use js_sys::Object;

/// Custom error type for password hashing and verification operations
#[derive(Error, Debug)]
pub enum PasswordError {
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_wasm_bindgen::Error),
    #[error("Invalid hash parameters: {0}")]
    InvalidParams(String),
    #[error("Invalid password or hash: {0}")]
    InvalidInput(String),
}

// Convert PasswordError to a JavaScript object with { message: String }
impl From<PasswordError> for JsValue {
    fn from(err: PasswordError) -> Self {
        let obj = Object::new();
        let message = err.to_string();
        js_sys::Reflect::set(
            &obj,
            &JsValue::from_str("message"),
            &JsValue::from_str(&message),
        ).expect("Failed to set error message");
        obj.into()
    }
}

// Implement conversion from argon2::Error to PasswordError
impl From<argon2::Error> for PasswordError {
    fn from(err: argon2::Error) -> Self {
        PasswordError::InvalidParams(err.to_string())
    }
}

/// Options for configuring Argon2 hashing
#[derive(Serialize, Deserialize)]
pub struct HashOptions {
    pub time_cost: u32,
    pub memory_cost: u32,
    pub parallelism: u32,
}

/// Request struct for password verification
#[derive(Serialize, Deserialize)]
pub struct VerifyRequest {
    pub hash: String,
    pub password: String,
}

/// Hashes a password using Argon2id with optional configuration
#[wasm_bindgen]
pub fn hash(password: &str, options: JsValue) -> Result<String, JsValue> {
    // Input validation
    if password.is_empty() {
        return Err(PasswordError::InvalidInput("Password cannot be empty".to_string()).into());
    }

    let opts: Option<HashOptions> = serde_wasm_bindgen::from_value(options)
        .map_err(|err| {
            error!("Failed to deserialize options: {}", err);
            PasswordError::Serialization(err)
        })?;

    argon2id_hash(password, opts).map_err(|err| {
        error!("Failed to hash password: {}", err);
        err.into()
    })
}

/// Verifies a password against a stored hash
#[wasm_bindgen]
pub fn verify(hash: &str, password: &str) -> Result<bool, JsValue> {
    // Input validation
    if hash.is_empty() || password.is_empty() {
        return Err(PasswordError::InvalidInput("Hash and password cannot be empty".to_string()).into());
    }

    let options = VerifyRequest {
        hash: hash.to_string(),
        password: password.to_string(),
    };

    argon2id_verify(&options).map_err(|err| {
        error!("Failed to verify password: {}", err);
        err.into()
    })
}

/// Internal function to hash a password with Argon2id
fn argon2id_hash(password: &str, options: Option<HashOptions>) -> Result<String, PasswordError> {
    let salt = SaltString::generate(&mut OsRng);

    let argon2 = match options {
        Some(opts) => {
            // Validate parameters to prevent invalid configurations
            if opts.memory_cost < 8 || opts.time_cost == 0 || opts.parallelism == 0 {
                return Err(PasswordError::InvalidInput(
                    "Invalid hash parameters: memory_cost must be >= 8, time_cost and parallelism must be > 0".to_string(),
                ));
            }

            let params = Params::new(
                opts.memory_cost,
                opts.time_cost,
                opts.parallelism,
                None,
            )?;

            Argon2::new(
                argon2::Algorithm::Argon2id,
                argon2::Version::V0x13,
                params,
            )
        }
        None => Argon2::default(),
    };

    argon2
        .hash_password(password.as_bytes(), &salt)
        .map(|password_hash| password_hash.to_string())
        .map_err(|err| PasswordError::InvalidParams(err.to_string()))
}

/// Internal function to verify a password against a hash
fn argon2id_verify(options: &VerifyRequest) -> Result<bool, PasswordError> {
    let password_hash = PasswordHash::new(&options.hash)
        .map_err(|err| PasswordError::InvalidParams(err.to_string()))?;

    Argon2::default()
        .verify_password(options.password.as_bytes(), &password_hash)
        .map(|_| true)
        .or_else(|err| match err {
            argon2::password_hash::Error::Password => Ok(false),
            _ => Err(PasswordError::InvalidParams(err.to_string())),
        })
}
