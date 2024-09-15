use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2, Params,
};
use wasm_bindgen::prelude::*;
use log::error;
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize)]
pub struct HashOptions {
    pub time_cost: u32,
    pub memory_cost: u32,
    pub parallelism: u32,
}

pub struct VerifyRequest {
    pub hash: String,
    pub password: String,
}

#[wasm_bindgen]
pub fn hash(password: &str, options: JsValue) -> Result<String, JsValue> {
    let opts: Option<HashOptions> = serde_wasm_bindgen::from_value(options).map_err(|err| {
        error!("Failed to deserialize options: {}", err);
        JsValue::from_str(&err.to_string())
    })?;
    argon2id_hash(password, opts).map_err(|err| {
        error!("Failed to hash password: {}", err);
        JsValue::from_str(&err)
    })
}

#[wasm_bindgen]
pub fn verify(hash: &str, password: &str) -> Result<bool, JsValue> {
    let options = VerifyRequest {
        hash: hash.to_string(),
        password: password.to_string()
    };
    argon2id_verify(&options).map_err(|err| {
        error!("Failed to verify password: {}", err);
        JsValue::from_str(&err)
    })
}

fn argon2id_hash(password: &str, options: Option<HashOptions>) -> Result<String, String> {
    let salt = SaltString::generate(&mut OsRng);

    let argon2 = match options {
        Some(opts) => {
            let params = Params::new(opts.memory_cost, opts.time_cost, opts.parallelism, None)
                .map_err(|err| {
                    error!("Invalid hash options: {}", err);
                    err.to_string()
                })?;

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
        .map_err(|err| {
            error!("Failed to hash password: {}", err);
            err.to_string()
        })
}
fn argon2id_verify(options: &VerifyRequest) -> Result<bool, String> {
    let password_hash = PasswordHash::new(&options.hash)
        .map_err(|err| {
            error!("Invalid password hash: {}", err);
            err.to_string()
        })?;

    Argon2::default()
        .verify_password(options.password.as_bytes(), &password_hash)
        .map(|_| true)
        .or_else(|err| match err {
            argon2::password_hash::Error::Password => Ok(false),
            _ => {
                error!("Failed to verify password: {}", err);
                Err(err.to_string())
            }
        })
}