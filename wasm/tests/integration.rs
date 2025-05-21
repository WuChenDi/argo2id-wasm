use argon2id_wasm::{hash, verify, HashOptions};
use wasm_bindgen::JsValue;
use wasm_bindgen_test::*;
use js_sys::Object;

#[wasm_bindgen_test]
fn test_hash_with_empty_password() {
    let result = hash("", JsValue::NULL);
    assert!(result.is_err());
    if let Err(err) = result {
        let obj: Object = err.into();
        let message = js_sys::Reflect::get(&obj, &JsValue::from_str("message"))
            .unwrap()
            .as_string()
            .unwrap();
        assert_eq!(message, "Invalid password or hash: Password cannot be empty");
    }
}

#[wasm_bindgen_test]
fn test_hash_with_valid_password() {
    let result = hash("test123", JsValue::NULL);
    assert!(result.is_ok());
    let hash = result.unwrap();
    assert!(!hash.is_empty());
    assert!(hash.starts_with("$argon2id$"));
}

#[wasm_bindgen_test]
fn test_hash_with_custom_options() {
    let options = HashOptions {
        time_cost: 2,
        memory_cost: 16,
        parallelism: 1,
    };
    let js_options = serde_wasm_bindgen::to_value(&options).unwrap();
    let result = hash("test123", js_options);
    assert!(result.is_ok());
}

#[wasm_bindgen_test]
fn test_hash_with_invalid_options() {
    let options = HashOptions {
        time_cost: 0, // Invalid time_cost
        memory_cost: 8,
        parallelism: 1,
    };
    let js_options = serde_wasm_bindgen::to_value(&options).unwrap();
    let result = hash("test123", js_options);
    assert!(result.is_err());
    if let Err(err) = result {
        let obj: Object = err.into();
        let message = js_sys::Reflect::get(&obj, &JsValue::from_str("message"))
            .unwrap()
            .as_string()
            .unwrap();
        assert_eq!(message, "Invalid password or hash: Invalid hash parameters: memory_cost must be >= 8, time_cost and parallelism must be > 0");
    }
}

#[wasm_bindgen_test]
fn test_verify_with_invalid_hash() {
    let result = verify("invalid_hash", "test123");
    assert!(result.is_err());
    if let Err(err) = result {
        let obj: Object = err.into();
        let message = js_sys::Reflect::get(&obj, &JsValue::from_str("message"))
            .unwrap()
            .as_string()
            .unwrap();
        assert!(message.contains("Invalid hash parameters"));
    }
}

#[wasm_bindgen_test]
fn test_verify_password_flow() {
    // First hash a password
    let hash = hash("test123", JsValue::NULL).unwrap();
    
    // Verify with correct password
    let result = verify(&hash, "test123");
    assert!(result.is_ok());
    assert!(result.unwrap());

    // Verify with incorrect password
    let result = verify(&hash, "wrong_password");
    assert!(result.is_ok());
    assert!(!result.unwrap());
}
