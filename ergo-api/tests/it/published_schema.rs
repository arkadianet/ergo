//! Narrow shape checks for documented responses against mounted route results.
//! This checks required fields and JSON types, not a complete OpenAPI validator.
use serde_json::Value;

fn document() -> Value {
    serde_norway::from_str(ergo_api::server::scala_openapi_yaml()).unwrap()
}

pub(super) fn assert_response(path: &str, method: &str, body: &Value) {
    let doc = document();
    let schema =
        &doc["paths"][path][method]["responses"]["200"]["content"]["application/json"]["schema"];
    assert!(
        schema.is_object(),
        "missing response schema for {method} {path}"
    );
    check_shape(&doc, schema, body);
}

fn check_shape(doc: &Value, schema: &Value, value: &Value) {
    if let Some(reference) = schema["$ref"].as_str() {
        check_shape(
            doc,
            doc.pointer(reference.strip_prefix('#').unwrap()).unwrap(),
            value,
        );
        return;
    }
    if value.is_null() && schema["nullable"] == true {
        return;
    }
    if let Some(parts) = schema["allOf"].as_array() {
        for part in parts {
            check_shape(doc, part, value);
        }
    }
    match schema["type"].as_str() {
        Some("object") => {
            let object = value.as_object().expect("documented object response");
            if let Some(required) = schema["required"].as_array() {
                for key in required {
                    assert!(
                        object.contains_key(key.as_str().unwrap()),
                        "missing required field {key}"
                    );
                }
            }
            if let Some(properties) = schema["properties"].as_object() {
                for (key, child) in properties {
                    if let Some(v) = object.get(key) {
                        check_shape(doc, child, v);
                    }
                }
            }
        }
        Some("array") => {
            for item in value.as_array().expect("documented array response") {
                check_shape(doc, &schema["items"], item);
            }
        }
        Some("string") => assert!(value.is_string(), "documented string: {value}"),
        Some("integer") => assert!(
            value.is_i64() || value.is_u64(),
            "documented integer: {value}"
        ),
        Some("number") => assert!(value.is_number()),
        Some("boolean") => assert!(value.is_boolean()),
        _ => {}
    }
}

#[test]
fn api_key_requirements_have_no_oauth_scopes() {
    fn walk(value: &Value, count: &mut usize) {
        match value {
            Value::Object(object) => {
                if let Some(Value::Array(scopes)) = object.get("ApiKeyAuth") {
                    assert!(
                        scopes.is_empty(),
                        "API key requirements cannot carry OAuth scopes"
                    );
                    *count += 1;
                }
                for child in object.values() {
                    walk(child, count);
                }
            }
            Value::Array(array) => {
                for child in array {
                    walk(child, count);
                }
            }
            _ => {}
        }
    }
    let mut count = 0;
    walk(&document(), &mut count);
    assert!(count > 0);
}
