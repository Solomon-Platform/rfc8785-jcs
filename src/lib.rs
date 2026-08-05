//! [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785) JSON Canonicalization Scheme (JCS), plus a
//! named/versioned SHA-256 content hash built on top of it.
//!
//! Canonicalization makes hashing a JSON value well-defined regardless of how it was
//! constructed: two `serde_json::Value`s that are structurally equal always canonicalize to the
//! same bytes, independent of object key insertion order.
//!
//! Deliberate simplifications, documented rather than silently handled:
//! - Floating point numbers are rejected outright rather than canonicalized. RFC 8785 defines a
//!   canonical form for IEEE-754 doubles, but that form is a frequent source of cross-language
//!   hash mismatches (denormals, `-0.0` vs `0.0`, NaN/Infinity have no valid JSON
//!   representation). If your data can carry money, scores, or other values where an exact
//!   cross-platform hash matters, encode them as integers or strings before hashing.
//! - Object key ordering uses Rust's default `String` `Ord`, a byte-wise comparison of the UTF-8
//!   encoding. This is equivalent to sorting by UTF-16 code unit (what RFC 8785 requires) for
//!   any key made only of ASCII characters; it would diverge only for non-ASCII object keys.

use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

#[derive(Debug, thiserror::Error)]
pub enum JcsError {
    #[error("{0}")]
    Canonicalization(String),
}

/// JCS-canonicalize a `serde_json::Value` into its canonical UTF-8 string form.
pub fn canonicalize(value: &Value) -> Result<String, JcsError> {
    let mut out = String::new();
    write_canonical(value, &mut out)?;
    Ok(out)
}

fn write_canonical(value: &Value, out: &mut String) -> Result<(), JcsError> {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                out.push_str(&i.to_string());
            } else if let Some(u) = n.as_u64() {
                out.push_str(&u.to_string());
            } else {
                return Err(JcsError::Canonicalization(format!(
                    "floating point numbers are forbidden as hash input: {n}"
                )));
            }
        }
        Value::String(s) => {
            out.push_str(
                &serde_json::to_string(s)
                    .map_err(|e| JcsError::Canonicalization(format!("string escape failed: {e}")))?,
            );
        }
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_canonical(item, out)?;
            }
            out.push(']');
        }
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            out.push('{');
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(
                    &serde_json::to_string(k)
                        .map_err(|e| JcsError::Canonicalization(format!("key escape failed: {e}")))?,
                );
                out.push(':');
                write_canonical(&map[*k], out)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

/// `{kind, schema_version, payload}` envelope — naming and versioning a hash input so a schema
/// change never silently collides with the hash of a differently-shaped payload.
#[derive(Serialize)]
struct Envelope<'a> {
    kind: &'a str,
    schema_version: u32,
    payload: Value,
}

/// Hash a named, versioned payload: JCS-canonicalize `{kind, schema_version, payload}` and
/// SHA-256 it, returning lowercase hex without a prefix.
///
/// `kind` and `schema_version` being part of the hash input (not just metadata alongside it)
/// means a payload that's identical in content but a different logical "thing", or the same
/// logical thing on a later schema version, is guaranteed to hash differently.
pub fn named_hash(kind: &str, schema_version: u32, payload: Value) -> Result<String, JcsError> {
    let envelope = Envelope {
        kind,
        schema_version,
        payload,
    };
    let envelope_value = serde_json::to_value(&envelope)
        .map_err(|e| JcsError::Canonicalization(format!("envelope serialize failed: {e}")))?;
    let canonical = canonicalize(&envelope_value)?;
    let mut hasher = Sha256::new();
    hasher.update(canonical.as_bytes());
    let digest = hasher.finalize();
    Ok(hex::encode(digest))
}

/// Minimal hex encoder so the crate doesn't need a `hex` dependency for one call site.
mod hex {
    pub fn encode(bytes: impl AsRef<[u8]>) -> String {
        let mut s = String::with_capacity(bytes.as_ref().len() * 2);
        for b in bytes.as_ref() {
            s.push_str(&format!("{b:02x}"));
        }
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn canonicalize_sorts_object_keys() {
        let a = json!({"b": 1, "a": 2, "c": {"z": 1, "y": 2}});
        let canon = canonicalize(&a).unwrap();
        assert_eq!(canon, r#"{"a":2,"b":1,"c":{"y":2,"z":1}}"#);
    }

    #[test]
    fn hash_is_independent_of_input_key_order() {
        let payload_a = json!({
            "id": "018f0000-0000-7000-8000-000000000000",
            "version": 3,
            "body": {"choice": "alt-1", "assumptions": ["a", "b"]}
        });
        let payload_b = json!({
            "body": {"assumptions": ["a", "b"], "choice": "alt-1"},
            "version": 3,
            "id": "018f0000-0000-7000-8000-000000000000"
        });
        let hash_a = named_hash("example", 1, payload_a).unwrap();
        let hash_b = named_hash("example", 1, payload_b).unwrap();
        assert_eq!(
            hash_a, hash_b,
            "JCS must make hash independent of object key order"
        );
        assert_eq!(hash_a.len(), 64);
        assert!(hash_a
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    }

    #[test]
    fn hash_changes_when_payload_changes() {
        let h1 = named_hash("x", 1, json!({"a": 1})).unwrap();
        let h2 = named_hash("x", 1, json!({"a": 2})).unwrap();
        assert_ne!(h1, h2);
    }

    #[test]
    fn hash_changes_when_kind_or_schema_version_changes() {
        let base = named_hash("x", 1, json!({"a": 1})).unwrap();
        let other_kind = named_hash("y", 1, json!({"a": 1})).unwrap();
        let other_version = named_hash("x", 2, json!({"a": 1})).unwrap();
        assert_ne!(base, other_kind);
        assert_ne!(base, other_version);
    }

    #[test]
    fn floating_point_payload_is_rejected() {
        let err = named_hash("x", 1, json!({"a": 1.5})).unwrap_err();
        assert!(matches!(err, JcsError::Canonicalization(_)));
    }

    #[test]
    fn missing_vs_null_are_different_hash_inputs() {
        let with_null = named_hash("x", 1, json!({"a": null})).unwrap();
        let without = named_hash("x", 1, json!({})).unwrap();
        assert_ne!(with_null, without);
    }
}
