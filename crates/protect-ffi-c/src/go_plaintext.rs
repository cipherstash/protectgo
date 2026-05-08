use cipherstash_client::encryption::{Plaintext, TryFromPlaintext, TypeParseError};
use cipherstash_client::schema::ColumnType;
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize, Debug, PartialEq)]
#[serde(untagged)]
pub(crate) enum GoPlaintext {
    String(String),
    Number(f64),
    Boolean(bool),
    JsonB(serde_json::Value),
}

impl From<GoPlaintext> for Plaintext {
    fn from(value: GoPlaintext) -> Self {
        match value {
            GoPlaintext::String(s) => Plaintext::Utf8Str(Some(s)),
            GoPlaintext::Number(n) => Plaintext::Float(Some(n)),
            GoPlaintext::Boolean(b) => Plaintext::Boolean(Some(b)),
            GoPlaintext::JsonB(j) => Plaintext::JsonB(Some(j)),
        }
    }
}

impl TryFrom<Plaintext> for GoPlaintext {
    type Error = TypeParseError;

    fn try_from(value: Plaintext) -> Result<Self, Self::Error> {
        match value {
            v @ Plaintext::Utf8Str(Some(_)) => {
                String::try_from_plaintext(v).map(GoPlaintext::String)
            }
            v @ Plaintext::JsonB(Some(_)) => {
                serde_json::Value::try_from_plaintext(v).map(GoPlaintext::JsonB)
            }
            Plaintext::BigInt(Some(n)) => Ok(GoPlaintext::Number(n as f64)),
            Plaintext::Float(Some(n)) => Ok(GoPlaintext::Number(n)),
            Plaintext::Boolean(Some(b)) => Ok(GoPlaintext::Boolean(b)),
            _ => Err(TypeParseError("Unsupported type".to_string())),
        }
    }
}

impl GoPlaintext {
    /// Convert GoPlaintext to Plaintext based on a target ColumnType.
    ///
    /// This conversion follows the rule that type coercion is allowed but parsing is not.
    /// For example:
    /// - GoPlaintext::Number to Plaintext::BigInt is allowed (coercion with truncation)
    /// - GoPlaintext::String to Plaintext::BigInt is NOT allowed (would require parsing)
    pub fn to_plaintext_with_type(
        &self,
        column_type: ColumnType,
    ) -> Result<Plaintext, TypeParseError> {
        match (self, column_type) {
            // String conversions - only allow to Utf8Str
            (GoPlaintext::String(s), ColumnType::Utf8Str) => {
                Ok(Plaintext::Utf8Str(Some(s.clone())))
            }

            // Number conversions - allow to numeric types with potential truncation/coercion
            (GoPlaintext::Number(n), ColumnType::Float) => Ok(Plaintext::Float(Some(*n))),
            (GoPlaintext::Number(n), ColumnType::Decimal) => Decimal::try_from(*n)
                .map(|d| Plaintext::Decimal(Some(d)))
                .map_err(|e| TypeParseError(format!("Cannot convert number to Decimal: {}", e))),
            (GoPlaintext::Number(n), ColumnType::BigInt) => Ok(Plaintext::BigInt(Some(*n as i64))),
            (GoPlaintext::Number(n), ColumnType::Int) => Ok(Plaintext::Int(Some(*n as i32))),
            (GoPlaintext::Number(n), ColumnType::SmallInt) => {
                Ok(Plaintext::SmallInt(Some(*n as i16)))
            }
            (GoPlaintext::Number(n), ColumnType::BigUInt) => {
                if *n < 0.0 {
                    Err(TypeParseError(
                        "Cannot convert negative number to BigUInt".to_string(),
                    ))
                } else {
                    Ok(Plaintext::BigUInt(Some(*n as u64)))
                }
            }

            // Boolean conversions - only allow to Boolean
            (GoPlaintext::Boolean(b), ColumnType::Boolean) => Ok(Plaintext::Boolean(Some(*b))),

            // JsonB conversions - only allow to JsonB
            (GoPlaintext::JsonB(j), ColumnType::JsonB) => Ok(Plaintext::JsonB(Some(j.clone()))),

            // All other conversions are not allowed - provide helpful error message
            (go_type, col_type) => {
                let valid_targets = match go_type {
                    GoPlaintext::String(_) => "Utf8Str (string columns)",
                    GoPlaintext::Number(_) => {
                        "Float, BigInt, Int, SmallInt, BigUInt, Decimal (numeric columns)"
                    }
                    GoPlaintext::Boolean(_) => "Boolean (boolean columns)",
                    GoPlaintext::JsonB(_) => "JsonB (json columns)",
                };
                Err(TypeParseError(format!(
                    "Cannot convert {} to {:?}. {} values can only be used with: {}. \
                    Check your column's cast_as setting in the encrypt config.",
                    go_plaintext_type_name(go_type),
                    col_type,
                    go_plaintext_type_name(go_type),
                    valid_targets
                )))
            }
        }
    }
}

/// Helper function to get a readable type name for error messages
pub(crate) fn go_plaintext_type_name(go_plaintext: &GoPlaintext) -> &'static str {
    match go_plaintext {
        GoPlaintext::String(_) => "String",
        GoPlaintext::Number(_) => "Number",
        GoPlaintext::Boolean(_) => "Boolean",
        GoPlaintext::JsonB(_) => "JsonB",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    mod go_plaintext_to_plaintext {
        use super::*;

        #[test]
        fn test_string() {
            let go_string = GoPlaintext::String("hello".to_string());
            let plaintext: Plaintext = go_string.into();
            assert_eq!(plaintext, Plaintext::Utf8Str(Some("hello".to_string())));
        }

        #[test]
        fn test_number() {
            let go_number = GoPlaintext::Number(42.5);
            let plaintext: Plaintext = go_number.into();
            assert_eq!(plaintext, Plaintext::Float(Some(42.5)));
        }

        #[test]
        fn test_boolean() {
            let go_bool = GoPlaintext::Boolean(true);
            let plaintext: Plaintext = go_bool.into();
            assert_eq!(plaintext, Plaintext::Boolean(Some(true)));
        }

        #[test]
        fn test_jsonb() {
            let go_jsonb = GoPlaintext::JsonB(serde_json::json!({"key": "value"}));
            let plaintext: Plaintext = go_jsonb.into();
            assert_eq!(
                plaintext,
                Plaintext::JsonB(Some(serde_json::json!({"key": "value"})))
            );
        }
    }

    mod plaintext_to_go_plaintext {
        use super::*;

        #[test]
        fn test_utf8str() {
            let plaintext = Plaintext::Utf8Str(Some("hello".to_string()));
            let go_plaintext: GoPlaintext = plaintext.try_into().unwrap();
            assert_eq!(go_plaintext, GoPlaintext::String("hello".to_string()));
        }

        #[test]
        fn test_float() {
            let plaintext = Plaintext::Float(Some(42.5));
            let go_plaintext: GoPlaintext = plaintext.try_into().unwrap();
            assert_eq!(go_plaintext, GoPlaintext::Number(42.5));
        }

        #[test]
        fn test_boolean() {
            let plaintext = Plaintext::Boolean(Some(true));
            let go_plaintext: GoPlaintext = plaintext.try_into().unwrap();
            assert_eq!(go_plaintext, GoPlaintext::Boolean(true));
        }

        #[test]
        fn test_jsonb() {
            let plaintext = Plaintext::JsonB(Some(serde_json::json!({"key": "value"})));
            let go_plaintext: GoPlaintext = plaintext.try_into().unwrap();
            assert_eq!(
                go_plaintext,
                GoPlaintext::JsonB(serde_json::json!({"key": "value"}))
            );
        }

        #[test]
        fn test_bigint() {
            let plaintext = Plaintext::BigInt(Some(42));
            let go_plaintext: GoPlaintext = plaintext.try_into().unwrap();
            assert_eq!(go_plaintext, GoPlaintext::Number(42.0));
        }

        #[test]
        fn test_unsupported_type_returns_error() {
            let plaintext = Plaintext::Utf8Str(None);
            let result: Result<GoPlaintext, TypeParseError> = plaintext.try_into();
            assert!(result.is_err());
        }
    }

    mod go_plaintext_to_plaintext_with_type {
        use super::*;

        #[test]
        fn test_string_to_utf8str() {
            let go_string = GoPlaintext::String("hello".to_string());
            let result = go_string
                .to_plaintext_with_type(ColumnType::Utf8Str)
                .unwrap();
            assert_eq!(result, Plaintext::Utf8Str(Some("hello".to_string())));
        }

        #[test]
        fn test_string_to_int_fails() {
            let go_string = GoPlaintext::String("123".to_string());
            let result = go_string.to_plaintext_with_type(ColumnType::Int);
            assert!(result.is_err());
            assert!(result.unwrap_err().0.contains("Cannot convert"));
        }

        #[test]
        fn test_number_to_float() {
            let go_number = GoPlaintext::Number(3.78);
            let result = go_number.to_plaintext_with_type(ColumnType::Float).unwrap();
            assert_eq!(result, Plaintext::Float(Some(3.78)));
        }

        #[test]
        fn test_number_to_decimal() {
            let go_number = GoPlaintext::Number(3.78);
            let result = go_number
                .to_plaintext_with_type(ColumnType::Decimal)
                .unwrap();
            let expected_decimal = Decimal::try_from(3.78).unwrap();
            assert_eq!(result, Plaintext::Decimal(Some(expected_decimal)));
        }

        #[test]
        fn test_number_to_bigint_truncates() {
            let go_number = GoPlaintext::Number(42.7);
            let result = go_number
                .to_plaintext_with_type(ColumnType::BigInt)
                .unwrap();
            assert_eq!(result, Plaintext::BigInt(Some(42)));
        }

        #[test]
        fn test_number_to_int_truncates() {
            let go_number = GoPlaintext::Number(42.7);
            let result = go_number.to_plaintext_with_type(ColumnType::Int).unwrap();
            assert_eq!(result, Plaintext::Int(Some(42)));
        }

        #[test]
        fn test_number_to_smallint_truncates() {
            let go_number = GoPlaintext::Number(42.7);
            let result = go_number
                .to_plaintext_with_type(ColumnType::SmallInt)
                .unwrap();
            assert_eq!(result, Plaintext::SmallInt(Some(42)));
        }

        #[test]
        fn test_number_to_biguint() {
            let go_number = GoPlaintext::Number(42.0);
            let result = go_number
                .to_plaintext_with_type(ColumnType::BigUInt)
                .unwrap();
            assert_eq!(result, Plaintext::BigUInt(Some(42)));
        }

        #[test]
        fn test_negative_number_to_biguint_fails() {
            let go_number = GoPlaintext::Number(-42.0);
            let result = go_number.to_plaintext_with_type(ColumnType::BigUInt);
            assert!(result.is_err());
            assert!(result.unwrap_err().0.contains("negative"));
        }

        #[test]
        fn test_boolean_to_boolean() {
            let go_bool = GoPlaintext::Boolean(true);
            let result = go_bool.to_plaintext_with_type(ColumnType::Boolean).unwrap();
            assert_eq!(result, Plaintext::Boolean(Some(true)));
        }

        #[test]
        fn test_boolean_to_string_fails() {
            let go_bool = GoPlaintext::Boolean(true);
            let result = go_bool.to_plaintext_with_type(ColumnType::Utf8Str);
            assert!(result.is_err());
            assert!(result.unwrap_err().0.contains("Cannot convert"));
        }

        #[test]
        fn test_jsonb_to_jsonb() {
            let json_value = serde_json::json!({"key": "value"});
            let go_jsonb = GoPlaintext::JsonB(json_value.clone());
            let result = go_jsonb.to_plaintext_with_type(ColumnType::JsonB).unwrap();
            assert_eq!(result, Plaintext::JsonB(Some(json_value)));
        }

        #[test]
        fn test_jsonb_to_string_fails() {
            let json_value = serde_json::json!({"key": "value"});
            let go_jsonb = GoPlaintext::JsonB(json_value);
            let result = go_jsonb.to_plaintext_with_type(ColumnType::Utf8Str);
            assert!(result.is_err());
            assert!(result.unwrap_err().0.contains("Cannot convert"));
        }

        #[test]
        fn test_number_to_boolean_fails() {
            let go_number = GoPlaintext::Number(1.0);
            let result = go_number.to_plaintext_with_type(ColumnType::Boolean);
            assert!(result.is_err());
            assert!(result.unwrap_err().0.contains("Cannot convert"));
        }

        #[test]
        fn test_type_coercion_error_shows_valid_alternatives() {
            let go_string = GoPlaintext::String("hello".to_string());
            let result = go_string.to_plaintext_with_type(ColumnType::Int);
            assert!(result.is_err());
            let err_msg = result.unwrap_err().0;
            assert!(
                err_msg.contains("Utf8Str"),
                "Error should mention valid target Utf8Str: {}",
                err_msg
            );
            assert!(
                err_msg.contains("cast_as"),
                "Error should mention cast_as setting: {}",
                err_msg
            );

            let go_number = GoPlaintext::Number(42.0);
            let result = go_number.to_plaintext_with_type(ColumnType::Boolean);
            assert!(result.is_err());
            let err_msg = result.unwrap_err().0;
            assert!(
                err_msg.contains("Float") || err_msg.contains("BigInt"),
                "Error should mention valid numeric targets: {}",
                err_msg
            );

            let go_bool = GoPlaintext::Boolean(true);
            let result = go_bool.to_plaintext_with_type(ColumnType::Int);
            assert!(result.is_err());
            let err_msg = result.unwrap_err().0;
            assert!(
                err_msg.contains("Boolean"),
                "Error should mention valid target Boolean: {}",
                err_msg
            );

            let go_json = GoPlaintext::JsonB(serde_json::json!({"a": 1}));
            let result = go_json.to_plaintext_with_type(ColumnType::Int);
            assert!(result.is_err());
            let err_msg = result.unwrap_err().0;
            assert!(
                err_msg.contains("JsonB"),
                "Error should mention valid target JsonB: {}",
                err_msg
            );
        }
    }
}
