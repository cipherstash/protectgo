use chrono::{DateTime, NaiveDate, Utc};
use cipherstash_client::encryption::{Plaintext, TryFromPlaintext, TypeParseError};
use cipherstash_client::schema::ColumnType;
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};

/// The plaintext values that cross the FFI boundary from/to Go.
///
/// Untagged so a bare JSON scalar (string, number, boolean) or object/array
/// deserializes directly. The variant order is load-bearing: `Number` must
/// precede `JsonB` (which accepts any value) so number literals map to
/// `Number`, not the catch-all.
///
/// `Number` holds a [`serde_json::Number`], NOT an `f64`: the JSON parser
/// preserves integer literals as exact `i64`/`u64`, so a `big_int` value beyond
/// 2^53 survives deserialization losslessly. `to_plaintext_with_type` then
/// takes the exact integer when the target is an integer column, falling back
/// to an exact-or-error `f64` path only for non-integer number forms.
///
/// Go has no dedicated bigint or date wire form. Large integers arrive as JSON
/// numbers (`Number`); dates/timestamps arrive as RFC 3339 / `YYYY-MM-DD`
/// strings (`String`). On decrypt, integers are emitted as exact JSON integers
/// (via `JsonB`), and dates/timestamps/decimals as strings — see
/// [`TryFrom<Plaintext>`].
#[derive(Deserialize, Serialize, Debug, PartialEq)]
#[serde(untagged)]
pub(crate) enum GoPlaintext {
    String(String),
    Number(serde_json::Number),
    Boolean(bool),
    JsonB(serde_json::Value),
}

impl From<GoPlaintext> for Plaintext {
    fn from(value: GoPlaintext) -> Self {
        match value {
            GoPlaintext::String(s) => Plaintext::Text(Some(s)),
            // Untyped default: a number becomes a float (used only where no
            // column cast type is available; typed conversion goes through
            // `to_plaintext_with_type`). A `serde_json::Number` always converts
            // to `f64`.
            GoPlaintext::Number(n) => Plaintext::Float(Some(n.as_f64().unwrap_or(f64::NAN))),
            GoPlaintext::Boolean(b) => Plaintext::Boolean(Some(b)),
            GoPlaintext::JsonB(j) => Plaintext::Json(Some(j)),
        }
    }
}

impl TryFrom<Plaintext> for GoPlaintext {
    type Error = TypeParseError;

    fn try_from(value: Plaintext) -> Result<Self, Self::Error> {
        match value {
            v @ Plaintext::Text(Some(_)) => String::try_from_plaintext(v).map(GoPlaintext::String),
            v @ Plaintext::Json(Some(_)) => {
                serde_json::Value::try_from_plaintext(v).map(GoPlaintext::JsonB)
            }
            // Integer casts decrypt to EXACT JSON integers, never f64 — a lossy
            // f64 cast would corrupt values beyond 2^53. Carried in `JsonB` (an
            // untagged `serde_json::Number`), which serializes as a bare integer.
            Plaintext::BigInt(Some(n)) => Ok(GoPlaintext::JsonB(serde_json::json!(n))),
            Plaintext::Int(Some(n)) => Ok(GoPlaintext::JsonB(serde_json::json!(n as i64))),
            Plaintext::SmallInt(Some(n)) => Ok(GoPlaintext::JsonB(serde_json::json!(n as i64))),
            Plaintext::Float(Some(n)) => serde_json::Number::from_f64(n)
                .map(GoPlaintext::Number)
                .ok_or_else(|| {
                    TypeParseError(
                        "Float value is not representable in JSON (NaN or Infinity)".to_string(),
                    )
                }),
            Plaintext::Boolean(Some(b)) => Ok(GoPlaintext::Boolean(b)),
            // Decimal is emitted as a JSON string so its full precision survives
            // (a JSON number would be re-parsed as f64 on the Go side).
            Plaintext::Decimal(Some(d)) => Ok(GoPlaintext::String(d.to_string())),
            // Dates and timestamps decrypt to canonical strings.
            Plaintext::NaiveDate(Some(nd)) => {
                Ok(GoPlaintext::String(nd.format("%Y-%m-%d").to_string()))
            }
            Plaintext::Timestamp(Some(ts)) => Ok(GoPlaintext::String(ts.to_rfc3339())),
            _ => Err(TypeParseError("Unsupported type".to_string())),
        }
    }
}

impl GoPlaintext {
    /// Convert a `GoPlaintext` to a `Plaintext` for the column's storage type.
    ///
    /// The storage type is driven by `cast_as`, not the input variant. Strings
    /// bound for `Date`/`Timestamp` columns are parsed (RFC 3339, plus plain
    /// `YYYY-MM-DD` for dates). Numbers bound for integer columns must be
    /// represented exactly or the conversion errors — integer literals are
    /// taken from the exact `i64`/`u64` the JSON parser preserved (no f64
    /// round-trip), and any lossy cast is rejected rather than silently
    /// corrupting the stored value and the index terms derived from it.
    ///
    /// Errors never echo the input value: it is plaintext being encrypted.
    pub fn to_plaintext_with_type(
        &self,
        column_type: ColumnType,
    ) -> Result<Plaintext, TypeParseError> {
        match (self, column_type) {
            // String conversions - Text, Date, and Timestamp (the latter two parse).
            (GoPlaintext::String(s), ColumnType::Text) => Ok(Plaintext::Text(Some(s.clone()))),
            (GoPlaintext::String(s), ColumnType::Date) => parse_naive_date(s)
                .map(|d| Plaintext::NaiveDate(Some(d)))
                .map_err(|e| TypeParseError(format!("Cannot parse Date: {}", e))),
            (GoPlaintext::String(s), ColumnType::Timestamp) => parse_timestamp(s)
                .map(|t| Plaintext::Timestamp(Some(t)))
                .map_err(|e| TypeParseError(format!("Cannot parse Timestamp: {}", e))),

            // Float stores the value verbatim (rounding an integer literal to
            // f64 is expected for a float column).
            (GoPlaintext::Number(n), ColumnType::Float) => n
                .as_f64()
                .map(|f| Plaintext::Float(Some(f)))
                .ok_or_else(|| TypeParseError("Cannot convert number to Float".to_string())),

            // Decimal parses from the number's exact decimal text, NOT via f64,
            // so a large integer literal or an exact decimal survives.
            (GoPlaintext::Number(n), ColumnType::Decimal) => Decimal::from_str_exact(&n.to_string())
                .map(|d| Plaintext::Decimal(Some(d)))
                .map_err(|_| {
                    TypeParseError(
                        "Cannot convert number to Decimal: value is not representable as a decimal"
                            .to_string(),
                    )
                }),

            // Signed integer casts: take the exact i64 first, then range-check;
            // fall back to the exact-or-error f64 path for non-integer forms.
            (GoPlaintext::Number(n), ColumnType::BigInt) => {
                number_to_signed_int::<i64>(n, ColumnType::BigInt).map(|v| Plaintext::BigInt(Some(v)))
            }
            (GoPlaintext::Number(n), ColumnType::Int) => {
                number_to_signed_int::<i32>(n, ColumnType::Int).map(|v| Plaintext::Int(Some(v)))
            }
            (GoPlaintext::Number(n), ColumnType::SmallInt) => {
                number_to_signed_int::<i16>(n, ColumnType::SmallInt)
                    .map(|v| Plaintext::SmallInt(Some(v)))
            }

            // Unsigned: take the exact u64 first (covers 0..=u64::MAX, including
            // values above i64::MAX); negatives error; non-integer forms use the
            // exact-or-error f64 path.
            (GoPlaintext::Number(n), ColumnType::BigUInt) => {
                if let Some(u) = n.as_u64() {
                    return Ok(Plaintext::BigUInt(Some(u)));
                }
                let f = n.as_f64().ok_or_else(|| out_of_range(ColumnType::BigUInt))?;
                if f < 0.0 {
                    return Err(TypeParseError(
                        "Cannot convert negative number to BigUInt".to_string(),
                    ));
                }
                f64_to_exact_int::<u64>(f, ColumnType::BigUInt).map(|v| Plaintext::BigUInt(Some(v)))
            }

            // Boolean conversions - only allow to Boolean
            (GoPlaintext::Boolean(b), ColumnType::Boolean) => Ok(Plaintext::Boolean(Some(*b))),

            // Json conversions - only allow to Json
            (GoPlaintext::JsonB(j), ColumnType::Json) => Ok(Plaintext::Json(Some(j.clone()))),

            // All other conversions are not allowed - provide a helpful message.
            (go_type, col_type) => {
                let valid_targets = match go_type {
                    GoPlaintext::String(_) => {
                        "Text (string columns), Date, Timestamp (ISO 8601 strings)"
                    }
                    GoPlaintext::Number(_) => {
                        "Float, BigInt, Int, SmallInt, BigUInt, Decimal (numeric columns)"
                    }
                    GoPlaintext::Boolean(_) => "Boolean (boolean columns)",
                    GoPlaintext::JsonB(_) => "Json (json columns)",
                };
                let type_name = go_plaintext_type_name(go_type);
                Err(TypeParseError(format!(
                    "Cannot convert {} to {:?}. {} values can only be used with: {}. \
                    Check your column's cast_as setting in the encrypt config.",
                    type_name, col_type, type_name, valid_targets
                )))
            }
        }
    }
}

/// Error for a number that does not fit the target integer type. Never echoes
/// the value (it is plaintext being encrypted).
fn out_of_range(column_type: ColumnType) -> TypeParseError {
    TypeParseError(format!(
        "Cannot convert number to {:?}: value is out of range",
        column_type
    ))
}

/// Convert a JSON number to a signed integer type exactly.
///
/// Integer literals are taken from the exact `i64` the JSON parser preserved,
/// so precision beyond 2^53 survives; a value that does not fit the target is
/// rejected. Non-integer (f64-form) numbers fall back to the exact-or-error
/// [`f64_to_exact_int`] path.
fn number_to_signed_int<T>(
    n: &serde_json::Number,
    column_type: ColumnType,
) -> Result<T, TypeParseError>
where
    T: TryFrom<i64> + TryFrom<i128>,
{
    if let Some(i) = n.as_i64() {
        return T::try_from(i).map_err(|_| out_of_range(column_type));
    }
    let f = n.as_f64().ok_or_else(|| out_of_range(column_type))?;
    f64_to_exact_int::<T>(f, column_type)
}

/// Convert an `f64` into an integer type exactly, or error.
///
/// A saturating `as` cast would silently corrupt out-of-range values, map NaN
/// to 0, and drop fractional parts — and the index terms would be computed over
/// the corrupted value. Error unless the value is finite, integral, and fits
/// the target. The error deliberately does not echo the value.
fn f64_to_exact_int<T: TryFrom<i128>>(
    n: f64,
    column_type: ColumnType,
) -> Result<T, TypeParseError> {
    if !n.is_finite() {
        return Err(TypeParseError(format!(
            "Cannot convert number to {:?}: value must be finite (got NaN or Infinity)",
            column_type
        )));
    }
    if n.fract() != 0.0 {
        return Err(TypeParseError(format!(
            "Cannot convert number to {:?}: value has a fractional component",
            column_type
        )));
    }
    // `n` is finite with no fractional part, so if it lies within i128's range
    // the `as` cast below is exact. `i128::MAX as f64` rounds up to 2^127,
    // which does NOT fit in i128, hence `>=`.
    if n < i128::MIN as f64 || n >= i128::MAX as f64 {
        return Err(out_of_range(column_type));
    }
    T::try_from(n as i128).map_err(|_| out_of_range(column_type))
}

/// Parse a string into a `NaiveDate`. Accepts full RFC 3339 timestamps and
/// plain `YYYY-MM-DD`.
fn parse_naive_date(s: &str) -> Result<NaiveDate, String> {
    if let Ok(dt) = DateTime::parse_from_rfc3339(s) {
        return Ok(dt.with_timezone(&Utc).date_naive());
    }
    NaiveDate::parse_from_str(s, "%Y-%m-%d").map_err(|e| e.to_string())
}

/// Parse a string into a UTC `DateTime`. Accepts RFC 3339.
fn parse_timestamp(s: &str) -> Result<DateTime<Utc>, String> {
    DateTime::parse_from_rfc3339(s)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|e| e.to_string())
}

/// Helper function to get a readable type name for error messages
pub(crate) fn go_plaintext_type_name(go_plaintext: &GoPlaintext) -> &'static str {
    match go_plaintext {
        GoPlaintext::String(_) => "String",
        GoPlaintext::Number(_) => "Number",
        GoPlaintext::Boolean(_) => "Boolean",
        GoPlaintext::JsonB(_) => "Json",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A `GoPlaintext::Number` from an f64 (fractional/float forms).
    fn num(f: f64) -> GoPlaintext {
        GoPlaintext::Number(serde_json::Number::from_f64(f).unwrap())
    }

    /// A `GoPlaintext::Number` from an exact i64 integer literal.
    fn int(i: i64) -> GoPlaintext {
        GoPlaintext::Number(serde_json::Number::from(i))
    }

    fn sample_dt() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2025-03-14T12:34:56.789Z")
            .unwrap()
            .with_timezone(&Utc)
    }

    mod go_plaintext_to_plaintext {
        use super::*;

        #[test]
        fn test_string() {
            let plaintext: Plaintext = GoPlaintext::String("hello".to_string()).into();
            assert_eq!(plaintext, Plaintext::Text(Some("hello".to_string())));
        }

        #[test]
        fn test_number() {
            let plaintext: Plaintext = num(42.5).into();
            assert_eq!(plaintext, Plaintext::Float(Some(42.5)));
        }

        #[test]
        fn test_boolean() {
            let plaintext: Plaintext = GoPlaintext::Boolean(true).into();
            assert_eq!(plaintext, Plaintext::Boolean(Some(true)));
        }

        #[test]
        fn test_jsonb() {
            let plaintext: Plaintext =
                GoPlaintext::JsonB(serde_json::json!({"key": "value"})).into();
            assert_eq!(
                plaintext,
                Plaintext::Json(Some(serde_json::json!({"key": "value"})))
            );
        }
    }

    mod plaintext_to_go_plaintext {
        use super::*;

        #[test]
        fn test_text() {
            let go: GoPlaintext = Plaintext::Text(Some("hello".to_string())).try_into().unwrap();
            assert_eq!(go, GoPlaintext::String("hello".to_string()));
        }

        #[test]
        fn test_float() {
            let go: GoPlaintext = Plaintext::Float(Some(42.5)).try_into().unwrap();
            assert_eq!(go, num(42.5));
        }

        #[test]
        fn test_boolean() {
            let go: GoPlaintext = Plaintext::Boolean(Some(true)).try_into().unwrap();
            assert_eq!(go, GoPlaintext::Boolean(true));
        }

        #[test]
        fn test_json() {
            let go: GoPlaintext = Plaintext::Json(Some(serde_json::json!({"key": "value"})))
                .try_into()
                .unwrap();
            assert_eq!(go, GoPlaintext::JsonB(serde_json::json!({"key": "value"})));
        }

        #[test]
        fn test_bigint_becomes_exact_json_integer() {
            for v in [i64::MIN, i64::MAX, 0, -1, 9_007_199_254_740_995] {
                let go: GoPlaintext = Plaintext::BigInt(Some(v)).try_into().unwrap();
                assert_eq!(go, GoPlaintext::JsonB(serde_json::json!(v)));
                assert_eq!(serde_json::to_string(&go).unwrap(), v.to_string());
            }
        }

        #[test]
        fn test_int_and_small_int_become_json_integers() {
            let go: GoPlaintext = Plaintext::Int(Some(42)).try_into().unwrap();
            assert_eq!(serde_json::to_string(&go).unwrap(), "42");
            let go: GoPlaintext = Plaintext::SmallInt(Some(-7)).try_into().unwrap();
            assert_eq!(serde_json::to_string(&go).unwrap(), "-7");
        }

        #[test]
        fn test_decimal_becomes_json_string() {
            let d = Decimal::new(1999, 2); // 19.99
            let go: GoPlaintext = Plaintext::Decimal(Some(d)).try_into().unwrap();
            assert_eq!(go, GoPlaintext::String("19.99".to_string()));
        }

        #[test]
        fn test_naive_date_becomes_yyyy_mm_dd_string() {
            let d = NaiveDate::from_ymd_opt(2025, 3, 14).unwrap();
            let go: GoPlaintext = Plaintext::NaiveDate(Some(d)).try_into().unwrap();
            assert_eq!(go, GoPlaintext::String("2025-03-14".to_string()));
        }

        #[test]
        fn test_timestamp_becomes_rfc3339_string() {
            let t = sample_dt();
            let go: GoPlaintext = Plaintext::Timestamp(Some(t)).try_into().unwrap();
            assert_eq!(go, GoPlaintext::String(t.to_rfc3339()));
        }

        #[test]
        fn test_float_nan_is_rejected() {
            // serde_json cannot represent NaN, so a Float(NaN) decrypt errors
            // rather than producing an unserializable value.
            let result: Result<GoPlaintext, TypeParseError> =
                Plaintext::Float(Some(f64::NAN)).try_into();
            assert!(result.is_err());
        }

        #[test]
        fn test_unsupported_type_returns_error() {
            let result: Result<GoPlaintext, TypeParseError> = Plaintext::Text(None).try_into();
            assert!(result.is_err());
        }
    }

    mod go_plaintext_to_plaintext_with_type {
        use super::*;

        #[test]
        fn test_string_to_text() {
            let result = GoPlaintext::String("hello".to_string())
                .to_plaintext_with_type(ColumnType::Text)
                .unwrap();
            assert_eq!(result, Plaintext::Text(Some("hello".to_string())));
        }

        #[test]
        fn test_string_to_int_fails() {
            let result =
                GoPlaintext::String("123".to_string()).to_plaintext_with_type(ColumnType::Int);
            assert!(result.unwrap_err().0.contains("Cannot convert"));
        }

        #[test]
        fn test_number_to_float() {
            let result = num(3.78).to_plaintext_with_type(ColumnType::Float).unwrap();
            assert_eq!(result, Plaintext::Float(Some(3.78)));
        }

        #[test]
        fn test_large_integer_literal_to_float_rounds() {
            // A big integer literal into a float column is accepted (f64 rounds).
            let result = int(9_007_199_254_740_995)
                .to_plaintext_with_type(ColumnType::Float)
                .unwrap();
            assert_eq!(
                result,
                Plaintext::Float(Some(9_007_199_254_740_995_i64 as f64))
            );
        }

        // --- Exact-integer behaviour (the precision regression) ---

        #[test]
        fn bigint_is_exact_beyond_2_53() {
            for v in [9_007_199_254_740_995_i64, i64::MAX, i64::MIN, 0, -1] {
                let result = int(v).to_plaintext_with_type(ColumnType::BigInt).unwrap();
                assert_eq!(result, Plaintext::BigInt(Some(v)));
            }
        }

        #[test]
        fn bigint_is_exact_through_json_deserialization() {
            // The regression: deserializing the literal must NOT round to f64.
            let go: GoPlaintext = serde_json::from_str("9007199254740995").unwrap();
            let result = go.to_plaintext_with_type(ColumnType::BigInt).unwrap();
            assert_eq!(result, Plaintext::BigInt(Some(9_007_199_254_740_995)));
        }

        #[test]
        fn integer_literal_out_of_int_range_fails() {
            let err = int(5_000_000_000)
                .to_plaintext_with_type(ColumnType::Int)
                .unwrap_err();
            assert!(err.0.contains("Int"), "{}", err.0);
            assert!(err.0.contains("out of range"), "{}", err.0);
        }

        #[test]
        fn in_range_integer_literal_to_int() {
            let result = int(42).to_plaintext_with_type(ColumnType::Int).unwrap();
            assert_eq!(result, Plaintext::Int(Some(42)));
            let max = int(i32::MAX as i64)
                .to_plaintext_with_type(ColumnType::Int)
                .unwrap();
            assert_eq!(max, Plaintext::Int(Some(i32::MAX)));
        }

        #[test]
        fn smallint_range_check() {
            let ok = int(i16::MAX as i64)
                .to_plaintext_with_type(ColumnType::SmallInt)
                .unwrap();
            assert_eq!(ok, Plaintext::SmallInt(Some(i16::MAX)));
            let err = int(40_000)
                .to_plaintext_with_type(ColumnType::SmallInt)
                .unwrap_err();
            assert!(err.0.contains("SmallInt") && err.0.contains("out of range"));
        }

        #[test]
        fn biguint_accepts_u64_above_i64_max() {
            let v: u64 = (i64::MAX as u64) + 1;
            let go = GoPlaintext::Number(serde_json::Number::from(v));
            assert_eq!(
                go.to_plaintext_with_type(ColumnType::BigUInt).unwrap(),
                Plaintext::BigUInt(Some(v))
            );
            // And exact through the JSON boundary.
            let go2: GoPlaintext = serde_json::from_str(&v.to_string()).unwrap();
            assert_eq!(
                go2.to_plaintext_with_type(ColumnType::BigUInt).unwrap(),
                Plaintext::BigUInt(Some(v))
            );
        }

        #[test]
        fn biguint_max_is_exact() {
            let go = GoPlaintext::Number(serde_json::Number::from(u64::MAX));
            assert_eq!(
                go.to_plaintext_with_type(ColumnType::BigUInt).unwrap(),
                Plaintext::BigUInt(Some(u64::MAX))
            );
        }

        #[test]
        fn negative_integer_to_biguint_fails() {
            let err = int(-42)
                .to_plaintext_with_type(ColumnType::BigUInt)
                .unwrap_err();
            assert!(err.0.contains("negative"), "{}", err.0);
        }

        // --- Fractional / f64-form numbers still rejected for integer casts ---

        #[test]
        fn fractional_number_to_int_fails() {
            let err = num(42.5).to_plaintext_with_type(ColumnType::Int).unwrap_err();
            assert!(err.0.contains("Int"), "{}", err.0);
            // Reaches the exact-or-error f64 path, which reports the fractional part.
            assert!(err.0.contains("fractional") || err.0.contains("out of range"));
        }

        #[test]
        fn fractional_number_to_bigint_fails() {
            let err = num(42.5)
                .to_plaintext_with_type(ColumnType::BigInt)
                .unwrap_err();
            assert!(err.0.contains("BigInt"), "{}", err.0);
        }

        #[test]
        fn f64_form_out_of_range_to_bigint_fails() {
            // 2^63 as an f64 literal exceeds i64::MAX.
            let err = num(9_223_372_036_854_775_808.0)
                .to_plaintext_with_type(ColumnType::BigInt)
                .unwrap_err();
            assert!(err.0.contains("out of range"), "{}", err.0);
        }

        #[test]
        fn negative_fractional_to_biguint_fails() {
            let err = num(-42.0)
                .to_plaintext_with_type(ColumnType::BigUInt)
                .unwrap_err();
            assert!(err.0.contains("negative"), "{}", err.0);
        }

        // --- Decimal exactness (no f64 round-trip) ---

        #[test]
        fn decimal_from_fractional_literal() {
            let go: GoPlaintext = serde_json::from_str("0.1").unwrap();
            match go.to_plaintext_with_type(ColumnType::Decimal).unwrap() {
                Plaintext::Decimal(Some(d)) => assert_eq!(d.to_string(), "0.1"),
                other => panic!("expected Decimal, got {other:?}"),
            }
        }

        #[test]
        fn decimal_from_large_integer_is_exact() {
            // A large integer into a decimal column is exact — via the number's
            // decimal text, not f64 (which would round at 2^53).
            let go: GoPlaintext = serde_json::from_str("9007199254740995").unwrap();
            match go.to_plaintext_with_type(ColumnType::Decimal).unwrap() {
                Plaintext::Decimal(Some(d)) => assert_eq!(d.to_string(), "9007199254740995"),
                other => panic!("expected Decimal, got {other:?}"),
            }
        }

        #[test]
        fn errors_do_not_echo_the_value() {
            let err = int(5_000_000_001)
                .to_plaintext_with_type(ColumnType::Int)
                .unwrap_err();
            assert!(
                !err.0.contains("5000000001"),
                "error must not echo the plaintext value, got: {}",
                err.0
            );
        }

        #[test]
        fn test_boolean_to_boolean() {
            let result = GoPlaintext::Boolean(true)
                .to_plaintext_with_type(ColumnType::Boolean)
                .unwrap();
            assert_eq!(result, Plaintext::Boolean(Some(true)));
        }

        #[test]
        fn test_boolean_to_string_fails() {
            let result = GoPlaintext::Boolean(true).to_plaintext_with_type(ColumnType::Text);
            assert!(result.unwrap_err().0.contains("Cannot convert"));
        }

        #[test]
        fn test_jsonb_to_json() {
            let json_value = serde_json::json!({"key": "value"});
            let result = GoPlaintext::JsonB(json_value.clone())
                .to_plaintext_with_type(ColumnType::Json)
                .unwrap();
            assert_eq!(result, Plaintext::Json(Some(json_value)));
        }

        #[test]
        fn test_jsonb_to_string_fails() {
            let result = GoPlaintext::JsonB(serde_json::json!({"key": "value"}))
                .to_plaintext_with_type(ColumnType::Text);
            assert!(result.unwrap_err().0.contains("Cannot convert"));
        }

        #[test]
        fn test_iso_date_string_to_date() {
            let result = GoPlaintext::String("2025-03-14".to_string())
                .to_plaintext_with_type(ColumnType::Date)
                .unwrap();
            assert_eq!(
                result,
                Plaintext::NaiveDate(Some(NaiveDate::from_ymd_opt(2025, 3, 14).unwrap()))
            );
        }

        #[test]
        fn test_rfc3339_string_to_date_truncates_time() {
            let result = GoPlaintext::String("2025-03-14T12:34:56.789Z".to_string())
                .to_plaintext_with_type(ColumnType::Date)
                .unwrap();
            assert_eq!(
                result,
                Plaintext::NaiveDate(Some(NaiveDate::from_ymd_opt(2025, 3, 14).unwrap()))
            );
        }

        #[test]
        fn test_rfc3339_string_to_timestamp() {
            let result = GoPlaintext::String("2025-03-14T12:34:56.789Z".to_string())
                .to_plaintext_with_type(ColumnType::Timestamp)
                .unwrap();
            assert_eq!(result, Plaintext::Timestamp(Some(sample_dt())));
        }

        #[test]
        fn test_invalid_date_string_fails_without_echoing_input() {
            let err = GoPlaintext::String("not a date".to_string())
                .to_plaintext_with_type(ColumnType::Date)
                .expect_err("unparseable input must fail");
            assert!(err.0.contains("Cannot parse Date"), "{}", err.0);
            assert!(!err.0.contains("not a date"), "{}", err.0);
        }

        #[test]
        fn test_date_only_string_fails_as_timestamp() {
            let err = GoPlaintext::String("2025-03-14".to_string())
                .to_plaintext_with_type(ColumnType::Timestamp)
                .expect_err("date-only string must fail as Timestamp");
            assert!(err.0.contains("Cannot parse Timestamp"));
            assert!(!err.0.contains("2025-03-14"));
        }

        #[test]
        fn test_type_coercion_error_shows_valid_alternatives() {
            let err = GoPlaintext::String("hello".to_string())
                .to_plaintext_with_type(ColumnType::Int)
                .unwrap_err()
                .0;
            assert!(err.contains("Text"), "{}", err);
            assert!(err.contains("cast_as"), "{}", err);

            let err = GoPlaintext::JsonB(serde_json::json!({"a": 1}))
                .to_plaintext_with_type(ColumnType::Int)
                .unwrap_err()
                .0;
            assert!(err.contains("Json"), "{}", err);
        }
    }

    mod wire_deserialization {
        use super::*;

        #[test]
        fn integer_literal_deserializes_as_number_not_jsonb() {
            let go: GoPlaintext = serde_json::from_str("42").unwrap();
            assert_eq!(go, GoPlaintext::Number(serde_json::Number::from(42)));
        }

        #[test]
        fn large_integer_literal_deserializes_exactly() {
            let go: GoPlaintext = serde_json::from_str("9007199254740995").unwrap();
            match go {
                GoPlaintext::Number(n) => assert_eq!(n.as_i64(), Some(9_007_199_254_740_995)),
                other => panic!("expected Number, got {other:?}"),
            }
        }

        #[test]
        fn object_deserializes_as_jsonb() {
            let go: GoPlaintext = serde_json::from_str(r#"{"key":"value"}"#).unwrap();
            assert_eq!(go, GoPlaintext::JsonB(serde_json::json!({"key": "value"})));
        }

        #[test]
        fn string_deserializes_as_string() {
            let go: GoPlaintext = serde_json::from_str(r#""hello""#).unwrap();
            assert_eq!(go, GoPlaintext::String("hello".to_string()));
        }
    }
}
