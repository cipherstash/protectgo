//! Callback-driven authentication strategies for the C FFI boundary.
//!
//! protect-ffi's Go caller can supply a `getToken` callback (a C function
//! pointer plus an opaque `cgo.Handle`) that produces either a CTS service
//! token directly (`tokenProvider`) or a third-party OIDC JWT to federate
//! (`oidcFederation`). This module wraps that callback in the
//! [`stack_auth::AuthStrategy`] / [`stack_auth::OidcProvider`] traits so the
//! rest of the client is agnostic to how tokens are sourced.
//!
//! The callback may perform network I/O in Go, so it is always invoked from
//! [`tokio::task::spawn_blocking`]. It returns a C-heap (malloc'd) NUL-terminated
//! JSON string that Rust copies and frees with [`libc::free`]; a NULL return
//! means "the provider failed with no detail".

use std::ffi::CStr;
use std::future::Future;
use std::os::raw::c_char;

use serde::Deserialize;
use serde_json::Value;
use stack_auth::{
    AuthError, AuthStrategy, AutoStrategy, OidcFederationStrategy, OidcProvider, SecretToken,
    ServerError, ServiceToken,
};

/// The C `getToken` callback: `char *(*)(uint64_t handle)`.
///
/// Go returns a malloc'd (C heap, via `C.CString`) NUL-terminated JSON string,
/// or NULL to signal "provider failed with no detail".
pub type ProtectTokenFn = Option<unsafe extern "C" fn(handle: u64) -> *mut c_char>;

/// A resolved token callback: the raw C function pointer and the opaque handle
/// passed back to it verbatim on every invocation.
///
/// A bare function pointer plus a `u64` is `Send + Sync + Copy`, so this can be
/// held inside a long-lived client and moved into blocking tasks freely.
#[derive(Clone, Copy)]
pub(crate) struct GoTokenCallback {
    get_token: unsafe extern "C" fn(u64) -> *mut c_char,
    handle: u64,
}

impl GoTokenCallback {
    pub(crate) fn new(get_token: unsafe extern "C" fn(u64) -> *mut c_char, handle: u64) -> Self {
        Self { get_token, handle }
    }
}

/// The auth strategy declared in `newClient` options.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AuthStrategyOpts {
    #[serde(rename = "type")]
    pub strategy_type: AuthStrategyType,
    /// Optional CTS base URL override (oidcFederation only).
    pub base_url: Option<String>,
}

#[derive(Deserialize, PartialEq, Eq, Clone, Copy)]
pub(crate) enum AuthStrategyType {
    #[serde(rename = "oidcFederation")]
    OidcFederation,
    #[serde(rename = "tokenProvider")]
    TokenProvider,
}

/// Invoke the Go callback on a blocking thread and return its JSON result.
///
/// `None` means the callback returned NULL (or the blocking task panicked).
async fn invoke_token_callback(cb: GoTokenCallback) -> Option<String> {
    tokio::task::spawn_blocking(move || {
        // SAFETY: `cb.get_token` is a valid C function pointer supplied by the
        // Go caller; `cb.handle` is the opaque value it expects back.
        let ptr = unsafe { (cb.get_token)(cb.handle) };
        if ptr.is_null() {
            return None;
        }
        // SAFETY: Go guarantees a NUL-terminated C string when the pointer is
        // non-null.
        let owned = unsafe { CStr::from_ptr(ptr) }.to_string_lossy().into_owned();
        // SAFETY: the string was allocated by Go's C allocator (`C.CString` →
        // `malloc`), so it must be released with `free`.
        unsafe { libc::free(ptr as *mut libc::c_void) };
        Some(owned)
    })
    .await
    .unwrap_or(None)
}

/// A protect-ffi-internal error for a callback that returned a malformed shape
/// (not an auth-domain outcome). Kept as `Server` to match the shape such
/// protocol violations took before typed reconstruction existed.
fn strategy_protocol_error(msg: impl Into<String>) -> AuthError {
    AuthError::Server(ServerError(msg.into()))
}

/// Build an attributable message for a reconstructed auth failure. Falls back
/// to the failure `code` (or a generic phrase when that is absent too) so a
/// reconstructed error is never blank. Codes that map to a fixed [`AuthError`]
/// variant ignore this message; it only surfaces for the `Custom` fallthrough.
fn auth_failure_message(code: &str, message: String) -> String {
    if !message.is_empty() {
        message
    } else if !code.is_empty() {
        format!("auth failure: {code}")
    } else {
        "strategy.getToken failed with an unspecified auth failure".to_string()
    }
}

/// Reconstruct a [`stack_auth::AuthError`] from a `{ ...payload, type, error,
/// help?, url? }` failure object via [`AuthError::from_error_code`], so a
/// strategy failure crosses back into Rust as the real typed error —
/// preserving its code and any structured payload — rather than a flattened
/// `Server`. Unknown / foreign codes fall through to `AuthError::Custom`.
fn failure_to_auth_error(failure: &Value) -> AuthError {
    let obj = match failure.as_object() {
        Some(o) => o,
        None => return strategy_protocol_error("strategy.getToken failed"),
    };
    let code = obj.get("type").and_then(Value::as_str).unwrap_or_default();
    // The message lives on the nested `error` object.
    let message = obj
        .get("error")
        .and_then(Value::as_object)
        .and_then(|err| err.get("message"))
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    // Thread the structured payload: the whole failure object minus the
    // reserved keys.
    let mut payload = obj.clone();
    for key in ["type", "error", "help", "url"] {
        let _ = payload.remove(key);
    }
    AuthError::from_error_code(code, auth_failure_message(code, message), &payload)
}

/// Decode the callback's JSON envelope into a bare token string, or a typed
/// [`AuthError`].
///
/// Accepts the success form `{"token": "<string>"}` and the failure form
/// `{"failure": {...}}`. Every protocol violation maps to a precise
/// `AuthError::Server(ServerError(..))` message the contract pins.
fn decode_token_envelope(raw: Option<String>) -> Result<String, AuthError> {
    let raw = raw.ok_or_else(|| strategy_protocol_error("strategy callback returned no result"))?;
    let value: Value = serde_json::from_str(&raw)
        .map_err(|_| strategy_protocol_error("strategy callback did not return an object"))?;
    let obj = value
        .as_object()
        .ok_or_else(|| strategy_protocol_error("strategy callback did not return an object"))?;

    if let Some(failure) = obj.get("failure") {
        return Err(failure_to_auth_error(failure));
    }

    let token = obj
        .get("token")
        .ok_or_else(|| strategy_protocol_error("strategy callback result missing 'token' field"))?;
    let token = token
        .as_str()
        .ok_or_else(|| strategy_protocol_error("strategy callback 'token' field is not a string"))?;
    Ok(token.to_string())
}

/// [`OidcProvider`] that fetches a third-party OIDC JWT from the Go callback.
///
/// The callback's `token` is the raw third-party JWT (Clerk/Auth0/etc.);
/// [`OidcFederationStrategy`] exchanges it for a CTS service token.
pub(crate) struct GoOidcProvider {
    cb: GoTokenCallback,
}

impl GoOidcProvider {
    pub(crate) fn new(cb: GoTokenCallback) -> Self {
        Self { cb }
    }
}

impl OidcProvider for GoOidcProvider {
    fn fetch(&self) -> impl Future<Output = Result<SecretToken, AuthError>> + Send {
        let cb = self.cb;
        async move {
            let raw = invoke_token_callback(cb).await;
            let token = decode_token_envelope(raw)?;
            Ok(SecretToken::new(token))
        }
    }
}

/// [`AuthStrategy`] that treats the callback's `token` as a CTS service token
/// used directly. Caching is the Go side's responsibility — the callback is
/// invoked per ZeroKMS request.
pub(crate) struct GoProvidedTokenStrategy {
    cb: GoTokenCallback,
}

impl GoProvidedTokenStrategy {
    pub(crate) fn new(cb: GoTokenCallback) -> Self {
        Self { cb }
    }
}

impl AuthStrategy for &GoProvidedTokenStrategy {
    async fn get_token(self) -> Result<ServiceToken, AuthError> {
        let raw = invoke_token_callback(self.cb).await;
        let token = decode_token_envelope(raw)?;
        Ok(ServiceToken::new(SecretToken::new(token)))
    }
}

/// The auth strategy held by the client: the filesystem/env-backed
/// [`AutoStrategy`], the OIDC federation strategy, or the direct
/// callback-supplied token strategy.
///
/// `AutoStrategy` is boxed because it is substantially larger than the other
/// variants (clippy's `large_enum_variant`).
pub(crate) enum GoAuthStrategy {
    Auto(Box<AutoStrategy>),
    Oidc(Box<OidcFederationStrategy<GoOidcProvider>>),
    Provided(GoProvidedTokenStrategy),
}

impl AuthStrategy for &GoAuthStrategy {
    async fn get_token(self) -> Result<ServiceToken, AuthError> {
        match self {
            GoAuthStrategy::Auto(s) => (&**s).get_token().await,
            GoAuthStrategy::Oidc(s) => (&**s).get_token().await,
            GoAuthStrategy::Provided(s) => s.get_token().await,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    // A set of C callbacks returning fixed JSON envelopes, used to exercise the
    // decode protocol end-to-end through the same free/copy path production uses.
    unsafe extern "C" fn cb_bare_token(_h: u64) -> *mut c_char {
        CString::new(r#"{"token":"the-service-token"}"#)
            .unwrap()
            .into_raw()
    }
    unsafe extern "C" fn cb_null(_h: u64) -> *mut c_char {
        std::ptr::null_mut()
    }
    unsafe extern "C" fn cb_not_object(_h: u64) -> *mut c_char {
        CString::new("42").unwrap().into_raw()
    }
    unsafe extern "C" fn cb_missing_token(_h: u64) -> *mut c_char {
        CString::new(r#"{"nope":1}"#).unwrap().into_raw()
    }
    unsafe extern "C" fn cb_non_string_token(_h: u64) -> *mut c_char {
        CString::new(r#"{"token":123}"#).unwrap().into_raw()
    }
    unsafe extern "C" fn cb_malformed(_h: u64) -> *mut c_char {
        CString::new("{ not json").unwrap().into_raw()
    }
    unsafe extern "C" fn cb_failure_known(_h: u64) -> *mut c_char {
        CString::new(r#"{"failure":{"type":"ACCESS_DENIED","error":{"message":"nope"}}}"#)
            .unwrap()
            .into_raw()
    }
    unsafe extern "C" fn cb_failure_unknown(_h: u64) -> *mut c_char {
        CString::new(r#"{"failure":{"type":"WEIRD_CODE","error":{"message":"boom"}}}"#)
            .unwrap()
            .into_raw()
    }
    unsafe extern "C" fn cb_failure_no_message(_h: u64) -> *mut c_char {
        CString::new(r#"{"failure":{"type":"WEIRD_CODE"}}"#)
            .unwrap()
            .into_raw()
    }

    // These callbacks use CString::into_raw (Rust allocator), but the decode
    // path frees with libc::free. To exercise the pure decode logic without a
    // cross-allocator free, the tests below call decode_token_envelope directly
    // with the JSON the callback would return.

    fn envelope(json: &str) -> Result<String, AuthError> {
        decode_token_envelope(Some(json.to_string()))
    }

    #[test]
    fn bare_token_decodes() {
        assert_eq!(
            envelope(r#"{"token":"abc"}"#).unwrap(),
            "abc".to_string()
        );
    }

    // AuthError::Server prepends "Server error: " in its Display; Go matches on
    // the precise inner substring, so assert containment (and the Server code).

    #[test]
    fn null_result_is_a_precise_server_error() {
        let err = decode_token_envelope(None).unwrap_err();
        assert_eq!(err.error_code(), "SERVER_ERROR");
        assert!(err.to_string().contains("strategy callback returned no result"));
    }

    #[test]
    fn non_object_is_a_precise_server_error() {
        let err = envelope("42").unwrap_err();
        assert!(err
            .to_string()
            .contains("strategy callback did not return an object"));
    }

    #[test]
    fn malformed_json_is_a_precise_server_error() {
        let err = envelope("{ not json").unwrap_err();
        assert!(err
            .to_string()
            .contains("strategy callback did not return an object"));
    }

    #[test]
    fn missing_token_is_a_precise_server_error() {
        let err = envelope(r#"{"nope":1}"#).unwrap_err();
        assert!(err
            .to_string()
            .contains("strategy callback result missing 'token' field"));
    }

    #[test]
    fn non_string_token_is_a_precise_server_error() {
        let err = envelope(r#"{"token":123}"#).unwrap_err();
        assert!(err
            .to_string()
            .contains("strategy callback 'token' field is not a string"));
    }

    #[test]
    fn known_failure_code_maps_to_typed_variant() {
        let err = envelope(r#"{"failure":{"type":"ACCESS_DENIED","error":{"message":"nope"}}}"#)
            .unwrap_err();
        assert_eq!(err.error_code(), "ACCESS_DENIED");
        assert!(!matches!(err, AuthError::Custom(_)));
    }

    #[test]
    fn unknown_failure_code_falls_back_to_custom_with_message() {
        let err = envelope(r#"{"failure":{"type":"WEIRD_CODE","error":{"message":"boom"}}}"#)
            .unwrap_err();
        assert_eq!(err.error_code(), "CUSTOM");
        assert_eq!(err.to_string(), "boom");
    }

    #[test]
    fn failure_without_message_uses_code_in_message() {
        let err = envelope(r#"{"failure":{"type":"WEIRD_CODE"}}"#).unwrap_err();
        assert_eq!(err.error_code(), "CUSTOM");
        assert_eq!(err.to_string(), "auth failure: WEIRD_CODE");
    }

    // Exercise the full C-callback path (fn-ptr invocation + copy) for the
    // callbacks that use a Rust-allocated string. We leak rather than free to
    // avoid a cross-allocator free in the test (production frees Go's malloc'd
    // string with libc::free).
    #[tokio::test]
    async fn invoke_reads_bare_token_from_c_callback() {
        let cb = GoTokenCallback::new(cb_bare_token, 0);
        // Manually reproduce invoke without the libc::free (Rust-allocated).
        let ptr = unsafe { (cb.get_token)(cb.handle) };
        let s = unsafe { CString::from_raw(ptr) }.to_string_lossy().into_owned();
        assert_eq!(
            decode_token_envelope(Some(s)).unwrap(),
            "the-service-token"
        );
    }

    // Reference the remaining callbacks so they are not dead code; each is a
    // valid extern "C" fn pointer of the ProtectTokenFn shape.
    #[test]
    fn callbacks_are_valid_fn_pointers() {
        let _: [unsafe extern "C" fn(u64) -> *mut c_char; 8] = [
            cb_null,
            cb_not_object,
            cb_missing_token,
            cb_non_string_token,
            cb_malformed,
            cb_failure_known,
            cb_failure_unknown,
            cb_failure_no_message,
        ];
    }
}
