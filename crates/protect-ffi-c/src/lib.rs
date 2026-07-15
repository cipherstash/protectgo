// FFI functions intentionally accept raw pointers in `extern "C"` signatures
// that are validated (null-checked) before dereferencing. Marking every FFI
// function `unsafe` would change the C header signature, which is undesirable.
#![allow(clippy::not_unsafe_ptr_arg_deref)]

mod auth;
mod eql_v3;
mod go_plaintext;

use auth::{
    AuthStrategyType, GoAuthStrategy, GoOidcProvider, GoProvidedTokenStrategy, GoTokenCallback,
    ProtectTokenFn,
};
use cipherstash_client::{
    encryption::{EncryptionError, Plaintext, QueryOp, ScopedCipher, TypeParseError},
    eql::{
        encrypt_eql, EqlCiphertext, EqlEncryptOpts, EqlError, EqlOperation, EqlOutput,
        Identifier as EqlIdentifier, PreparedPlaintext,
    },
    schema::{
        column::{Index, IndexType},
        errors::ConfigError,
        CanonicalEncryptionConfig, ColumnConfig, Identifier,
    },
    zerokms::{
        self, FallbackKeyProvider, RecordDecryptError, SecretKey, WithContext,
        ZeroKMSBuilder, ZeroKMSBuilderError, ZeroKMSWithClientKey,
    },
    AuthError, AutoStrategy, IdentifiedBy, UnverifiedContext,
};
use cts_common::Crn;
use eql_v3::{
    encrypted_record_from_value, is_encrypted_value, query_output, storage_output,
    validate_eql_version, EncryptedOutput, EqlVersion, QueryOutput,
};
use go_plaintext::GoPlaintext;
use once_cell::sync::OnceCell;
use serde::{Deserialize, Serialize};
use std::{
    borrow::Cow,
    collections::{BTreeMap, HashMap},
    ffi::{CStr, CString},
    os::raw::c_char,
    sync::Arc,
};
use tokio::runtime::Runtime;

// ---------------------------------------------------------------------------
// C FFI result type
// ---------------------------------------------------------------------------

#[repr(C)]
pub struct CResult {
    pub success: bool,
    pub data: *const c_char,
    pub error: *const c_char,
}

impl Default for CResult {
    fn default() -> Self {
        Self {
            success: false,
            data: std::ptr::null(),
            error: std::ptr::null(),
        }
    }
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

type ScopedZeroKMS = ScopedCipher<GoAuthStrategy>;

/// Opaque client handle passed across the FFI boundary.
pub struct Client {
    cipher: Arc<ScopedZeroKMS>,
    zerokms: Arc<ZeroKMSWithClientKey<GoAuthStrategy>>,
    encrypt_config: Arc<HashMap<Identifier, ColumnConfig>>,
    /// EQL wire version this client emits. Decryption accepts both formats
    /// regardless of this setting.
    eql_version: EqlVersion,
}

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

/// What type of value was received in a query
#[derive(Debug, Clone)]
pub enum ReceivedKind {
    String(String),
    Number(f64),
    Boolean(bool),
    JsonObject,
    JsonArray,
    JsonScalar(String),
}

impl std::fmt::Display for ReceivedKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::String(s) => write!(f, "String \"{}\"", truncate_for_error(s, 30)),
            Self::Number(n) => write!(f, "Number {}", n),
            Self::Boolean(b) => write!(f, "Boolean {}", b),
            Self::JsonObject => write!(f, "JSON object"),
            Self::JsonArray => write!(f, "JSON array"),
            Self::JsonScalar(s) => write!(f, "JSON scalar {}", s),
        }
    }
}

impl ReceivedKind {
    /// Introspect JSON values so object/array are distinguished.
    pub fn from_json(value: &serde_json::Value) -> Self {
        match value {
            serde_json::Value::Object(_) => Self::JsonObject,
            serde_json::Value::Array(_) => Self::JsonArray,
            serde_json::Value::String(s) => Self::JsonScalar(format!("\"{}\"", s)),
            serde_json::Value::Number(n) => Self::JsonScalar(n.to_string()),
            serde_json::Value::Bool(b) => Self::JsonScalar(b.to_string()),
            serde_json::Value::Null => Self::JsonScalar("null".to_string()),
        }
    }
}

/// What type of value was expected
#[derive(Debug, Clone, Copy)]
pub enum ExpectedKind {
    JsonObjectOrArray,
    StringPathOrJsonObjectOrArray,
}

impl std::fmt::Display for ExpectedKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::JsonObjectOrArray => write!(f, "JSON object or array"),
            Self::StringPathOrJsonObjectOrArray => {
                write!(f, "String (JSON path) or JSON object/array")
            }
        }
    }
}

/// Query operation context for errors
#[derive(Debug, Clone, Copy)]
pub enum QueryOpKind {
    SteVecTerm,
    SteVecDefault,
}

impl std::fmt::Display for QueryOpKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SteVecTerm => write!(f, "ste_vec_term"),
            Self::SteVecDefault => write!(f, "ste_vec (default)"),
        }
    }
}

/// Wrapper for bounded display of potentially large strings
#[derive(Debug, Clone)]
pub struct Truncated<'a> {
    value: Cow<'a, str>,
    max_len: usize,
}

impl<'a> Truncated<'a> {
    pub fn new(value: impl Into<Cow<'a, str>>, max_len: usize) -> Self {
        Self {
            value: value.into(),
            max_len,
        }
    }

    pub fn path(value: impl Into<Cow<'a, str>>) -> Self {
        Self::new(value, 50)
    }
}

impl std::fmt::Display for Truncated<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.value.chars().count() <= self.max_len {
            write!(f, "{}", self.value)
        } else {
            let truncated: String = self.value.chars().take(self.max_len).collect();
            write!(f, "{}...", truncated)
        }
    }
}

/// Hints for InvalidQueryInput errors
#[derive(Debug, Clone, Copy)]
pub enum QueryInputHint {
    UseSelectorForPath,
    WrapInObject,
    WrapNumberInObject,
    WrapBooleanInObject,
    UsePathOrObject,
}

impl std::fmt::Display for QueryInputHint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UseSelectorForPath => write!(f, "For path queries like '$.field', use queryOp: 'ste_vec_selector'. For containment queries, wrap the value in an object: {{\"field\": \"value\"}}."),
            Self::WrapInObject => write!(f, "Wrap the value in a JSON object: {{\"field\": value}}."),
            Self::WrapNumberInObject => write!(f, "Wrap the number in a JSON object to query by value: {{\"field\": <number>}}."),
            Self::WrapBooleanInObject => write!(f, "Wrap the boolean in a JSON object to query by value: {{\"field\": <boolean>}}."),
            Self::UsePathOrObject => write!(f, "Use a JSON path string like '$.field' for path queries, or a JSON object like {{\"field\": value}} for containment queries."),
        }
    }
}

/// Reasons for JSON path errors
#[derive(Debug, Clone, Copy)]
pub enum JsonPathReason {
    Empty,
    MissingDollar,
}

impl std::fmt::Display for JsonPathReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => write!(f, "path cannot be empty"),
            Self::MissingDollar => write!(f, "path must start with '$'"),
        }
    }
}

/// Hints for JSON path errors
#[derive(Debug, Clone)]
pub enum JsonPathHint {
    TryPrefix(String),
}

impl std::fmt::Display for JsonPathHint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TryPrefix(path) => write!(f, "Try: '$.{}' or '$[\"{}\"]'.", path, path),
        }
    }
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("Credential error: {0}")]
    Credentials(String),
    #[error(transparent)]
    ZeroKMSBuilder(#[from] ZeroKMSBuilderError),
    #[error(transparent)]
    Auth(#[from] AuthError),
    #[error(transparent)]
    ZeroKMS(#[from] zerokms::Error),
    #[error(transparent)]
    TypeParse(#[from] TypeParseError),
    #[error(transparent)]
    Encryption(#[from] EncryptionError),
    #[error(transparent)]
    Eql(#[from] EqlError),
    #[error("protect-ffi invariant violation: {0}. This is a bug in protect-ffi.")]
    InvariantViolation(String),
    #[error("Unknown query operation: '{0}'")]
    UnknownQueryOp(String),
    #[error(transparent)]
    Parse(#[from] serde_json::Error),
    #[error("column {}.{} not found in Encrypt config", _0.table, _0.column)]
    UnknownColumn(Identifier),
    #[error(transparent)]
    RecordDecryptError(#[from] RecordDecryptError),
    #[error("Column '{column}' does not have a '{index_type}' index configured. {hint}")]
    MissingIndex {
        column: String,
        index_type: String,
        hint: String,
    },
    #[error(
        "Invalid query input for '{query_op}': received {received}, expected {expected}. {hint}"
    )]
    InvalidQueryInput {
        query_op: QueryOpKind,
        received: ReceivedKind,
        expected: ExpectedKind,
        hint: QueryInputHint,
    },
    #[error("Invalid JSON path '{path}': {reason}. {hint}")]
    InvalidJsonPath {
        path: Truncated<'static>,
        reason: JsonPathReason,
        hint: JsonPathHint,
    },
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[error("Configuration error for column '{table}.{column}': ste_vec index requires cast_as: 'json', but found cast_as: '{found_cast_as}'. Either change cast_as to 'json' or remove the ste_vec index.")]
    SteVecRequiresJsonCastAs {
        table: String,
        column: String,
        found_cast_as: String,
    },
    #[error("invalid eqlVersion {0}: expected 2 or 3")]
    InvalidEqlVersion(u8),
    #[error("Column '{column}' has no EQL v3 column type: {reason}. {hint}")]
    NoV3Domain {
        column: String,
        reason: String,
        hint: String,
    },
    #[error("EQL v3 conversion failed: {0}")]
    FromV2(#[from] eql_bindings::from_v2::FromV2Error),
    #[error("invalid ciphertext: {0}")]
    InvalidCiphertext(#[from] zerokms::DecryptError),
    #[error("null pointer error")]
    NullPointer,
    #[error("utf8 conversion error")]
    Utf8Error,
}

// ---------------------------------------------------------------------------
// Configuration / credential types
// ---------------------------------------------------------------------------

/// Credential fields shared by [`ClientOpts`].
#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct CredentialOpts {
    workspace_crn: Option<Crn>,
    access_key: Option<String>,
    client_id: Option<String>,
    client_key: Option<String>,
}

impl CredentialOpts {
    /// Build an [`AutoStrategy`] from optional workspace CRN and access key,
    /// falling back to env vars and profile store for unset fields.
    fn build_strategy(&self) -> Result<AutoStrategy, Error> {
        let mut builder = AutoStrategy::builder();
        if let Some(key) = self.access_key.as_ref() {
            builder = builder.with_access_key(key);
        }
        if let Some(crn) = self.workspace_crn.as_ref() {
            builder = builder.with_workspace_crn(crn.clone());
        }
        Ok(builder.detect()?)
    }

    /// Build an `Option<SecretKey>` from the `client_id` + `client_key` pair.
    ///
    /// Returns `None` if either field is missing (triggers `FallbackKeyProvider` to try the
    /// profile store). Returns `Err` if the values are present but invalid.
    fn secret_key(&self) -> Result<Option<SecretKey>, Error> {
        match (self.client_id.as_ref(), self.client_key.as_ref()) {
            (Some(id), Some(key)) => SecretKey::from_hex(id.clone(), key.clone())
                .map(Some)
                .map_err(|e| Error::Credentials(e.to_string())),
            _ => Ok(None),
        }
    }

    /// Build a key provider that resolves the client key from explicit fields,
    /// falling back to the profile store (`~/.cipherstash/secretkey.json`).
    fn build_key_provider(
        &self,
    ) -> Result<FallbackKeyProvider<Option<SecretKey>, stack_profile::ProfileStore>, Error> {
        Ok(FallbackKeyProvider::new(
            self.secret_key()?,
            stack_profile::ProfileStore::default(),
        ))
    }
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct ClientOpts {
    #[serde(flatten)]
    creds: CredentialOpts,
    keyset: Option<IdentifiedBy>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct NewClientOptions {
    encrypt_config: CanonicalEncryptionConfig,
    client_opts: Option<ClientOpts>,
    auth_strategy: Option<auth::AuthStrategyOpts>,
    /// EQL wire version to emit: 2 (default) or 3. Validated before any I/O.
    eql_version: Option<u8>,
}

// ---------------------------------------------------------------------------
// Request / response types
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
#[serde(untagged)]
enum DecryptResult {
    Success { data: GoPlaintext },
    Error { error: String },
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct EncryptOptions {
    plaintext: GoPlaintext,
    column: String,
    table: String,
    lock_context: Option<LockContext>,
    unverified_context: Option<UnverifiedContext>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct EncryptBulkOptions {
    plaintexts: Vec<PlaintextPayload>,
    unverified_context: Option<UnverifiedContext>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PlaintextPayload {
    plaintext: GoPlaintext,
    column: String,
    table: String,
    /// Lock context for this payload. Payloads with different lock_context values
    /// will be encrypted in separate batches to preserve per-payload context binding.
    lock_context: Option<LockContext>,
}

/// Options for encrypting a query term (search predicate)
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct EncryptQueryOptions {
    plaintext: GoPlaintext,
    column: String,
    table: String,
    /// The index type to use: "ste_vec", "match", "ore", "ope", "unique"
    index_type: String,
    /// The query operation: "default", "ste_vec_selector", "ste_vec_term"
    #[serde(default = "default_query_op")]
    query_op: String,
    lock_context: Option<LockContext>,
    unverified_context: Option<UnverifiedContext>,
}

fn default_query_op() -> String {
    "default".to_string()
}

/// Options for bulk query encryption
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct EncryptQueryBulkOptions {
    queries: Vec<QueryPayload>,
    unverified_context: Option<UnverifiedContext>,
}

/// Individual query payload for bulk operations
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct QueryPayload {
    plaintext: GoPlaintext,
    column: String,
    table: String,
    index_type: String,
    #[serde(default = "default_query_op")]
    query_op: String,
    lock_context: Option<LockContext>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DecryptOptions {
    /// Raw JSON payload — parsed internally so decrypt accepts BOTH the v2 and
    /// v3 wire formats regardless of the client's `eqlVersion`.
    ciphertext: serde_json::Value,
    lock_context: Option<LockContext>,
    unverified_context: Option<UnverifiedContext>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DecryptBulkOptions {
    ciphertexts: Vec<BulkDecryptPayload>,
    unverified_context: Option<UnverifiedContext>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct BulkDecryptPayload {
    /// Raw JSON payload — see [`DecryptOptions::ciphertext`].
    ciphertext: serde_json::Value,
    lock_context: Option<LockContext>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct LockContext {
    identity_claim: Vec<String>,
}

impl From<LockContext> for Vec<zerokms::Context> {
    fn from(val: LockContext) -> Self {
        val.identity_claim
            .into_iter()
            .map(zerokms::Context::IdentityClaim)
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Runtime management
// ---------------------------------------------------------------------------

static RUNTIME: OnceCell<Runtime> = OnceCell::new();

fn get_runtime() -> &'static Runtime {
    RUNTIME.get_or_init(|| Runtime::new().expect("Failed to create tokio runtime"))
}

// ---------------------------------------------------------------------------
// String conversion helpers
// ---------------------------------------------------------------------------

unsafe fn c_str_to_string(c_str: *const c_char) -> Result<String, Error> {
    if c_str.is_null() {
        return Err(Error::NullPointer);
    }
    CStr::from_ptr(c_str)
        .to_str()
        .map_err(|_| Error::Utf8Error)
        .map(|s| s.to_string())
}

fn string_to_c_str(s: String) -> *const c_char {
    match CString::new(s) {
        Ok(c_string) => c_string.into_raw(),
        Err(_) => std::ptr::null(),
    }
}

// ---------------------------------------------------------------------------
// Query helpers
// ---------------------------------------------------------------------------

/// Truncate a string for error messages
fn truncate_for_error(s: &str, max_len: usize) -> String {
    if max_len == 0 {
        return "...".to_string();
    }
    let mut out = String::new();
    let mut iter = s.chars();
    for _ in 0..max_len {
        match iter.next() {
            Some(ch) => out.push(ch),
            None => return s.to_string(),
        }
    }
    if iter.next().is_none() {
        return s.to_string();
    }
    format!("{}...", out)
}

/// Validate a JSON path string
fn validate_json_path(path: &str) -> Result<(), Error> {
    if path.is_empty() {
        return Err(Error::InvalidJsonPath {
            path: Truncated::path(path.to_string()),
            reason: JsonPathReason::Empty,
            hint: JsonPathHint::TryPrefix(path.to_string()),
        });
    }
    if !path.starts_with('$') {
        return Err(Error::InvalidJsonPath {
            path: Truncated::path(path.to_string()),
            reason: JsonPathReason::MissingDollar,
            hint: JsonPathHint::TryPrefix(path.to_string()),
        });
    }
    Ok(())
}

/// Get a description of what an index type is used for
fn index_type_description(index_type: &str) -> &'static str {
    match index_type {
        "ste_vec" => "JSON path and containment queries",
        "ore" => "range comparisons (<, >, <=, >=)",
        "ope" => "range comparisons (<, >, <=, >=)",
        "match" => "full-text search queries",
        "unique" => "exact match queries",
        _ => "unknown query type",
    }
}

/// Format available indexes on a column for error messages
fn format_available_indexes(column_config: &ColumnConfig) -> String {
    let available: Vec<&str> = column_config
        .indexes
        .iter()
        .map(|idx| match &idx.index_type {
            IndexType::SteVec { .. } => "ste_vec",
            IndexType::Match { .. } => "match",
            IndexType::Ore => "ore",
            IndexType::Ope => "ope",
            IndexType::Unique { .. } => "unique",
        })
        .collect();

    if available.is_empty() {
        "No indexes are configured for this column.".to_string()
    } else {
        format!("Available indexes: {}.", available.join(", "))
    }
}

/// Find the matching index from column config by index type name
fn find_index_for_type<'a>(
    column_config: &'a ColumnConfig,
    column_name: &str,
    index_type_name: &str,
) -> Result<&'a Index, Error> {
    column_config
        .indexes
        .iter()
        .find(|idx| {
            matches!(
                (&idx.index_type, index_type_name),
                (IndexType::SteVec { .. }, "ste_vec")
                    | (IndexType::Match { .. }, "match")
                    | (IndexType::Ore, "ore")
                    | (IndexType::Ope, "ope")
                    | (IndexType::Unique { .. }, "unique")
            )
        })
        .ok_or_else(|| {
            let available = format_available_indexes(column_config);
            let description = index_type_description(index_type_name);
            Error::MissingIndex {
                column: column_name.to_string(),
                index_type: index_type_name.to_string(),
                hint: format!(
                    "{} Add an '{}' index to enable {}.",
                    available, index_type_name, description
                ),
            }
        })
}

/// Parse query operation string to QueryOp enum
fn parse_query_op(query_op: &str) -> Result<QueryOp, Error> {
    match query_op {
        "default" => Ok(QueryOp::Default),
        "ste_vec_selector" => Ok(QueryOp::SteVecSelector),
        "ste_vec_term" => Ok(QueryOp::SteVecTerm),
        _ => Err(Error::UnknownQueryOp(query_op.to_string())),
    }
}

/// Inferred operation mode for query encryption.
#[derive(Debug, Clone, Copy)]
enum InferredQueryMode {
    /// Use EqlOperation::Query with the given QueryOp
    QueryMode(QueryOp),
    /// Use EqlOperation::Store (for JSON containment queries on ste_vec, and for
    /// v3 scalar Default queries whose operand must carry every domain term)
    StoreMode,
}

/// Convert GoPlaintext to Plaintext and infer the appropriate operation mode.
///
/// Query mode has different type semantics than storage mode:
/// - SteVecSelector: Always string (JSON path like "$.user.email") -> QueryMode
/// - SteVecTerm: Always JSON (fragment to match with @>) -> StoreMode (produces sv array)
/// - Default: For SteVec indexes, infers from plaintext type:
///   - String -> QueryMode with SteVecSelector (path queries)
///   - Json (Object/Array) -> StoreMode (containment queries need sv array)
///   - Other indexes use column's cast_type; QueryMode with Default under
///     eqlVersion 2, StoreMode under eqlVersion 3 (the v3 scalar query operand
///     must carry ALL the column domain's terms, generated exactly as storage
///     encryption generates them and hoisted by query_output).
fn to_query_plaintext(
    go_plaintext: &GoPlaintext,
    query_op: QueryOp,
    index_type: &IndexType,
    column_type: cipherstash_client::schema::column::ColumnType,
    eql_version: EqlVersion,
) -> Result<(Plaintext, InferredQueryMode), Error> {
    use cipherstash_client::schema::column::ColumnType;

    match query_op {
        QueryOp::SteVecSelector => {
            if let GoPlaintext::String(path) = go_plaintext {
                validate_json_path(path)?;
            }
            // Force Text conversion regardless of column type
            let plaintext = go_plaintext.to_plaintext_with_type(ColumnType::Text)?;
            Ok((
                plaintext,
                InferredQueryMode::QueryMode(QueryOp::SteVecSelector),
            ))
        }
        QueryOp::SteVecTerm => {
            match go_plaintext {
                GoPlaintext::String(s) => {
                    return Err(Error::InvalidQueryInput {
                        query_op: QueryOpKind::SteVecTerm,
                        received: ReceivedKind::String(s.clone()),
                        expected: ExpectedKind::JsonObjectOrArray,
                        hint: QueryInputHint::UseSelectorForPath,
                    });
                }
                GoPlaintext::Number(n) => {
                    return Err(Error::InvalidQueryInput {
                        query_op: QueryOpKind::SteVecTerm,
                        received: ReceivedKind::Number(n.as_f64().unwrap_or(f64::NAN)),
                        expected: ExpectedKind::JsonObjectOrArray,
                        hint: QueryInputHint::WrapNumberInObject,
                    });
                }
                GoPlaintext::Boolean(b) => {
                    return Err(Error::InvalidQueryInput {
                        query_op: QueryOpKind::SteVecTerm,
                        received: ReceivedKind::Boolean(*b),
                        expected: ExpectedKind::JsonObjectOrArray,
                        hint: QueryInputHint::WrapBooleanInObject,
                    });
                }
                GoPlaintext::JsonB(_) => {
                    // Expected type - proceed
                }
            }
            let plaintext = go_plaintext.to_plaintext_with_type(ColumnType::Json)?;
            Ok((plaintext, InferredQueryMode::StoreMode))
        }
        QueryOp::Default => {
            if matches!(index_type, IndexType::SteVec { .. }) {
                match go_plaintext {
                    GoPlaintext::String(path) => {
                        validate_json_path(path)?;
                        let plaintext = go_plaintext.to_plaintext_with_type(ColumnType::Text)?;
                        Ok((
                            plaintext,
                            InferredQueryMode::QueryMode(QueryOp::SteVecSelector),
                        ))
                    }
                    GoPlaintext::JsonB(_) => {
                        let plaintext = go_plaintext.to_plaintext_with_type(ColumnType::Json)?;
                        Ok((plaintext, InferredQueryMode::StoreMode))
                    }
                    GoPlaintext::Number(n) => Err(Error::InvalidQueryInput {
                        query_op: QueryOpKind::SteVecDefault,
                        received: ReceivedKind::Number(n.as_f64().unwrap_or(f64::NAN)),
                        expected: ExpectedKind::StringPathOrJsonObjectOrArray,
                        hint: QueryInputHint::UsePathOrObject,
                    }),
                    GoPlaintext::Boolean(b) => Err(Error::InvalidQueryInput {
                        query_op: QueryOpKind::SteVecDefault,
                        received: ReceivedKind::Boolean(*b),
                        expected: ExpectedKind::StringPathOrJsonObjectOrArray,
                        hint: QueryInputHint::UsePathOrObject,
                    }),
                }
            } else {
                let plaintext = go_plaintext.to_plaintext_with_type(column_type)?;
                let mode = match eql_version {
                    EqlVersion::V2 => InferredQueryMode::QueryMode(QueryOp::Default),
                    // v3 scalar operands need every term of the column's domain,
                    // so run Store mode and let query_output hoist them.
                    EqlVersion::V3 => InferredQueryMode::StoreMode,
                };
                Ok((plaintext, mode))
            }
        }
    }
}

/// Resolve a query payload's column config and build its [`PreparedPlaintext`].
///
/// The single seam shared by both encrypt-query entry points, so the
/// version-dependent mode logic can never diverge. Returns the resolved
/// `&ColumnConfig` alongside the prepared plaintext — the caller needs it again
/// for [`query_output`].
fn prepare_query_plaintext<'a>(
    encrypt_config: &'a HashMap<Identifier, ColumnConfig>,
    table: &str,
    column: &str,
    go_plaintext: &GoPlaintext,
    index_type_name: &str,
    query_op_name: &str,
    eql_version: EqlVersion,
) -> Result<(PreparedPlaintext<'a>, &'a ColumnConfig), Error> {
    let ident = Identifier::new(table.to_string(), column.to_string());
    let column_config = encrypt_config
        .get(&ident)
        .ok_or(Error::UnknownColumn(ident))?;

    let index = find_index_for_type(column_config, column, index_type_name)?;
    let query_op = parse_query_op(query_op_name)?;

    let (plaintext, inferred_mode) = to_query_plaintext(
        go_plaintext,
        query_op,
        &index.index_type,
        column_config.cast_type,
        eql_version,
    )?;

    let eql_operation = match inferred_mode {
        InferredQueryMode::QueryMode(qop) => EqlOperation::Query(&index.index_type, qop),
        InferredQueryMode::StoreMode => EqlOperation::Store,
    };

    Ok((
        PreparedPlaintext::new(
            Cow::Borrowed(column_config),
            EqlIdentifier::new(table, column),
            plaintext,
            eql_operation,
        ),
        column_config,
    ))
}

// ---------------------------------------------------------------------------
// Core async implementations
// ---------------------------------------------------------------------------

async fn new_client_impl(
    opts: NewClientOptions,
    callback: Option<GoTokenCallback>,
) -> Result<Client, Error> {
    // Validate before any network I/O: a bad eqlVersion fails fast.
    let eql_version = validate_eql_version(opts.eql_version)?;
    let client_opts = opts.client_opts.unwrap_or_default();

    let auth = match opts.auth_strategy {
        None => GoAuthStrategy::Auto(Box::new(client_opts.creds.build_strategy()?)),
        Some(strat) => {
            let cb = callback.ok_or_else(|| {
                Error::Credentials("auth strategy requires a token callback".to_string())
            })?;
            match strat.strategy_type {
                AuthStrategyType::OidcFederation => {
                    let crn = client_opts.creds.workspace_crn.clone().ok_or_else(|| {
                        Error::Credentials(
                            "workspaceCrn is required for the oidcFederation auth strategy"
                                .to_string(),
                        )
                    })?;
                    let strategy =
                        stack_auth::OidcFederationStrategy::builder(crn, GoOidcProvider::new(cb))
                            .maybe_base_url(strat.base_url)?
                            .build()?;
                    GoAuthStrategy::Oidc(Box::new(strategy))
                }
                AuthStrategyType::TokenProvider => {
                    GoAuthStrategy::Provided(GoProvidedTokenStrategy::new(cb))
                }
            }
        }
    };

    let zerokms = ZeroKMSBuilder::new(auth)
        .with_key_provider(client_opts.creds.build_key_provider()?)
        .build()
        .await?;

    let zerokms = Arc::new(zerokms);
    let cipher = ScopedZeroKMS::init(zerokms.clone(), client_opts.keyset).await?;

    Ok(Client {
        cipher: Arc::new(cipher),
        zerokms,
        encrypt_config: Arc::new(build_config_map(opts.encrypt_config)?),
        eql_version,
    })
}

/// Turn the canonical config into the per-column map.
///
/// `ConfigError::SteVecRequiresJson` is remapped to
/// [`Error::SteVecRequiresJsonCastAs`] so its Display keeps the
/// `ste_vec index requires cast_as` substring the Go side matches on (upstream
/// phrases it as `requires plaintext_type: json`). Every other config error
/// passes through transparently.
fn build_config_map(
    config: CanonicalEncryptionConfig,
) -> Result<HashMap<Identifier, ColumnConfig>, Error> {
    config.into_config_map().map_err(|e| match e {
        ConfigError::SteVecRequiresJson {
            table,
            column,
            found_plaintext_type,
        } => Error::SteVecRequiresJsonCastAs {
            table,
            column,
            found_cast_as: found_plaintext_type,
        },
        other => Error::Config(other),
    })
}

async fn encrypt_impl(client: &Client, opts: EncryptOptions) -> Result<EncryptedOutput, Error> {
    let ident = Identifier::new(opts.table.clone(), opts.column.clone());

    let column_config = client
        .encrypt_config
        .get(&ident)
        .ok_or_else(|| Error::UnknownColumn(ident.clone()))?;

    let plaintext = opts
        .plaintext
        .to_plaintext_with_type(column_config.cast_type)?;

    let eql_ident = EqlIdentifier::new(&opts.table, &opts.column);
    let prepared = PreparedPlaintext::new(
        Cow::Borrowed(column_config),
        eql_ident,
        plaintext,
        EqlOperation::Store,
    );

    let eql_opts = EqlEncryptOpts {
        keyset_id: None,
        lock_context: Cow::Owned(opts.lock_context.map(Into::into).unwrap_or_default()),
        unverified_context: opts.unverified_context.map(Cow::Owned),
        index_types: None,
        decryption_policy: None,
    };

    let mut encrypted = encrypt_eql(client.cipher.clone(), vec![prepared], &eql_opts).await?;
    let eql_ciphertext = into_store_ciphertext(encrypted.remove(0))?;

    storage_output(eql_ciphertext, client.eql_version, column_config)
}

async fn encrypt_bulk_impl(
    client: &Client,
    opts: EncryptBulkOptions,
) -> Result<Vec<EncryptedOutput>, Error> {
    // Group payloads by lock_context for batch processing.
    // BTreeMap provides deterministic ordering of groups.
    let mut groups: BTreeMap<Vec<String>, Vec<(usize, PlaintextPayload)>> = BTreeMap::new();

    for (idx, payload) in opts.plaintexts.into_iter().enumerate() {
        let key = payload
            .lock_context
            .as_ref()
            .map(|lc| lc.identity_claim.clone())
            .unwrap_or_default();
        groups.entry(key).or_default().push((idx, payload));
    }

    let total_count: usize = groups.values().map(|g| g.len()).sum();
    let mut results: Vec<Option<EncryptedOutput>> = (0..total_count).map(|_| None).collect();

    for (lock_context_claims, payloads) in groups {
        let lock_context: Vec<zerokms::Context> = lock_context_claims
            .into_iter()
            .map(zerokms::Context::IdentityClaim)
            .collect();

        let mut prepared_plaintexts = Vec::with_capacity(payloads.len());
        let mut payload_data: Vec<(usize, Identifier)> = Vec::with_capacity(payloads.len());

        for (original_idx, payload) in payloads {
            let ident = Identifier::new(payload.table.clone(), payload.column.clone());

            let column_config = client
                .encrypt_config
                .get(&ident)
                .ok_or_else(|| Error::UnknownColumn(ident.clone()))?;

            let plaintext = payload
                .plaintext
                .to_plaintext_with_type(column_config.cast_type)?;

            let eql_ident = EqlIdentifier::new(&payload.table, &payload.column);
            let prepared = PreparedPlaintext::new(
                Cow::Borrowed(column_config),
                eql_ident,
                plaintext,
                EqlOperation::Store,
            );

            prepared_plaintexts.push(prepared);
            payload_data.push((original_idx, ident));
        }

        let eql_opts = EqlEncryptOpts {
            keyset_id: None,
            lock_context: Cow::Owned(lock_context),
            unverified_context: opts.unverified_context.as_ref().map(Cow::Borrowed),
            index_types: None,
            decryption_policy: None,
        };

        let encrypted = encrypt_eql(client.cipher.clone(), prepared_plaintexts, &eql_opts).await?;

        for (eql_output, (original_idx, ident)) in encrypted.into_iter().zip(payload_data) {
            let column_config = client
                .encrypt_config
                .get(&ident)
                .ok_or_else(|| Error::UnknownColumn(ident.clone()))?;
            results[original_idx] = Some(storage_output(
                into_store_ciphertext(eql_output)?,
                client.eql_version,
                column_config,
            )?);
        }
    }

    results
        .into_iter()
        .enumerate()
        .map(|(i, opt)| {
            opt.ok_or_else(|| {
                Error::InvariantViolation(format!("Missing encryption result for index {}", i))
            })
        })
        .collect::<Result<Vec<_>, _>>()
}

async fn encrypt_query_impl(
    client: &Client,
    opts: EncryptQueryOptions,
) -> Result<QueryOutput, Error> {
    let (prepared, column_config) = prepare_query_plaintext(
        &client.encrypt_config,
        &opts.table,
        &opts.column,
        &opts.plaintext,
        &opts.index_type,
        &opts.query_op,
        client.eql_version,
    )?;

    let eql_opts = EqlEncryptOpts {
        keyset_id: None,
        lock_context: Cow::Owned(opts.lock_context.map(Into::into).unwrap_or_default()),
        unverified_context: opts.unverified_context.map(Cow::Owned),
        index_types: None,
        decryption_policy: None,
    };

    let mut encrypted = encrypt_eql(client.cipher.clone(), vec![prepared], &eql_opts).await?;
    let eql_output = encrypted.remove(0);

    query_output(eql_output, client.eql_version, column_config)
}

async fn encrypt_query_bulk_impl(
    client: &Client,
    opts: EncryptQueryBulkOptions,
) -> Result<Vec<QueryOutput>, Error> {
    let mut groups: BTreeMap<Vec<String>, Vec<(usize, QueryPayload)>> = BTreeMap::new();

    for (idx, payload) in opts.queries.into_iter().enumerate() {
        let key = payload
            .lock_context
            .as_ref()
            .map(|lc| lc.identity_claim.clone())
            .unwrap_or_default();
        groups.entry(key).or_default().push((idx, payload));
    }

    let total_count: usize = groups.values().map(|g| g.len()).sum();
    let mut results: Vec<Option<QueryOutput>> = (0..total_count).map(|_| None).collect();

    for (lock_context_claims, payloads) in groups {
        let lock_context: Vec<zerokms::Context> = lock_context_claims
            .into_iter()
            .map(zerokms::Context::IdentityClaim)
            .collect();

        let mut prepared_plaintexts = Vec::with_capacity(payloads.len());
        let mut payload_data: Vec<(usize, &ColumnConfig)> = Vec::with_capacity(payloads.len());

        for (original_idx, payload) in &payloads {
            let (prepared, column_config) = prepare_query_plaintext(
                &client.encrypt_config,
                &payload.table,
                &payload.column,
                &payload.plaintext,
                &payload.index_type,
                &payload.query_op,
                client.eql_version,
            )?;

            prepared_plaintexts.push(prepared);
            payload_data.push((*original_idx, column_config));
        }

        let eql_opts = EqlEncryptOpts {
            keyset_id: None,
            lock_context: Cow::Owned(lock_context),
            unverified_context: opts.unverified_context.as_ref().map(Cow::Borrowed),
            index_types: None,
            decryption_policy: None,
        };

        let encrypted = encrypt_eql(client.cipher.clone(), prepared_plaintexts, &eql_opts).await?;

        for (eql_output, (original_idx, column_config)) in encrypted.into_iter().zip(payload_data) {
            results[original_idx] =
                Some(query_output(eql_output, client.eql_version, column_config)?);
        }
    }

    results
        .into_iter()
        .enumerate()
        .map(|(i, opt)| {
            opt.ok_or_else(|| {
                Error::InvariantViolation(format!("Missing query result for index {}", i))
            })
        })
        .collect::<Result<Vec<_>, _>>()
}

async fn decrypt_impl(client: &Client, opts: DecryptOptions) -> Result<GoPlaintext, Error> {
    let lock_context = opts.lock_context.map(Into::into).unwrap_or_default();
    let encrypted_record = encrypted_record_from_value(opts.ciphertext, lock_context)?;

    let plaintext = client
        .zerokms
        .decrypt_single(encrypted_record, None, opts.unverified_context.as_ref())
        .await
        .map_err(Error::from)
        .and_then(|bytes| Plaintext::from_slice(bytes.as_slice()).map_err(Error::from))?;

    GoPlaintext::try_from(plaintext).map_err(Error::from)
}

async fn decrypt_bulk_impl(
    client: &Client,
    opts: DecryptBulkOptions,
) -> Result<Vec<GoPlaintext>, Error> {
    let encrypted_records: Vec<WithContext<'static>> = opts
        .ciphertexts
        .into_iter()
        .map(|payload| {
            let lock_context = payload.lock_context.map(Into::into).unwrap_or_default();
            encrypted_record_from_value(payload.ciphertext, lock_context)
        })
        .collect::<Result<Vec<_>, Error>>()?;

    let decrypted = client
        .zerokms
        .decrypt(encrypted_records, None, opts.unverified_context.as_ref())
        .await?;

    let plaintexts = decrypted
        .into_iter()
        .map(|bytes| Plaintext::from_slice(&bytes).and_then(GoPlaintext::try_from))
        .collect::<Result<Vec<GoPlaintext>, TypeParseError>>()?;

    Ok(plaintexts)
}

async fn decrypt_bulk_fallible_impl(
    client: &Client,
    opts: DecryptBulkOptions,
) -> Result<Vec<DecryptResult>, Error> {
    // Decode each ciphertext independently so a single invalid payload turns
    // into a per-item error rather than aborting the whole batch.
    let parsed: Vec<Result<WithContext<'static>, Error>> = opts
        .ciphertexts
        .into_iter()
        .map(|payload| {
            let lock_context = payload.lock_context.map(Into::into).unwrap_or_default();
            encrypted_record_from_value(payload.ciphertext, lock_context)
        })
        .collect();

    let mut results: Vec<Option<DecryptResult>> = (0..parsed.len()).map(|_| None).collect();
    let mut valid_records: Vec<WithContext<'static>> = Vec::with_capacity(parsed.len());
    let mut valid_indices: Vec<usize> = Vec::with_capacity(parsed.len());

    for (idx, item) in parsed.into_iter().enumerate() {
        match item {
            Ok(record) => {
                valid_records.push(record);
                valid_indices.push(idx);
            }
            Err(e) => {
                results[idx] = Some(DecryptResult::Error {
                    error: e.to_string(),
                });
            }
        }
    }

    let decrypted: Vec<Result<Vec<u8>, RecordDecryptError>> = client
        .zerokms
        .decrypt_fallible(valid_records, opts.unverified_context.map(Cow::Owned))
        .await?;

    for (item, idx) in decrypted.into_iter().zip(valid_indices) {
        results[idx] = Some(match item {
            Ok(bytes) => match Plaintext::from_slice(&bytes)
                .map_err(Error::from)
                .and_then(|p| GoPlaintext::try_from(p).map_err(Error::from))
            {
                Ok(data) => DecryptResult::Success { data },
                Err(e) => DecryptResult::Error {
                    error: e.to_string(),
                },
            },
            Err(e) => DecryptResult::Error {
                error: e.to_string(),
            },
        });
    }

    results
        .into_iter()
        .enumerate()
        .map(|(i, opt)| {
            opt.ok_or_else(|| {
                Error::InvariantViolation(format!("missing decrypt_fallible result at index {i}"))
            })
        })
        .collect::<Result<Vec<_>, _>>()
}

// ---------------------------------------------------------------------------
// Crypto helpers
// ---------------------------------------------------------------------------

/// Decode a v2 [`EqlCiphertext`] into the record + lock-context pair zerokms
/// decrypts.
///
/// The SteVec root ciphertext is always `sv[0]` (mirrors upstream
/// `SteVec::into_root_ciphertext`, which is not exposed on the wire type).
/// Shared with [`eql_v3`] via `crate::encrypted_record_from_mp_base85`.
pub(crate) fn encrypted_record_from_mp_base85(
    encrypted: EqlCiphertext,
    encryption_context: Vec<zerokms::Context>,
) -> Result<WithContext<'static>, Error> {
    let encrypted_record = match encrypted {
        EqlCiphertext::Encrypted(payload) => payload.ciphertext,
        EqlCiphertext::SteVec(payload) => {
            payload
                .ste_vec
                .into_iter()
                .next()
                .ok_or_else(|| {
                    Error::InvariantViolation("Missing root entry in SteVec EQL payload".to_string())
                })?
                .ciphertext
        }
    };

    Ok(WithContext {
        record: encrypted_record,
        context: Cow::Owned(encryption_context),
    })
}

/// Extract the [`EqlCiphertext`] from a Store-mode [`EqlOutput`].
///
/// Used by `encrypt` / `encrypt_bulk`, which always run with
/// `EqlOperation::Store` and therefore must produce storage ciphertexts.
fn into_store_ciphertext(output: EqlOutput) -> Result<EqlCiphertext, Error> {
    match output {
        EqlOutput::Store(ciphertext) => Ok(ciphertext),
        EqlOutput::Query(_) => Err(Error::InvariantViolation(
            "encrypt_eql returned a query payload for a store-mode encryption".to_string(),
        )),
    }
}

// ---------------------------------------------------------------------------
// Exported C FFI functions
// ---------------------------------------------------------------------------

#[no_mangle]
pub extern "C" fn protect_new_client(
    options_json: *const c_char,
    get_token: ProtectTokenFn,
    token_handle: u64,
) -> CResult {
    let mut result = CResult::default();

    let options_str = match unsafe { c_str_to_string(options_json) } {
        Ok(s) => s,
        Err(e) => {
            result.error = string_to_c_str(e.to_string());
            return result;
        }
    };

    let callback = get_token.map(|f| GoTokenCallback::new(f, token_handle));

    let rt = get_runtime();
    match rt.block_on(async {
        let opts: NewClientOptions = serde_json::from_str(&options_str)?;
        new_client_impl(opts, callback).await
    }) {
        Ok(client) => {
            let client_box = Box::new(client);
            let client_ptr = Box::into_raw(client_box) as *const Client;
            result.success = true;
            result.data = client_ptr as *const c_char;
        }
        Err(e) => {
            result.error = string_to_c_str(e.to_string());
        }
    }

    result
}

/// Run an operation that parses `options_json`, executes an async impl against
/// the client, and serializes the result to JSON. Centralizes the null-check,
/// UTF-8 decode, runtime dispatch, and error stringification every exported
/// operation shares.
fn run_client_op<Opts, Out, F, Fut>(
    client_ptr: *const Client,
    options_json: *const c_char,
    run: F,
) -> CResult
where
    Opts: for<'de> Deserialize<'de>,
    Out: Serialize,
    F: FnOnce(&'static Client, Opts) -> Fut,
    Fut: std::future::Future<Output = Result<Out, Error>>,
{
    let mut result = CResult::default();

    if client_ptr.is_null() {
        result.error = string_to_c_str("Client pointer is null".to_string());
        return result;
    }

    // SAFETY: null-checked above; the pointer originates from `Box::into_raw`
    // in `protect_new_client` and outlives this call.
    let client: &Client = unsafe { &*client_ptr };

    let options_str = match unsafe { c_str_to_string(options_json) } {
        Ok(s) => s,
        Err(e) => {
            result.error = string_to_c_str(e.to_string());
            return result;
        }
    };

    let rt = get_runtime();
    let outcome = rt.block_on(async {
        let opts: Opts = serde_json::from_str(&options_str)?;
        run(client, opts).await
    });

    match outcome {
        Ok(value) => match serde_json::to_string(&value) {
            Ok(json) => {
                result.success = true;
                result.data = string_to_c_str(json);
            }
            Err(e) => {
                result.error = string_to_c_str(e.to_string());
            }
        },
        Err(e) => {
            result.error = string_to_c_str(e.to_string());
        }
    }

    result
}

#[no_mangle]
pub extern "C" fn protect_encrypt(
    client_ptr: *const Client,
    options_json: *const c_char,
) -> CResult {
    run_client_op(client_ptr, options_json, |client, opts: EncryptOptions| {
        encrypt_impl(client, opts)
    })
}

#[no_mangle]
pub extern "C" fn protect_encrypt_bulk(
    client_ptr: *const Client,
    options_json: *const c_char,
) -> CResult {
    run_client_op(
        client_ptr,
        options_json,
        |client, opts: EncryptBulkOptions| encrypt_bulk_impl(client, opts),
    )
}

#[no_mangle]
pub extern "C" fn protect_encrypt_query(
    client_ptr: *const Client,
    options_json: *const c_char,
) -> CResult {
    run_client_op(
        client_ptr,
        options_json,
        |client, opts: EncryptQueryOptions| encrypt_query_impl(client, opts),
    )
}

#[no_mangle]
pub extern "C" fn protect_encrypt_query_bulk(
    client_ptr: *const Client,
    options_json: *const c_char,
) -> CResult {
    run_client_op(
        client_ptr,
        options_json,
        |client, opts: EncryptQueryBulkOptions| encrypt_query_bulk_impl(client, opts),
    )
}

#[no_mangle]
pub extern "C" fn protect_decrypt(
    client_ptr: *const Client,
    options_json: *const c_char,
) -> CResult {
    run_client_op(client_ptr, options_json, |client, opts: DecryptOptions| {
        decrypt_impl(client, opts)
    })
}

#[no_mangle]
pub extern "C" fn protect_decrypt_bulk(
    client_ptr: *const Client,
    options_json: *const c_char,
) -> CResult {
    run_client_op(
        client_ptr,
        options_json,
        |client, opts: DecryptBulkOptions| decrypt_bulk_impl(client, opts),
    )
}

#[no_mangle]
pub extern "C" fn protect_decrypt_bulk_fallible(
    client_ptr: *const Client,
    options_json: *const c_char,
) -> CResult {
    run_client_op(
        client_ptr,
        options_json,
        |client, opts: DecryptBulkOptions| decrypt_bulk_fallible_impl(client, opts),
    )
}

/// Check if a JSON value is a valid EQL ciphertext (v2 or v3 storage payload).
#[no_mangle]
pub extern "C" fn protect_is_encrypted(value_json: *const c_char) -> bool {
    let value_str = match unsafe { c_str_to_string(value_json) } {
        Ok(s) => s,
        Err(_) => return false,
    };
    match serde_json::from_str::<serde_json::Value>(&value_str) {
        Ok(value) => is_encrypted_value(&value),
        Err(_) => false,
    }
}

#[no_mangle]
pub extern "C" fn protect_free_client(client_ptr: *const Client) {
    if !client_ptr.is_null() {
        unsafe {
            let _ = Box::from_raw(client_ptr as *mut Client);
        }
    }
}

#[no_mangle]
pub extern "C" fn protect_free_string(str_ptr: *const c_char) {
    if !str_ptr.is_null() {
        unsafe {
            let _ = CString::from_raw(str_ptr as *mut c_char);
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    mod truncate_for_error_tests {
        use super::*;

        #[test]
        fn handles_non_ascii_without_panicking() {
            let input = "\u{e9}\u{e9}\u{e9}";
            assert_eq!(truncate_for_error(input, 1), "\u{e9}...");
        }

        #[test]
        fn returns_ellipsis_when_max_len_zero() {
            assert_eq!(truncate_for_error("abc", 0), "...");
        }

        #[test]
        fn returns_full_string_when_within_limit() {
            assert_eq!(truncate_for_error("abc", 5), "abc");
        }

        #[test]
        fn returns_full_string_when_at_limit() {
            assert_eq!(truncate_for_error("abc", 3), "abc");
        }

        #[test]
        fn truncates_when_over_limit() {
            assert_eq!(truncate_for_error("abcdef", 3), "abc...");
        }
    }

    mod is_encrypted_tests {
        use super::*;
        use cipherstash_client::eql::{
            EncryptedPayload, EqlCiphertext, Identifier as EqlIdentifier, SteVecEntry,
            SteVecEntryTerm, SteVecPayload, EQL_SCHEMA_VERSION,
        };
        use cipherstash_client::zerokms::EncryptedRecord;
        use serde_json::json;
        use std::ffi::CString;

        fn dummy_encrypted_record() -> EncryptedRecord {
            EncryptedRecord {
                iv: Default::default(),
                ciphertext: vec![1; 16],
                tag: vec![2; 16],
                descriptor: "users/email".to_string(),
                keyset_id: None,
                decryption_policy: None,
            }
        }

        fn check_is_encrypted(value: serde_json::Value) -> bool {
            let json_str = serde_json::to_string(&value).unwrap();
            let c_str = CString::new(json_str).unwrap();
            protect_is_encrypted(c_str.as_ptr())
        }

        #[test]
        fn valid_scalar_ciphertext_is_encrypted() {
            let payload = EqlCiphertext::Encrypted(EncryptedPayload {
                version: EQL_SCHEMA_VERSION,
                identifier: EqlIdentifier::new("users", "email"),
                ciphertext: dummy_encrypted_record(),
                hmac_256: None,
                bloom_filter: None,
                ore_block_u64_8_256: None,
                ope_cllw: None,
            });
            let value = serde_json::to_value(&payload).unwrap();
            assert_eq!(value["k"], "ct");
            assert!(check_is_encrypted(value));
        }

        #[test]
        fn valid_ste_vec_ciphertext_is_encrypted() {
            let payload = EqlCiphertext::SteVec(SteVecPayload {
                version: EQL_SCHEMA_VERSION,
                identifier: EqlIdentifier::new("users", "profile"),
                ste_vec: vec![SteVecEntry {
                    selector: "deadbeef".into(),
                    ciphertext: dummy_encrypted_record(),
                    is_array: None,
                    term: SteVecEntryTerm::Hmac {
                        hmac_256: "feedface".into(),
                    },
                }],
            });
            let value = serde_json::to_value(&payload).unwrap();
            assert_eq!(value["k"], "sv");
            assert!(check_is_encrypted(value));
        }

        #[test]
        fn invalid_ciphertext_is_not_encrypted() {
            assert!(!check_is_encrypted(json!({"random": "data"})));
        }

        #[test]
        fn missing_discriminator_is_not_encrypted() {
            assert!(!check_is_encrypted(json!({
                "i": {"t": "users", "c": "email"},
                "v": 2
            })));
        }

        #[test]
        fn unknown_discriminator_is_not_encrypted() {
            assert!(!check_is_encrypted(json!({
                "k": "wat",
                "i": {"t": "users", "c": "email"},
                "v": 2
            })));
        }
    }

    mod lock_context_grouping {
        use std::collections::BTreeMap;

        fn group_by_lock_context(
            payloads: Vec<(String, Option<Vec<String>>)>,
        ) -> BTreeMap<Vec<String>, Vec<(usize, String)>> {
            let mut groups: BTreeMap<Vec<String>, Vec<(usize, String)>> = BTreeMap::new();
            for (idx, (data, lock_context)) in payloads.into_iter().enumerate() {
                let key = lock_context.unwrap_or_default();
                groups.entry(key).or_default().push((idx, data));
            }
            groups
        }

        #[test]
        fn same_lock_context_groups_together() {
            let payloads = vec![
                ("a".to_string(), Some(vec!["user:1".to_string()])),
                ("b".to_string(), Some(vec!["user:1".to_string()])),
                ("c".to_string(), Some(vec!["user:1".to_string()])),
            ];
            let groups = group_by_lock_context(payloads);
            assert_eq!(groups.len(), 1);
            assert_eq!(groups[&vec!["user:1".to_string()]].len(), 3);
        }

        #[test]
        fn different_lock_contexts_separate_groups() {
            let payloads = vec![
                ("a".to_string(), Some(vec!["user:1".to_string()])),
                ("b".to_string(), Some(vec!["user:2".to_string()])),
                ("c".to_string(), Some(vec!["user:1".to_string()])),
            ];
            let groups = group_by_lock_context(payloads);
            assert_eq!(groups.len(), 2);
            assert_eq!(groups[&vec!["user:1".to_string()]].len(), 2);
            assert_eq!(groups[&vec!["user:2".to_string()]].len(), 1);
        }

        #[test]
        fn none_lock_context_groups_together() {
            let payloads = vec![
                ("a".to_string(), None),
                ("b".to_string(), None),
                ("c".to_string(), Some(vec!["user:1".to_string()])),
            ];
            let groups = group_by_lock_context(payloads);
            assert_eq!(groups.len(), 2);
            assert_eq!(groups[&vec![]].len(), 2);
            assert_eq!(groups[&vec!["user:1".to_string()]].len(), 1);
        }

        #[test]
        fn preserves_original_indices() {
            let payloads = vec![
                ("a".to_string(), Some(vec!["user:2".to_string()])),
                ("b".to_string(), Some(vec!["user:1".to_string()])),
                ("c".to_string(), Some(vec!["user:2".to_string()])),
            ];
            let groups = group_by_lock_context(payloads);
            let user1_group = &groups[&vec!["user:1".to_string()]];
            assert_eq!(user1_group[0], (1, "b".to_string()));
            let user2_group = &groups[&vec!["user:2".to_string()]];
            assert_eq!(user2_group[0], (0, "a".to_string()));
            assert_eq!(user2_group[1], (2, "c".to_string()));
        }
    }

    mod config_parsing {
        use super::*;
        use serde_json::json;

        fn parse_config(value: serde_json::Value) -> Result<HashMap<Identifier, ColumnConfig>, Error> {
            let config: CanonicalEncryptionConfig = serde_json::from_value(value).unwrap();
            build_config_map(config)
        }

        #[test]
        fn canonical_config_maps_columns() {
            let map = parse_config(json!({
                "v": 1,
                "tables": {
                    "users": {
                        "email": { "cast_as": "text", "indexes": { "unique": {} } },
                        "age": { "cast_as": "small_int", "indexes": { "ore": {} } }
                    }
                }
            }))
            .unwrap();
            let email = map
                .get(&Identifier::new("users", "email"))
                .expect("email column");
            assert_eq!(
                email.cast_type,
                cipherstash_client::schema::column::ColumnType::Text
            );
            let age = map
                .get(&Identifier::new("users", "age"))
                .expect("age column");
            assert_eq!(
                age.cast_type,
                cipherstash_client::schema::column::ColumnType::SmallInt
            );
        }

        #[test]
        fn ste_vec_on_non_json_column_keeps_go_substring() {
            let err = parse_config(json!({
                "v": 1,
                "tables": {
                    "users": {
                        "profile": {
                            "cast_as": "text",
                            "indexes": { "ste_vec": { "prefix": "users/profile" } }
                        }
                    }
                }
            }))
            .unwrap_err();
            let msg = err.to_string();
            // The substring Go's inferSentinel matches on for ErrSteVecRequiresJSON.
            assert!(
                msg.contains("ste_vec index requires cast_as"),
                "error must keep the Go sentinel substring: {msg}"
            );
            assert!(msg.contains("users"));
            assert!(msg.contains("profile"));
        }
    }

    mod query_op_parsing {
        use super::*;

        #[test]
        fn parse_query_op_default() {
            assert!(matches!(parse_query_op("default"), Ok(QueryOp::Default)));
        }

        #[test]
        fn parse_query_op_ste_vec_selector() {
            assert!(matches!(
                parse_query_op("ste_vec_selector"),
                Ok(QueryOp::SteVecSelector)
            ));
        }

        #[test]
        fn parse_query_op_ste_vec_term() {
            assert!(matches!(
                parse_query_op("ste_vec_term"),
                Ok(QueryOp::SteVecTerm)
            ));
        }

        #[test]
        fn parse_query_op_unknown_returns_error() {
            let err = parse_query_op("unknown").unwrap_err();
            assert!(err.to_string().contains("Unknown query operation"));
        }
    }

    mod find_index_for_type_tests {
        use super::*;
        use cipherstash_client::schema::column::{ColumnMode, ColumnType, Index, IndexType, Tokenizer};

        fn make_column_config_with_indexes(indexes: Vec<Index>) -> ColumnConfig {
            ColumnConfig {
                name: "test_column".to_string(),
                cast_type: ColumnType::Text,
                indexes,
                in_place: false,
                mode: ColumnMode::Encrypted,
            }
        }

        #[test]
        fn find_ste_vec_index() {
            let config = make_column_config_with_indexes(vec![Index::new(IndexType::SteVec {
                prefix: "test".to_string(),
                term_filters: vec![],
                array_index_mode: Default::default(),
                mode: Default::default(),
            })]);
            let result = find_index_for_type(&config, "test_column", "ste_vec");
            assert!(matches!(
                result.unwrap().index_type,
                IndexType::SteVec { .. }
            ));
        }

        #[test]
        fn find_ore_index() {
            let config = make_column_config_with_indexes(vec![Index::new(IndexType::Ore)]);
            assert!(matches!(
                find_index_for_type(&config, "test_column", "ore")
                    .unwrap()
                    .index_type,
                IndexType::Ore
            ));
        }

        #[test]
        fn find_unique_index() {
            let config = make_column_config_with_indexes(vec![Index::new(IndexType::Unique {
                token_filters: vec![],
            })]);
            assert!(matches!(
                find_index_for_type(&config, "test_column", "unique")
                    .unwrap()
                    .index_type,
                IndexType::Unique { .. }
            ));
        }

        #[test]
        fn missing_index_returns_error() {
            let config = make_column_config_with_indexes(vec![Index::new(IndexType::Ore)]);
            let err = find_index_for_type(&config, "test_column", "ste_vec").unwrap_err();
            assert!(err.to_string().contains("does not have"));
            assert!(err.to_string().contains("test_column"));
        }

        #[test]
        fn missing_index_error_includes_column_and_suggestions() {
            let config = make_column_config_with_indexes(vec![
                Index::new(IndexType::Ore),
                Index::new(IndexType::Match {
                    tokenizer: Tokenizer::Standard,
                    token_filters: vec![],
                    k: 6,
                    m: 2048,
                    include_original: false,
                }),
            ]);
            let err_msg = find_index_for_type(&config, "email", "ste_vec")
                .unwrap_err()
                .to_string();
            assert!(err_msg.contains("email"));
            assert!(err_msg.contains("ste_vec"));
            assert!(err_msg.contains("ore"));
            assert!(err_msg.contains("match"));
        }
    }

    mod query_inference_tests {
        use super::*;
        use cipherstash_client::encryption::Plaintext;
        use cipherstash_client::schema::column::{ColumnType, IndexType, Tokenizer};

        fn ste_vec_index() -> IndexType {
            IndexType::SteVec {
                prefix: "test/col".to_string(),
                term_filters: vec![],
                array_index_mode: Default::default(),
                mode: Default::default(),
            }
        }

        #[test]
        fn ste_vec_default_with_string_infers_selector() {
            let result = to_query_plaintext(
                &GoPlaintext::String("$.user.email".to_string()),
                QueryOp::Default,
                &ste_vec_index(),
                ColumnType::Json,
                EqlVersion::V2,
            );
            assert!(matches!(
                result,
                Ok((
                    Plaintext::Text(Some(_)),
                    InferredQueryMode::QueryMode(QueryOp::SteVecSelector)
                ))
            ));
        }

        #[test]
        fn ste_vec_default_with_object_infers_store_mode() {
            let result = to_query_plaintext(
                &GoPlaintext::JsonB(serde_json::json!({"role": "admin"})),
                QueryOp::Default,
                &ste_vec_index(),
                ColumnType::Json,
                EqlVersion::V2,
            );
            assert!(matches!(
                result,
                Ok((Plaintext::Json(Some(_)), InferredQueryMode::StoreMode))
            ));
        }

        #[test]
        fn ste_vec_default_with_number_returns_error() {
            let result = to_query_plaintext(
                &GoPlaintext::Number(serde_json::Number::from(42)),
                QueryOp::Default,
                &ste_vec_index(),
                ColumnType::Json,
                EqlVersion::V2,
            );
            assert!(result.unwrap_err().to_string().contains("Invalid query input"));
        }

        #[test]
        fn non_ste_vec_default_uses_column_type_under_v2() {
            let result = to_query_plaintext(
                &GoPlaintext::String("search term".to_string()),
                QueryOp::Default,
                &IndexType::Match {
                    tokenizer: Tokenizer::Standard,
                    token_filters: vec![],
                    k: 6,
                    m: 2048,
                    include_original: true,
                },
                ColumnType::Text,
                EqlVersion::V2,
            );
            assert!(matches!(
                result,
                Ok((
                    Plaintext::Text(Some(_)),
                    InferredQueryMode::QueryMode(QueryOp::Default)
                ))
            ));
        }

        #[test]
        fn scalar_default_under_v3_infers_store_mode() {
            let result = to_query_plaintext(
                &GoPlaintext::String("hello".to_string()),
                QueryOp::Default,
                &IndexType::Unique {
                    token_filters: vec![],
                },
                ColumnType::Text,
                EqlVersion::V3,
            );
            assert!(matches!(
                result,
                Ok((Plaintext::Text(Some(_)), InferredQueryMode::StoreMode))
            ));
        }

        #[test]
        fn ste_vec_term_with_string_error_is_helpful() {
            let result = to_query_plaintext(
                &GoPlaintext::String("admin".to_string()),
                QueryOp::SteVecTerm,
                &ste_vec_index(),
                ColumnType::Json,
                EqlVersion::V2,
            );
            let err_msg = result.unwrap_err().to_string();
            assert!(err_msg.contains("ste_vec_term"));
            assert!(err_msg.contains("String"));
        }

        #[test]
        fn invalid_json_path_error() {
            let result = to_query_plaintext(
                &GoPlaintext::String("user.email".to_string()),
                QueryOp::SteVecSelector,
                &ste_vec_index(),
                ColumnType::Json,
                EqlVersion::V2,
            );
            let err_msg = result.unwrap_err().to_string();
            assert!(err_msg.contains("user.email"));
            assert!(err_msg.contains('$'));
        }
    }
}
