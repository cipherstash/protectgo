// FFI functions intentionally accept raw pointers in `extern "C"` signatures
// that are validated (null-checked) before dereferencing. Marking every FFI
// function `unsafe` would change the C header signature, which is undesirable.
#![allow(clippy::not_unsafe_ptr_arg_deref)]

mod encrypt_config;
mod go_plaintext;

use cipherstash_client::{
    credentials::ServiceToken,
    encryption::{EncryptionError, Plaintext, QueryOp, ScopedCipher, TypeParseError},
    eql::{
        encrypt_eql, EqlCiphertext, EqlEncryptOpts, EqlError, EqlOperation,
        Identifier as EqlIdentifier, PreparedPlaintext,
    },
    schema::{
        column::{Index, IndexType},
        ColumnConfig,
    },
    zerokms::{
        self, FallbackKeyProvider, RecordDecryptError, SecretKey, WithContext, ZeroKMSBuilder,
        ZeroKMSBuilderError, ZeroKMSWithClientKey,
    },
    AuthError, AutoStrategy, IdentifiedBy, UnverifiedContext,
};
use cts_common::Crn;
use encrypt_config::{EncryptConfig, Identifier};
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

type ScopedZeroKMS = ScopedCipher<AutoStrategy>;

/// Opaque client handle passed across the FFI boundary.
#[derive(Clone)]
pub struct Client {
    cipher: Arc<ScopedZeroKMS>,
    zerokms: Arc<ZeroKMSWithClientKey<AutoStrategy>>,
    encrypt_config: Arc<HashMap<Identifier, ColumnConfig>>,
}

/// Re-export EqlCiphertext as Encrypted for backward compatibility.
///
/// This is a unified structure that contains the identifier, version, and the encrypted body
/// with all associated cryptographic searchable encrypted metadata (SEM).
///
/// Note: The ciphertext field (c) is serialized in MessagePack Base85 format.
pub type Encrypted = EqlCiphertext;

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
    #[error("Configuration error: {0}")]
    Config(String),
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
    #[error("Configuration error for column '{table}.{column}': ste_vec index requires cast_as: 'json', but found cast_as: '{found_cast_as}'. Either change cast_as to 'json' or remove the ste_vec index.")]
    SteVecRequiresJsonCastAs {
        table: String,
        column: String,
        found_cast_as: String,
    },
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
                .map_err(|e| Error::Config(e.to_string())),
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
    encrypt_config: EncryptConfig,
    client_opts: Option<ClientOpts>,
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
    service_token: Option<ServiceToken>,
    unverified_context: Option<UnverifiedContext>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct EncryptBulkOptions {
    plaintexts: Vec<PlaintextPayload>,
    service_token: Option<ServiceToken>,
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
    /// The index type to use: "ste_vec", "match", "ore", "unique"
    index_type: String,
    /// The query operation: "default", "ste_vec_selector", "ste_vec_term"
    #[serde(default = "default_query_op")]
    query_op: String,
    lock_context: Option<LockContext>,
    service_token: Option<ServiceToken>,
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
    service_token: Option<ServiceToken>,
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
    ciphertext: Encrypted,
    lock_context: Option<LockContext>,
    service_token: Option<ServiceToken>,
    unverified_context: Option<UnverifiedContext>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DecryptBulkOptions {
    ciphertexts: Vec<BulkDecryptPayload>,
    service_token: Option<ServiceToken>,
    unverified_context: Option<UnverifiedContext>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct BulkDecryptPayload {
    ciphertext: Encrypted,
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
///
/// This determines which EqlOperation to use:
/// - QueryMode: Use EqlOperation::Query (standard query encryption)
/// - StoreMode: Use EqlOperation::Store (for containment queries that need sv array)
#[derive(Debug, Clone, Copy)]
enum InferredQueryMode {
    /// Use EqlOperation::Query with the given QueryOp
    QueryMode(QueryOp),
    /// Use EqlOperation::Store (for JSON containment queries on ste_vec)
    StoreMode,
}

/// Convert GoPlaintext to Plaintext and infer the appropriate operation mode.
///
/// Returns both the converted Plaintext and the inferred operation mode.
///
/// Query mode has different type semantics than storage mode:
/// - SteVecSelector: Always string (JSON path like "$.user.email") -> QueryMode
/// - SteVecTerm: Always JSON (fragment to match with @>) -> StoreMode (produces sv array)
/// - Default: For SteVec indexes, infers from plaintext type:
///   - String -> QueryMode with SteVecSelector (path queries)
///   - JsonB (Object/Array) -> StoreMode (containment queries need sv array)
///   - Other indexes use column's cast_type and QueryMode with Default
fn to_query_plaintext(
    go_plaintext: &GoPlaintext,
    query_op: QueryOp,
    index_type: &IndexType,
    column_type: cipherstash_client::schema::column::ColumnType,
) -> Result<(Plaintext, InferredQueryMode), Error> {
    use cipherstash_client::schema::column::ColumnType;

    match query_op {
        QueryOp::SteVecSelector => {
            // Selector queries expect a string path like "$.user.email"
            // Validate the path if we have a string
            if let GoPlaintext::String(path) = go_plaintext {
                validate_json_path(path)?;
            }
            // Force Utf8Str conversion regardless of column type
            let plaintext = go_plaintext.to_plaintext_with_type(ColumnType::Utf8Str)?;
            Ok((
                plaintext,
                InferredQueryMode::QueryMode(QueryOp::SteVecSelector),
            ))
        }
        QueryOp::SteVecTerm => {
            // Term queries expect a JSON fragment to match with @>
            // Provide helpful errors for wrong types
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
                        received: ReceivedKind::Number(*n),
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
                    // This is the expected type - proceed
                }
            }
            // Use Store mode to produce sv array for containment matching
            let plaintext = go_plaintext.to_plaintext_with_type(ColumnType::JsonB)?;
            Ok((plaintext, InferredQueryMode::StoreMode))
        }
        QueryOp::Default => {
            // For SteVec indexes with Default queryOp, infer from plaintext type
            if matches!(index_type, IndexType::SteVec { .. }) {
                match go_plaintext {
                    GoPlaintext::String(path) => {
                        // String -> selector (path queries like "$.user.email")
                        validate_json_path(path)?;
                        let plaintext = go_plaintext.to_plaintext_with_type(ColumnType::Utf8Str)?;
                        Ok((
                            plaintext,
                            InferredQueryMode::QueryMode(QueryOp::SteVecSelector),
                        ))
                    }
                    GoPlaintext::JsonB(_) => {
                        // Object/Array -> Store mode for containment queries
                        // This produces sv array needed for @> operator matching
                        let plaintext = go_plaintext.to_plaintext_with_type(ColumnType::JsonB)?;
                        Ok((plaintext, InferredQueryMode::StoreMode))
                    }
                    GoPlaintext::Number(n) => Err(Error::InvalidQueryInput {
                        query_op: QueryOpKind::SteVecDefault,
                        received: ReceivedKind::Number(*n),
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
                // Non-SteVec indexes: use column's storage type (original behavior)
                let plaintext = go_plaintext.to_plaintext_with_type(column_type)?;
                Ok((plaintext, InferredQueryMode::QueryMode(QueryOp::Default)))
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Core async implementations
// ---------------------------------------------------------------------------

async fn new_client_impl(opts: NewClientOptions) -> Result<Client, Error> {
    let client_opts = opts.client_opts.unwrap_or_default();

    let strategy = client_opts.creds.build_strategy()?;
    let zerokms = ZeroKMSBuilder::new(strategy)
        .with_key_provider(client_opts.creds.build_key_provider()?)
        .build()
        .await?;

    let zerokms = Arc::new(zerokms);
    let cipher = ScopedZeroKMS::init(zerokms.clone(), client_opts.keyset).await?;

    let client = Client {
        cipher: Arc::new(cipher),
        zerokms,
        encrypt_config: Arc::new(opts.encrypt_config.into_config_map()?),
    };

    Ok(client)
}

async fn encrypt_impl(client: &Client, opts: EncryptOptions) -> Result<Encrypted, Error> {
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
        service_token: opts.service_token.map(Cow::Owned),
        unverified_context: opts.unverified_context.map(Cow::Owned),
        index_types: None,
    };

    let mut encrypted = encrypt_eql(client.cipher.clone(), vec![prepared], &eql_opts).await?;
    Ok(encrypted.remove(0))
}

async fn encrypt_bulk_impl(
    client: &Client,
    opts: EncryptBulkOptions,
) -> Result<Vec<Encrypted>, Error> {
    // Group payloads by lock_context for batch processing
    // BTreeMap provides deterministic ordering of groups
    let mut groups: BTreeMap<Vec<String>, Vec<(usize, PlaintextPayload)>> = BTreeMap::new();

    for (idx, payload) in opts.plaintexts.into_iter().enumerate() {
        let key = payload
            .lock_context
            .as_ref()
            .map(|lc| lc.identity_claim.clone())
            .unwrap_or_default();
        groups.entry(key).or_default().push((idx, payload));
    }

    // Pre-allocate results vector
    let total_count: usize = groups.values().map(|g| g.len()).sum();
    let mut results: Vec<Option<EqlCiphertext>> = (0..total_count).map(|_| None).collect();

    // Process each lock_context group
    for (lock_context_claims, payloads) in groups {
        let lock_context: Vec<zerokms::Context> = lock_context_claims
            .into_iter()
            .map(zerokms::Context::IdentityClaim)
            .collect();

        // Build PreparedPlaintext items for this group
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
            service_token: opts.service_token.as_ref().map(Cow::Borrowed),
            unverified_context: opts.unverified_context.as_ref().map(Cow::Borrowed),
            index_types: None,
        };

        let encrypted = encrypt_eql(client.cipher.clone(), prepared_plaintexts, &eql_opts).await?;

        // Place results back in original order
        for (eql_ciphertext, (original_idx, _ident)) in encrypted.into_iter().zip(payload_data) {
            results[original_idx] = Some(eql_ciphertext);
        }
    }

    // Unwrap all results (all should be Some)
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
) -> Result<EqlCiphertext, Error> {
    let ident = Identifier::new(opts.table.clone(), opts.column.clone());

    let column_config = client
        .encrypt_config
        .get(&ident)
        .ok_or_else(|| Error::UnknownColumn(ident.clone()))?;

    // Find the requested index type from column config
    let index = find_index_for_type(column_config, &opts.column, &opts.index_type)?;
    let query_op = parse_query_op(&opts.query_op)?;

    // Infer type and operation mode from plaintext
    let (plaintext, inferred_mode) = to_query_plaintext(
        &opts.plaintext,
        query_op,
        &index.index_type,
        column_config.cast_type,
    )?;

    // Select the appropriate EqlOperation based on inferred mode
    let eql_operation = match inferred_mode {
        InferredQueryMode::QueryMode(qop) => EqlOperation::Query(&index.index_type, qop),
        InferredQueryMode::StoreMode => EqlOperation::Store,
    };

    let eql_ident = EqlIdentifier::new(&opts.table, &opts.column);
    let prepared = PreparedPlaintext::new(
        Cow::Borrowed(column_config),
        eql_ident,
        plaintext,
        eql_operation,
    );

    let eql_opts = EqlEncryptOpts {
        keyset_id: None,
        lock_context: Cow::Owned(opts.lock_context.map(Into::into).unwrap_or_default()),
        service_token: opts.service_token.map(Cow::Owned),
        unverified_context: opts.unverified_context.map(Cow::Owned),
        index_types: None,
    };

    let mut encrypted = encrypt_eql(client.cipher.clone(), vec![prepared], &eql_opts).await?;
    Ok(encrypted.remove(0))
}

async fn encrypt_query_bulk_impl(
    client: &Client,
    opts: EncryptQueryBulkOptions,
) -> Result<Vec<EqlCiphertext>, Error> {
    // Group payloads by lock_context (same pattern as encrypt_bulk)
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
    let mut results: Vec<Option<EqlCiphertext>> = (0..total_count).map(|_| None).collect();

    for (lock_context_claims, payloads) in groups {
        let lock_context: Vec<zerokms::Context> = lock_context_claims
            .into_iter()
            .map(zerokms::Context::IdentityClaim)
            .collect();

        let mut prepared_plaintexts = Vec::with_capacity(payloads.len());
        let mut original_indices = Vec::with_capacity(payloads.len());

        for (original_idx, payload) in payloads {
            let ident = Identifier::new(payload.table.clone(), payload.column.clone());
            let column_config = client
                .encrypt_config
                .get(&ident)
                .ok_or_else(|| Error::UnknownColumn(ident.clone()))?;

            let index = find_index_for_type(column_config, &payload.column, &payload.index_type)?;
            let query_op = parse_query_op(&payload.query_op)?;

            let (plaintext, inferred_mode) = to_query_plaintext(
                &payload.plaintext,
                query_op,
                &index.index_type,
                column_config.cast_type,
            )?;

            let eql_operation = match inferred_mode {
                InferredQueryMode::QueryMode(qop) => EqlOperation::Query(&index.index_type, qop),
                InferredQueryMode::StoreMode => EqlOperation::Store,
            };

            let eql_ident = EqlIdentifier::new(&payload.table, &payload.column);
            let prepared = PreparedPlaintext::new(
                Cow::Borrowed(column_config),
                eql_ident,
                plaintext,
                eql_operation,
            );

            prepared_plaintexts.push(prepared);
            original_indices.push(original_idx);
        }

        let eql_opts = EqlEncryptOpts {
            keyset_id: None,
            lock_context: Cow::Owned(lock_context),
            service_token: opts.service_token.as_ref().map(Cow::Borrowed),
            unverified_context: opts.unverified_context.as_ref().map(Cow::Borrowed),
            index_types: None,
        };

        let encrypted = encrypt_eql(client.cipher.clone(), prepared_plaintexts, &eql_opts).await?;

        for (eql_ciphertext, original_idx) in encrypted.into_iter().zip(original_indices) {
            results[original_idx] = Some(eql_ciphertext);
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
    let encrypted_record = encrypted_record_from_mp_base85(opts.ciphertext, lock_context)?;

    let plaintext = client
        .zerokms
        .decrypt_single(
            encrypted_record,
            None,
            opts.service_token.map(Cow::Owned),
            opts.unverified_context.as_ref(),
        )
        .await
        .map_err(Error::from)
        .and_then(|bytes| Plaintext::from_slice(bytes.as_slice()).map_err(Error::from))?;

    GoPlaintext::try_from(plaintext).map_err(Error::from)
}

async fn decrypt_bulk_impl(
    client: &Client,
    opts: DecryptBulkOptions,
) -> Result<Vec<GoPlaintext>, Error> {
    let ciphertexts: Vec<(Encrypted, Vec<zerokms::Context>)> = opts
        .ciphertexts
        .into_iter()
        .map(|payload| {
            let lock_context = payload.lock_context.map(Into::into).unwrap_or_default();
            (payload.ciphertext, lock_context)
        })
        .collect();

    let encrypted_records: Vec<WithContext<'static>> = ciphertexts
        .into_iter()
        .map(|(ciphertext, encryption_context)| {
            encrypted_record_from_mp_base85(ciphertext, encryption_context)
        })
        .collect::<Result<Vec<_>, Error>>()?;

    let decrypted = client
        .zerokms
        .decrypt(
            encrypted_records,
            None,
            opts.service_token.map(Cow::Owned),
            opts.unverified_context.as_ref(),
        )
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
    let ciphertexts: Vec<(Encrypted, Vec<zerokms::Context>)> = opts
        .ciphertexts
        .into_iter()
        .map(|payload| {
            let lock_context = payload.lock_context.map(Into::into).unwrap_or_default();
            (payload.ciphertext, lock_context)
        })
        .collect();

    let encrypted_records: Vec<WithContext<'static>> = ciphertexts
        .into_iter()
        .map(|(ciphertext, encryption_context)| {
            encrypted_record_from_mp_base85(ciphertext, encryption_context)
        })
        .collect::<Result<Vec<_>, Error>>()?;

    let decrypted: Vec<Result<Vec<u8>, RecordDecryptError>> = client
        .zerokms
        .decrypt_fallible(
            encrypted_records,
            opts.service_token.map(Cow::Owned),
            opts.unverified_context.map(Cow::Owned),
        )
        .await?;

    let plaintexts: Vec<Result<GoPlaintext, Error>> = decrypted
        .into_iter()
        .map(|item: Result<Vec<u8>, RecordDecryptError>| {
            item.map_err(Error::from).and_then(|bytes| {
                Plaintext::from_slice(&bytes)
                    .map_err(Error::from)
                    .and_then(|e| GoPlaintext::try_from(e).map_err(Error::from))
            })
        })
        .collect();

    let results = plaintexts
        .into_iter()
        .map(|result| match result {
            Ok(data) => DecryptResult::Success { data },
            Err(err) => DecryptResult::Error {
                error: err.to_string(),
            },
        })
        .collect();

    Ok(results)
}

// ---------------------------------------------------------------------------
// Crypto helpers
// ---------------------------------------------------------------------------

fn encrypted_record_from_mp_base85(
    encrypted: EqlCiphertext,
    encryption_context: Vec<zerokms::Context>,
) -> Result<WithContext<'static>, Error> {
    let encrypted_record = encrypted.body.ciphertext.ok_or_else(|| {
        Error::InvariantViolation("Missing ciphertext in EQL payload".to_string())
    })?;

    Ok(WithContext {
        record: encrypted_record,
        context: Cow::Owned(encryption_context),
    })
}

// ---------------------------------------------------------------------------
// Exported C FFI functions
// ---------------------------------------------------------------------------

#[no_mangle]
pub extern "C" fn protect_new_client(options_json: *const c_char) -> CResult {
    let mut result = CResult::default();

    let options_str = match unsafe { c_str_to_string(options_json) } {
        Ok(s) => s,
        Err(e) => {
            result.error = string_to_c_str(e.to_string());
            return result;
        }
    };

    let rt = get_runtime();
    match rt.block_on(async {
        let opts: NewClientOptions = serde_json::from_str(&options_str)?;
        new_client_impl(opts).await
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

#[no_mangle]
pub extern "C" fn protect_encrypt(
    client_ptr: *const Client,
    options_json: *const c_char,
) -> CResult {
    let mut result = CResult::default();

    if client_ptr.is_null() {
        result.error = string_to_c_str("Client pointer is null".to_string());
        return result;
    }

    let client = unsafe { &*client_ptr };

    let options_str = match unsafe { c_str_to_string(options_json) } {
        Ok(s) => s,
        Err(e) => {
            result.error = string_to_c_str(e.to_string());
            return result;
        }
    };

    let rt = get_runtime();
    match rt.block_on(async {
        let opts: EncryptOptions = serde_json::from_str(&options_str)?;
        encrypt_impl(client, opts).await
    }) {
        Ok(encrypted) => match serde_json::to_string(&encrypted) {
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
pub extern "C" fn protect_encrypt_bulk(
    client_ptr: *const Client,
    options_json: *const c_char,
) -> CResult {
    let mut result = CResult::default();

    if client_ptr.is_null() {
        result.error = string_to_c_str("Client pointer is null".to_string());
        return result;
    }

    let client = unsafe { &*client_ptr };

    let options_str = match unsafe { c_str_to_string(options_json) } {
        Ok(s) => s,
        Err(e) => {
            result.error = string_to_c_str(e.to_string());
            return result;
        }
    };

    let rt = get_runtime();
    match rt.block_on(async {
        let opts: EncryptBulkOptions = serde_json::from_str(&options_str)?;
        encrypt_bulk_impl(client, opts).await
    }) {
        Ok(encrypted_list) => match serde_json::to_string(&encrypted_list) {
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
pub extern "C" fn protect_encrypt_query(
    client_ptr: *const Client,
    options_json: *const c_char,
) -> CResult {
    let mut result = CResult::default();

    if client_ptr.is_null() {
        result.error = string_to_c_str("Client pointer is null".to_string());
        return result;
    }

    let client = unsafe { &*client_ptr };

    let options_str = match unsafe { c_str_to_string(options_json) } {
        Ok(s) => s,
        Err(e) => {
            result.error = string_to_c_str(e.to_string());
            return result;
        }
    };

    let rt = get_runtime();
    match rt.block_on(async {
        let opts: EncryptQueryOptions = serde_json::from_str(&options_str)?;
        encrypt_query_impl(client, opts).await
    }) {
        Ok(encrypted) => match serde_json::to_string(&encrypted) {
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
pub extern "C" fn protect_encrypt_query_bulk(
    client_ptr: *const Client,
    options_json: *const c_char,
) -> CResult {
    let mut result = CResult::default();

    if client_ptr.is_null() {
        result.error = string_to_c_str("Client pointer is null".to_string());
        return result;
    }

    let client = unsafe { &*client_ptr };

    let options_str = match unsafe { c_str_to_string(options_json) } {
        Ok(s) => s,
        Err(e) => {
            result.error = string_to_c_str(e.to_string());
            return result;
        }
    };

    let rt = get_runtime();
    match rt.block_on(async {
        let opts: EncryptQueryBulkOptions = serde_json::from_str(&options_str)?;
        encrypt_query_bulk_impl(client, opts).await
    }) {
        Ok(encrypted_list) => match serde_json::to_string(&encrypted_list) {
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
pub extern "C" fn protect_decrypt(
    client_ptr: *const Client,
    options_json: *const c_char,
) -> CResult {
    let mut result = CResult::default();

    if client_ptr.is_null() {
        result.error = string_to_c_str("Client pointer is null".to_string());
        return result;
    }

    let client = unsafe { &*client_ptr };

    let options_str = match unsafe { c_str_to_string(options_json) } {
        Ok(s) => s,
        Err(e) => {
            result.error = string_to_c_str(e.to_string());
            return result;
        }
    };

    let rt = get_runtime();
    match rt.block_on(async {
        let opts: DecryptOptions = serde_json::from_str(&options_str)?;
        decrypt_impl(client, opts).await
    }) {
        Ok(plaintext) => match serde_json::to_string(&plaintext) {
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
pub extern "C" fn protect_decrypt_bulk(
    client_ptr: *const Client,
    options_json: *const c_char,
) -> CResult {
    let mut result = CResult::default();

    if client_ptr.is_null() {
        result.error = string_to_c_str("Client pointer is null".to_string());
        return result;
    }

    let client = unsafe { &*client_ptr };

    let options_str = match unsafe { c_str_to_string(options_json) } {
        Ok(s) => s,
        Err(e) => {
            result.error = string_to_c_str(e.to_string());
            return result;
        }
    };

    let rt = get_runtime();
    match rt.block_on(async {
        let opts: DecryptBulkOptions = serde_json::from_str(&options_str)?;
        decrypt_bulk_impl(client, opts).await
    }) {
        Ok(plaintexts) => match serde_json::to_string(&plaintexts) {
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
pub extern "C" fn protect_decrypt_bulk_fallible(
    client_ptr: *const Client,
    options_json: *const c_char,
) -> CResult {
    let mut result = CResult::default();

    if client_ptr.is_null() {
        result.error = string_to_c_str("Client pointer is null".to_string());
        return result;
    }

    let client = unsafe { &*client_ptr };

    let options_str = match unsafe { c_str_to_string(options_json) } {
        Ok(s) => s,
        Err(e) => {
            result.error = string_to_c_str(e.to_string());
            return result;
        }
    };

    let rt = get_runtime();
    match rt.block_on(async {
        let opts: DecryptBulkOptions = serde_json::from_str(&options_str)?;
        decrypt_bulk_fallible_impl(client, opts).await
    }) {
        Ok(results_vec) => match serde_json::to_string(&results_vec) {
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

/// Check if a JSON value is a valid EQL ciphertext.
#[no_mangle]
pub extern "C" fn protect_is_encrypted(value_json: *const c_char) -> bool {
    let value_str = match unsafe { c_str_to_string(value_json) } {
        Ok(s) => s,
        Err(_) => return false,
    };
    let result: Result<EqlCiphertext, _> = serde_json::from_str(&value_str);
    result.is_ok()
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
        use serde_json::json;
        use std::ffi::CString;

        fn check_is_encrypted(value: serde_json::Value) -> bool {
            let json_str = serde_json::to_string(&value).unwrap();
            let c_str = CString::new(json_str).unwrap();
            protect_is_encrypted(c_str.as_ptr())
        }

        #[test]
        fn valid_eql_ciphertext_is_encrypted() {
            let valid = json!({
                "i": {"t": "users", "c": "email"},
                "v": 2
            });
            assert!(check_is_encrypted(valid));
        }

        #[test]
        fn valid_eql_ciphertext_with_ste_vec_is_encrypted() {
            let valid = json!({
                "i": {"t": "users", "c": "profile"},
                "v": 2,
                "sv": [{"s": "deadbeef"}]
            });
            assert!(check_is_encrypted(valid));
        }

        #[test]
        fn invalid_ciphertext_is_not_encrypted() {
            let invalid = json!({"random": "data"});
            assert!(!check_is_encrypted(invalid));
        }

        #[test]
        fn old_format_with_k_field_is_still_valid() {
            let old_format = json!({
                "k": "ct",
                "i": {"t": "users", "c": "email"},
                "v": 2
            });
            assert!(check_is_encrypted(old_format));
        }

        #[test]
        fn old_ste_vec_format_with_k_field_is_still_valid() {
            let old_format = json!({
                "k": "sv",
                "i": {"t": "users", "c": "profile"},
                "v": 2
            });
            assert!(check_is_encrypted(old_format));
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

    mod query_op_parsing {
        use super::*;

        #[test]
        fn parse_query_op_default() {
            let result = parse_query_op("default");
            assert!(matches!(result, Ok(QueryOp::Default)));
        }

        #[test]
        fn parse_query_op_ste_vec_selector() {
            let result = parse_query_op("ste_vec_selector");
            assert!(matches!(result, Ok(QueryOp::SteVecSelector)));
        }

        #[test]
        fn parse_query_op_ste_vec_term() {
            let result = parse_query_op("ste_vec_term");
            assert!(matches!(result, Ok(QueryOp::SteVecTerm)));
        }

        #[test]
        fn parse_query_op_unknown_returns_error() {
            let result = parse_query_op("unknown");
            assert!(result.is_err());
            let err = result.unwrap_err();
            assert!(err.to_string().contains("Unknown query operation"));
        }
    }

    mod find_index_for_type_tests {
        use super::*;
        use cipherstash_client::schema::column::{Index, IndexType, Tokenizer};

        fn make_column_config_with_indexes(indexes: Vec<Index>) -> ColumnConfig {
            ColumnConfig {
                name: "test_column".to_string(),
                cast_type: cipherstash_client::schema::column::ColumnType::Utf8Str,
                indexes,
                in_place: false,
                mode: cipherstash_client::schema::column::ColumnMode::Encrypted,
            }
        }

        #[test]
        fn find_ste_vec_index() {
            let config = make_column_config_with_indexes(vec![Index::new(IndexType::SteVec {
                prefix: "test".to_string(),
                term_filters: vec![],
                array_index_mode: Default::default(),
            })]);
            let result = find_index_for_type(&config, "test_column", "ste_vec");
            assert!(result.is_ok());
            assert!(matches!(
                result.unwrap().index_type,
                IndexType::SteVec { .. }
            ));
        }

        #[test]
        fn find_ore_index() {
            let config = make_column_config_with_indexes(vec![Index::new(IndexType::Ore)]);
            let result = find_index_for_type(&config, "test_column", "ore");
            assert!(result.is_ok());
            assert!(matches!(result.unwrap().index_type, IndexType::Ore));
        }

        #[test]
        fn find_unique_index() {
            let config = make_column_config_with_indexes(vec![Index::new(IndexType::Unique {
                token_filters: vec![],
            })]);
            let result = find_index_for_type(&config, "test_column", "unique");
            assert!(result.is_ok());
            assert!(matches!(
                result.unwrap().index_type,
                IndexType::Unique { .. }
            ));
        }

        #[test]
        fn find_match_index() {
            let config = make_column_config_with_indexes(vec![Index::new(IndexType::Match {
                tokenizer: Tokenizer::Standard,
                token_filters: vec![],
                k: 3,
                m: 2048,
                include_original: false,
            })]);
            let result = find_index_for_type(&config, "test_column", "match");
            assert!(result.is_ok());
            assert!(matches!(
                result.unwrap().index_type,
                IndexType::Match { .. }
            ));
        }

        #[test]
        fn missing_index_returns_error() {
            let config = make_column_config_with_indexes(vec![Index::new(IndexType::Ore)]);
            let result = find_index_for_type(&config, "test_column", "ste_vec");
            assert!(result.is_err());
            let err = result.unwrap_err();
            assert!(err.to_string().contains("does not have"));
            assert!(err.to_string().contains("test_column"));
        }

        #[test]
        fn unknown_index_type_returns_error() {
            let config = make_column_config_with_indexes(vec![Index::new(IndexType::Ore)]);
            let result = find_index_for_type(&config, "test_column", "invalid_type");
            assert!(result.is_err());
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
            let result = find_index_for_type(&config, "email", "ste_vec");
            assert!(result.is_err());
            let err_msg = result.unwrap_err().to_string();
            assert!(
                err_msg.contains("email"),
                "Error should include column name: {}",
                err_msg
            );
            assert!(
                err_msg.contains("ste_vec"),
                "Error should include requested index type: {}",
                err_msg
            );
            assert!(
                err_msg.contains("ore"),
                "Error should show available ore index: {}",
                err_msg
            );
            assert!(
                err_msg.contains("match"),
                "Error should show available match index: {}",
                err_msg
            );
        }
    }

    mod query_inference_tests {
        use super::*;
        use cipherstash_client::encryption::Plaintext;
        use cipherstash_client::schema::column::Tokenizer;
        use cipherstash_client::schema::column::{ColumnType, IndexType};

        #[test]
        fn test_ste_vec_default_with_string_infers_selector() {
            let go_plaintext = GoPlaintext::String("$.user.email".to_string());
            let index_type = IndexType::SteVec {
                prefix: "test/col".to_string(),
                term_filters: vec![],
                array_index_mode: Default::default(),
            };

            let result = to_query_plaintext(
                &go_plaintext,
                QueryOp::Default,
                &index_type,
                ColumnType::JsonB,
            );

            assert!(matches!(
                result,
                Ok((
                    Plaintext::Utf8Str(Some(_)),
                    InferredQueryMode::QueryMode(QueryOp::SteVecSelector)
                ))
            ));
        }

        #[test]
        fn test_ste_vec_default_with_object_infers_store_mode() {
            let go_plaintext = GoPlaintext::JsonB(serde_json::json!({"role": "admin"}));
            let index_type = IndexType::SteVec {
                prefix: "test/col".to_string(),
                term_filters: vec![],
                array_index_mode: Default::default(),
            };

            let result = to_query_plaintext(
                &go_plaintext,
                QueryOp::Default,
                &index_type,
                ColumnType::JsonB,
            );

            assert!(matches!(
                result,
                Ok((Plaintext::JsonB(Some(_)), InferredQueryMode::StoreMode))
            ));
        }

        #[test]
        fn test_ste_vec_default_with_array_infers_store_mode() {
            let go_plaintext = GoPlaintext::JsonB(serde_json::json!(["admin", "user"]));
            let index_type = IndexType::SteVec {
                prefix: "test/col".to_string(),
                term_filters: vec![],
                array_index_mode: Default::default(),
            };

            let result = to_query_plaintext(
                &go_plaintext,
                QueryOp::Default,
                &index_type,
                ColumnType::JsonB,
            );

            assert!(matches!(
                result,
                Ok((Plaintext::JsonB(Some(_)), InferredQueryMode::StoreMode))
            ));
        }

        #[test]
        fn test_ste_vec_default_with_number_returns_error() {
            let go_plaintext = GoPlaintext::Number(42.0);
            let index_type = IndexType::SteVec {
                prefix: "test/col".to_string(),
                term_filters: vec![],
                array_index_mode: Default::default(),
            };

            let result = to_query_plaintext(
                &go_plaintext,
                QueryOp::Default,
                &index_type,
                ColumnType::JsonB,
            );

            assert!(result.is_err());
            let err_msg = result.unwrap_err().to_string();
            assert!(
                err_msg.contains("Invalid query input"),
                "Error message should mention invalid input: {}",
                err_msg
            );
        }

        #[test]
        fn test_ste_vec_default_with_boolean_returns_error() {
            let go_plaintext = GoPlaintext::Boolean(true);
            let index_type = IndexType::SteVec {
                prefix: "test/col".to_string(),
                term_filters: vec![],
                array_index_mode: Default::default(),
            };

            let result = to_query_plaintext(
                &go_plaintext,
                QueryOp::Default,
                &index_type,
                ColumnType::JsonB,
            );

            assert!(result.is_err());
        }

        #[test]
        fn test_explicit_ste_vec_selector_uses_query_mode() {
            let go_plaintext = GoPlaintext::String("$.name".to_string());
            let index_type = IndexType::SteVec {
                prefix: "test/col".to_string(),
                term_filters: vec![],
                array_index_mode: Default::default(),
            };

            let result = to_query_plaintext(
                &go_plaintext,
                QueryOp::SteVecSelector,
                &index_type,
                ColumnType::JsonB,
            );

            assert!(matches!(
                result,
                Ok((
                    Plaintext::Utf8Str(Some(_)),
                    InferredQueryMode::QueryMode(QueryOp::SteVecSelector)
                ))
            ));
        }

        #[test]
        fn test_explicit_ste_vec_term_uses_store_mode() {
            let go_plaintext = GoPlaintext::JsonB(serde_json::json!({"key": "value"}));
            let index_type = IndexType::SteVec {
                prefix: "test/col".to_string(),
                term_filters: vec![],
                array_index_mode: Default::default(),
            };

            let result = to_query_plaintext(
                &go_plaintext,
                QueryOp::SteVecTerm,
                &index_type,
                ColumnType::JsonB,
            );

            assert!(matches!(
                result,
                Ok((Plaintext::JsonB(Some(_)), InferredQueryMode::StoreMode))
            ));
        }

        #[test]
        fn test_non_ste_vec_default_uses_column_type() {
            let go_plaintext = GoPlaintext::String("search term".to_string());
            let index_type = IndexType::Match {
                tokenizer: Tokenizer::Standard,
                token_filters: vec![],
                k: 6,
                m: 2048,
                include_original: true,
            };

            let result = to_query_plaintext(
                &go_plaintext,
                QueryOp::Default,
                &index_type,
                ColumnType::Utf8Str,
            );

            assert!(matches!(
                result,
                Ok((
                    Plaintext::Utf8Str(Some(_)),
                    InferredQueryMode::QueryMode(QueryOp::Default)
                ))
            ));
        }

        #[test]
        fn test_ste_vec_term_with_string_error_is_helpful() {
            let go_plaintext = GoPlaintext::String("admin".to_string());
            let index_type = IndexType::SteVec {
                prefix: "test/col".to_string(),
                term_filters: vec![],
                array_index_mode: Default::default(),
            };

            let result = to_query_plaintext(
                &go_plaintext,
                QueryOp::SteVecTerm,
                &index_type,
                ColumnType::JsonB,
            );

            assert!(result.is_err());
            let err_msg = result.unwrap_err().to_string();
            assert!(
                err_msg.contains("ste_vec_term"),
                "Error should mention ste_vec_term: {}",
                err_msg
            );
            assert!(
                err_msg.contains("String"),
                "Error should mention received String: {}",
                err_msg
            );
            assert!(
                err_msg.contains("ste_vec_selector") || err_msg.contains("path"),
                "Error should suggest ste_vec_selector for paths: {}",
                err_msg
            );
        }

        #[test]
        fn test_invalid_json_path_error() {
            let go_plaintext = GoPlaintext::String("user.email".to_string());
            let index_type = IndexType::SteVec {
                prefix: "test/col".to_string(),
                term_filters: vec![],
                array_index_mode: Default::default(),
            };

            let result = to_query_plaintext(
                &go_plaintext,
                QueryOp::SteVecSelector,
                &index_type,
                ColumnType::JsonB,
            );

            assert!(result.is_err());
            let err_msg = result.unwrap_err().to_string();
            assert!(
                err_msg.contains("user.email"),
                "Error should show the invalid path: {}",
                err_msg
            );
            assert!(
                err_msg.contains("$.user.email") || err_msg.contains("$"),
                "Error should suggest correct format with $: {}",
                err_msg
            );
        }
    }
}
