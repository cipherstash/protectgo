use cipherstash_client::{
    config::{
        console_config::ConsoleConfig, cts_config::CtsConfig, errors::ConfigError,
        zero_kms_config::ZeroKMSConfig, CipherStashConfigFile, CipherStashSecretConfigFile,
        EnvSource, FileSource,
    },
    credentials::{ServiceCredentials, ServiceToken},
    encryption::{
        self, EncryptionError, IndexTerm, Plaintext, PlaintextTarget, ReferencedPendingPipeline,
        ScopedCipher, SteVec, TypeParseError,
    },
    schema::ColumnConfig,
    zerokms::{self, EncryptedRecord, RecordDecryptError, WithContext, ZeroKMSWithClientKey},
    UnverifiedContext,
};
use cts_common::Crn;
use once_cell::sync::OnceCell;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::sync::Arc;
use tokio::runtime::Runtime;

mod encrypt_config;
use encrypt_config::{EncryptConfig, Identifier};

// Error handling
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

// Client structure that we'll pass around as an opaque pointer
#[derive(Clone)]
pub struct Client {
    cipher: Arc<ScopedZeroKMSNoRefresh>,
    zerokms: Arc<ZeroKMSWithClientKey<ServiceCredentials>>,
    encrypt_config: Arc<HashMap<Identifier, ColumnConfig>>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "k")]
pub enum Encrypted {
    #[serde(rename = "ct")]
    Ciphertext {
        #[serde(rename = "c")]
        ciphertext: String,
        #[serde(rename = "ob")]
        ore_index: Option<Vec<String>>,
        #[serde(rename = "bf")]
        match_index: Option<Vec<u16>>,
        #[serde(rename = "hm")]
        unique_index: Option<String>,
        #[serde(rename = "i")]
        identifier: Identifier,
        #[serde(rename = "v")]
        version: u16,
    },
    #[serde(rename = "sv")]
    SteVec {
        #[serde(rename = "sv")]
        ste_vec_index: SteVec<16>,
        #[serde(rename = "i")]
        identifier: Identifier,
        #[serde(rename = "v")]
        version: u16,
    },
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[error(transparent)]
    ZeroKMS(#[from] zerokms::Error),
    #[error(transparent)]
    TypeParse(#[from] TypeParseError),
    #[error(transparent)]
    Encryption(#[from] EncryptionError),
    #[error("protect-ffi invariant violation: {0}. This is a bug in protect-ffi. Please file an issue at https://github.com/cipherstash/protectgo/issues.")]
    InvariantViolation(String),
    #[error("{0}")]
    Base85(String),
    #[error("unimplemented: {0} not supported yet by protect-ffi")]
    Unimplemented(String),
    #[error(transparent)]
    Parse(#[from] serde_json::Error),
    #[error("column {}.{} not found in Encrypt config", _0.table, _0.column)]
    UnknownColumn(Identifier),
    #[error(transparent)]
    RecordDecryptError(#[from] RecordDecryptError),
    #[error("null pointer error")]
    NullPointer,
    #[error("utf8 conversion error")]
    Utf8Error,
}

type ScopedZeroKMSNoRefresh = ScopedCipher<ServiceCredentials>;

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct ClientOpts {
    workspace_crn: Option<Crn>,
    access_key: Option<String>,
    client_id: Option<String>,
    client_key: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct NewClientOptions {
    encrypt_config: EncryptConfig,
    client_opts: Option<ClientOpts>,
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
enum DecryptResult {
    Success { data: String },
    Error { error: String },
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct EncryptOptions {
    plaintext: String,
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
    plaintext: String,
    column: String,
    table: String,
    lock_context: Option<LockContext>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DecryptOptions {
    ciphertext: String,
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
    ciphertext: String,
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

// Runtime management
static RUNTIME: OnceCell<Runtime> = OnceCell::new();

fn get_runtime() -> &'static Runtime {
    RUNTIME.get_or_init(|| Runtime::new().expect("Failed to create tokio runtime"))
}

// Helper functions for string conversion
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

// Exported C functions

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

async fn new_client_impl(opts: NewClientOptions) -> Result<Client, Error> {
    let client_opts = opts.client_opts.unwrap_or_default();
    let console_config = ConsoleConfig::builder().with_env().build()?;
    let cts_config = CtsConfig::builder().with_env().build()?;

    let zerokms_config_builder = {
        let mut zerokms_config_builder = ZeroKMSConfig::builder()
            .add_source(EnvSource::default())
            .add_source(FileSource::<CipherStashSecretConfigFile>::default().optional())
            .add_source(FileSource::<CipherStashConfigFile>::default().optional())
            .console_config(&console_config)
            .cts_config(&cts_config);

        if let Some(workspace_crn) = client_opts.workspace_crn {
            zerokms_config_builder = zerokms_config_builder.workspace_crn(workspace_crn);
        }

        if let Some(access_key) = client_opts.access_key {
            zerokms_config_builder = zerokms_config_builder.access_key(access_key);
        }

        if let Some(client_id) = client_opts.client_id {
            zerokms_config_builder = zerokms_config_builder.try_with_client_id(&client_id)?;
        }

        if let Some(client_key) = client_opts.client_key {
            zerokms_config_builder = zerokms_config_builder.try_with_client_key(&client_key)?;
        }

        zerokms_config_builder
    };

    let zerokms_config = zerokms_config_builder.build_with_client_key()?;
    let zerokms = Arc::new(zerokms_config.create_client());
    let cipher = ScopedZeroKMSNoRefresh::init(zerokms.clone(), None).await?;

    let client = Client {
        cipher: Arc::new(cipher),
        zerokms,
        encrypt_config: Arc::new(opts.encrypt_config.into_config_map()),
    };

    Ok(client)
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
        Ok(encrypted) => {
            match serde_json::to_string(&encrypted) {
                Ok(json) => {
                    result.success = true;
                    result.data = string_to_c_str(json);
                }
                Err(e) => {
                    result.error = string_to_c_str(e.to_string());
                }
            }
        }
        Err(e) => {
            result.error = string_to_c_str(e.to_string());
        }
    }

    result
}

async fn encrypt_impl(client: &Client, opts: EncryptOptions) -> Result<Encrypted, Error> {
    let ident = Identifier::new(opts.table, opts.column);

    let column_config = client
        .encrypt_config
        .get(&ident)
        .ok_or_else(|| Error::UnknownColumn(ident.clone()))?;

    let mut plaintext_target = PlaintextTarget::new(opts.plaintext, column_config.clone());
    plaintext_target.context = opts.lock_context.map(Into::into).unwrap_or_default();

    let mut pipeline = ReferencedPendingPipeline::new(client.cipher.clone());
    pipeline.add_with_ref::<PlaintextTarget>(plaintext_target, 0)?;

    let mut source_encrypted = pipeline
        .encrypt(opts.service_token, opts.unverified_context)
        .await?;

    let encrypted = source_encrypted.remove(0).ok_or_else(|| {
        Error::InvariantViolation(
            "`encrypt` expected a single result in the pipeline, but there were none".to_string(),
        )
    })?;

    to_eql_encrypted(encrypted, &ident)
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
        Ok(plaintext) => {
            result.success = true;
            result.data = string_to_c_str(plaintext);
        }
        Err(e) => {
            result.error = string_to_c_str(e.to_string());
        }
    }

    result
}

async fn decrypt_impl(client: &Client, opts: DecryptOptions) -> Result<String, Error> {
    let lock_context = opts.lock_context.map(Into::into).unwrap_or_default();
    let encrypted_record = encrypted_record_from_mp_base85(&opts.ciphertext, lock_context)?;

    let decrypted = client
        .zerokms
        .decrypt_single(
            encrypted_record,
            opts.service_token,
            opts.unverified_context,
        )
        .await?;

    plaintext_str_from_bytes(decrypted)
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
        Ok(encrypted_list) => {
            match serde_json::to_string(&encrypted_list) {
                Ok(json) => {
                    result.success = true;
                    result.data = string_to_c_str(json);
                }
                Err(e) => {
                    result.error = string_to_c_str(e.to_string());
                }
            }
        }
        Err(e) => {
            result.error = string_to_c_str(e.to_string());
        }
    }

    result
}

async fn encrypt_bulk_impl(client: &Client, opts: EncryptBulkOptions) -> Result<Vec<Encrypted>, Error> {
    let plaintext_targets = opts
        .plaintexts
        .into_iter()
        .map(|payload| {
            let ident = Identifier::new(payload.table, payload.column);

            let column_config = client
                .encrypt_config
                .get(&ident)
                .ok_or_else(|| Error::UnknownColumn(ident.clone()))?;

            let mut plaintext_target =
                PlaintextTarget::new(payload.plaintext, column_config.clone());
            plaintext_target.context = payload.lock_context.map(Into::into).unwrap_or_default();

            Ok((plaintext_target, ident))
        })
        .collect::<Result<Vec<(PlaintextTarget, Identifier)>, Error>>()?;

    let len = plaintext_targets.len();
    let mut pipeline = ReferencedPendingPipeline::new(client.cipher.clone());
    let (plaintext_targets, identifiers): (Vec<PlaintextTarget>, Vec<Identifier>) =
        plaintext_targets.into_iter().unzip();

    for (i, plaintext_target) in plaintext_targets.into_iter().enumerate() {
        pipeline.add_with_ref::<PlaintextTarget>(plaintext_target, i)?;
    }

    let mut source_encrypted = pipeline
        .encrypt(opts.service_token, opts.unverified_context)
        .await?;

    let mut results: Vec<Encrypted> = Vec::with_capacity(len);

    for i in 0..len {
        let encrypted = source_encrypted.remove(i).ok_or_else(|| {
            Error::InvariantViolation(format!(
                "`encrypt_bulk` expected a result in the pipeline at index {i}, but there was none"
            ))
        })?;

        let ident = identifiers.get(i).ok_or_else(|| {
            Error::InvariantViolation(format!(
                "`encrypt_bulk` expected an identifier to exist for index {i}, but there was none"
            ))
        })?;

        let eql_payload = to_eql_encrypted(encrypted, ident)?;
        results.push(eql_payload);
    }

    Ok(results)
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
        Ok(plaintexts) => {
            match serde_json::to_string(&plaintexts) {
                Ok(json) => {
                    result.success = true;
                    result.data = string_to_c_str(json);
                }
                Err(e) => {
                    result.error = string_to_c_str(e.to_string());
                }
            }
        }
        Err(e) => {
            result.error = string_to_c_str(e.to_string());
        }
    }

    result
}

async fn decrypt_bulk_impl(client: &Client, opts: DecryptBulkOptions) -> Result<Vec<String>, Error> {
    let ciphertexts: Vec<(String, Vec<zerokms::Context>)> = opts
        .ciphertexts
        .into_iter()
        .map(|payload| {
            let lock_context = payload.lock_context.map(Into::into).unwrap_or_default();
            (payload.ciphertext, lock_context)
        })
        .collect();

    let encrypted_records = ciphertexts
        .into_iter()
        .map(|(ciphertext, encryption_context)| {
            encrypted_record_from_mp_base85(&ciphertext, encryption_context)
        })
        .collect::<Result<Vec<WithContext>, Error>>()?;

    let decrypted = client
        .zerokms
        .decrypt(
            encrypted_records,
            opts.service_token,
            opts.unverified_context,
        )
        .await?;

    let plaintexts = decrypted
        .into_iter()
        .map(plaintext_str_from_bytes)
        .collect::<Result<Vec<String>, Error>>()?;

    Ok(plaintexts)
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
        Ok(results) => {
            match serde_json::to_string(&results) {
                Ok(json) => {
                    result.success = true;
                    result.data = string_to_c_str(json);
                }
                Err(e) => {
                    result.error = string_to_c_str(e.to_string());
                }
            }
        }
        Err(e) => {
            result.error = string_to_c_str(e.to_string());
        }
    }

    result
}

async fn decrypt_bulk_fallible_impl(client: &Client, opts: DecryptBulkOptions) -> Result<Vec<DecryptResult>, Error> {
    let ciphertexts: Vec<(String, Vec<zerokms::Context>)> = opts
        .ciphertexts
        .into_iter()
        .map(|payload| {
            let lock_context = payload.lock_context.map(Into::into).unwrap_or_default();
            (payload.ciphertext, lock_context)
        })
        .collect();

    let encrypted_records: Result<Vec<WithContext>, Error> = ciphertexts
        .into_iter()
        .map(|(ciphertext, encryption_context)| {
            encrypted_record_from_mp_base85(&ciphertext, encryption_context)
        })
        .collect();

    let encrypted_records = encrypted_records?;

    let decrypted = client
        .zerokms
        .decrypt_fallible(
            encrypted_records,
            opts.service_token,
            opts.unverified_context,
        )
        .await?;

    let plaintexts: Vec<Result<String, Error>> = decrypted
        .into_iter()
        .map(|item| item.map_err(Error::from).and_then(plaintext_str_from_bytes))
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

// Helper functions (same as original)
fn encrypted_record_from_mp_base85(
    base85str: &str,
    encryption_context: Vec<zerokms::Context>,
) -> Result<WithContext, Error> {
    let encrypted_record = EncryptedRecord::from_mp_base85(base85str)
        .map_err(|err| Error::Base85(err.to_string()))?;

    Ok(WithContext {
        record: encrypted_record,
        context: encryption_context,
    })
}

fn plaintext_str_from_bytes(bytes: Vec<u8>) -> Result<String, Error> {
    let plaintext = Plaintext::from_slice(bytes.as_slice())?;

    match plaintext {
        Plaintext::Utf8Str(Some(ref inner)) => Ok(inner.clone()),
        _ => Err(Error::Unimplemented(
            "data types other than `Utf8Str`".to_string(),
        )),
    }
}

fn to_eql_encrypted(
    encrypted: encryption::Encrypted,
    identifier: &Identifier,
) -> Result<Encrypted, Error> {
    match encrypted {
        encryption::Encrypted::Record(ciphertext, terms) => {
            struct Indexes {
                match_index: Option<Vec<u16>>,
                ore_index: Option<Vec<String>>,
                unique_index: Option<String>,
            }

            let mut indexes = Indexes {
                match_index: None,
                ore_index: None,
                unique_index: None,
            };

            for index_term in terms {
                match index_term {
                    IndexTerm::Binary(bytes) => {
                        indexes.unique_index = Some(format_index_term_binary(&bytes))
                    }
                    IndexTerm::BitMap(inner) => indexes.match_index = Some(inner),
                    IndexTerm::OreArray(vec_of_bytes) => {
                        indexes.ore_index = Some(format_index_term_ore_array(&vec_of_bytes));
                    }
                    IndexTerm::OreFull(bytes) => {
                        indexes.ore_index = Some(format_index_term_ore(&bytes));
                    }
                    IndexTerm::OreLeft(bytes) => {
                        indexes.ore_index = Some(format_index_term_ore(&bytes));
                    }
                    IndexTerm::Null => {}
                    term => return Err(Error::Unimplemented(format!("index term `{term:?}`"))),
                };
            }

            let ciphertext = ciphertext
                .to_mp_base85()
                .map_err(|err| Error::Base85(err.to_string()))?;

            Ok(Encrypted::Ciphertext {
                ciphertext,
                identifier: identifier.to_owned(),
                match_index: indexes.match_index,
                ore_index: indexes.ore_index,
                unique_index: indexes.unique_index,
                version: 2,
            })
        }
        encryption::Encrypted::SteVec(ste_vec_index) => Ok(Encrypted::SteVec {
            identifier: identifier.to_owned(),
            ste_vec_index,
            version: 2,
        }),
    }
}

fn format_index_term_binary(bytes: &Vec<u8>) -> String {
    hex::encode(bytes)
}

fn format_index_term_ore_bytea(bytes: &Vec<u8>) -> String {
    hex::encode(bytes)
}

fn format_index_term_ore_array(vec_of_bytes: &[Vec<u8>]) -> Vec<String> {
    vec_of_bytes
        .iter()
        .map(format_index_term_ore_bytea)
        .collect()
}

fn format_index_term_ore(bytes: &Vec<u8>) -> Vec<String> {
    vec![format_index_term_ore_bytea(bytes)]
} 