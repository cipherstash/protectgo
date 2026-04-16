package protect

/*
#cgo LDFLAGS: -L${SRCDIR}
#cgo darwin LDFLAGS: -framework CoreFoundation -framework Security
#cgo darwin,arm64 LDFLAGS: -lprotect_ffi_darwin_arm64
#cgo darwin,amd64 LDFLAGS: -lprotect_ffi_darwin_x64
#cgo linux,arm64,!musl LDFLAGS: -lprotect_ffi_linux_arm64 -lm -ldl -lpthread
#cgo linux,amd64,!musl LDFLAGS: -lprotect_ffi_linux_x64 -lm -ldl -lpthread
#cgo linux,arm64,musl LDFLAGS: -lprotect_ffi_linux_arm64_musl
#cgo linux,amd64,musl LDFLAGS: -lprotect_ffi_linux_x64_musl
#include "protect_ffi.h"
#include <stdlib.h>
*/
import "C"
import (
	"encoding/json"
	"strings"
	"unsafe"
)

// Client represents a protect FFI client.
type Client struct {
	ptr unsafe.Pointer
}

// CastAs represents the different data types for column casting
type CastAs string

const (
	CastAsBigInt  CastAs = "bigint"
	CastAsBoolean CastAs = "boolean"
	CastAsDate    CastAs = "date"
	CastAsNumber  CastAs = "number"
	CastAsString  CastAs = "string"
	CastAsText    CastAs = "text"
	CastAsJson    CastAs = "json"
)

// ErrorCode represents a structured error code returned by the FFI layer
type ErrorCode string

const (
	ErrInvariantViolation       ErrorCode = "INVARIANT_VIOLATION"
	ErrUnknownQueryOp           ErrorCode = "UNKNOWN_QUERY_OP"
	ErrUnknownColumn            ErrorCode = "UNKNOWN_COLUMN"
	ErrMissingIndex             ErrorCode = "MISSING_INDEX"
	ErrInvalidQueryInput        ErrorCode = "INVALID_QUERY_INPUT"
	ErrInvalidJsonPath          ErrorCode = "INVALID_JSON_PATH"
	ErrSteVecRequiresJsonCastAs ErrorCode = "STE_VEC_REQUIRES_JSON_CAST_AS"
	ErrUnknown                  ErrorCode = "UNKNOWN"
)

// EncryptionError represents a structured error from the encryption FFI layer.
type EncryptionError struct {
	Code    ErrorCode
	Message string
}

// Error implements the error interface.
func (e *EncryptionError) Error() string {
	return e.Message
}

// inferErrorCode infers an error code from the error message returned by the FFI layer.
func inferErrorCode(msg string) ErrorCode {
	switch {
	case strings.Contains(msg, "invariant violation"):
		return ErrInvariantViolation
	case strings.Contains(msg, "Unknown query operation"):
		return ErrUnknownQueryOp
	case strings.Contains(msg, "not found in Encrypt config"):
		return ErrUnknownColumn
	case strings.Contains(msg, "does not have a"):
		return ErrMissingIndex
	case strings.Contains(msg, "Invalid query input"):
		return ErrInvalidQueryInput
	case strings.Contains(msg, "Invalid JSON path"):
		return ErrInvalidJsonPath
	case strings.Contains(msg, "ste_vec index requires cast_as"):
		return ErrSteVecRequiresJsonCastAs
	default:
		return ErrUnknown
	}
}

// newEncryptionError creates a new EncryptionError with an inferred error code.
func newEncryptionError(msg string) *EncryptionError {
	return &EncryptionError{
		Code:    inferErrorCode(msg),
		Message: msg,
	}
}

// Identifier represents a table and column identifier
type Identifier struct {
	Table  string `json:"t"`
	Column string `json:"c"`
}

// NewIdentifier creates a new identifier
func NewIdentifier(table, column string) Identifier {
	return Identifier{
		Table:  table,
		Column: column,
	}
}

// OreIndexOpts represents options for ORE index
type OreIndexOpts struct{}

// UniqueIndexOpts represents options for unique index
type UniqueIndexOpts struct {
	TokenFilters []TokenFilter `json:"token_filters,omitempty"`
}

// TokenFilter represents a token filter configuration
type TokenFilter struct {
	Kind string `json:"kind"`
}

// MatchIndexOpts represents options for match index
type MatchIndexOpts struct {
	Tokenizer       *Tokenizer    `json:"tokenizer,omitempty"`
	TokenFilters    []TokenFilter `json:"token_filters,omitempty"`
	K               *int          `json:"k,omitempty"`
	M               *int          `json:"m,omitempty"`
	IncludeOriginal *bool         `json:"include_original,omitempty"`
}

// Tokenizer represents tokenizer configuration
type Tokenizer struct {
	Kind        string `json:"kind"`
	TokenLength *int   `json:"token_length,omitempty"`
}

// SteVecIndexOpts represents options for SteVec index
type SteVecIndexOpts struct {
	Prefix         string        `json:"prefix"`
	TermFilters    []TokenFilter `json:"term_filters,omitempty"`
	ArrayIndexMode *string       `json:"array_index_mode,omitempty"`
}

// Indexes represents the indexes configuration for a column
type Indexes struct {
	OreIndex    *OreIndexOpts    `json:"ore,omitempty"`
	UniqueIndex *UniqueIndexOpts `json:"unique,omitempty"`
	MatchIndex  *MatchIndexOpts  `json:"match,omitempty"`
	SteVecIndex *SteVecIndexOpts `json:"ste_vec,omitempty"`
}

// Column represents a column configuration
type Column struct {
	CastAs  *CastAs  `json:"cast_as,omitempty"`
	Indexes *Indexes `json:"indexes,omitempty"`
}

// Table represents a table configuration with its columns
type Table map[string]Column

// Tables represents all tables configuration
type Tables map[string]Table

// EncryptConfig represents the encryption configuration
type EncryptConfig struct {
	Version uint32 `json:"v"`
	Tables  Tables `json:"tables"`
}

// KeysetConfig represents keyset configuration for the client
type KeysetConfig struct {
	Name *string `json:"name,omitempty"`
	ID   *string `json:"id,omitempty"`
}

// ClientOpts represents client configuration options
type ClientOpts struct {
	WorkspaceCrn *string       `json:"workspaceCrn,omitempty"`
	AccessKey    *string       `json:"accessKey,omitempty"`
	ClientID     *string       `json:"clientId,omitempty"`
	ClientKey    *string       `json:"clientKey,omitempty"`
	Keyset       *KeysetConfig `json:"keyset,omitempty"`
}

// NewClientOptions represents options for creating a new client
type NewClientOptions struct {
	EncryptConfig EncryptConfig `json:"encryptConfig"`
	ClientOpts    *ClientOpts   `json:"clientOpts,omitempty"`
}

// LockContext represents a lock context for encryption/decryption
type LockContext struct {
	IdentityClaim []string `json:"identityClaim"`
}

// EncryptOptions represents options for encryption
type EncryptOptions struct {
	Plaintext         interface{}  `json:"plaintext"`
	Column            string       `json:"column"`
	Table             string       `json:"table"`
	LockContext       *LockContext `json:"lockContext,omitempty"`
	ServiceToken      *string      `json:"serviceToken,omitempty"`
	UnverifiedContext interface{}  `json:"unverifiedContext,omitempty"`
}

// PlaintextPayload represents a single plaintext item for bulk encryption
type PlaintextPayload struct {
	Plaintext   interface{}  `json:"plaintext"`
	Column      string       `json:"column"`
	Table       string       `json:"table"`
	LockContext *LockContext `json:"lockContext,omitempty"`
}

// EncryptBulkOptions represents options for bulk encryption
type EncryptBulkOptions struct {
	Plaintexts        []PlaintextPayload `json:"plaintexts"`
	ServiceToken      *string            `json:"serviceToken,omitempty"`
	UnverifiedContext interface{}        `json:"unverifiedContext,omitempty"`
}

// DecryptOptions represents options for decryption
type DecryptOptions struct {
	Ciphertext        *Encrypted   `json:"ciphertext"`
	LockContext       *LockContext `json:"lockContext,omitempty"`
	ServiceToken      *string      `json:"serviceToken,omitempty"`
	UnverifiedContext interface{}  `json:"unverifiedContext,omitempty"`
}

// BulkDecryptPayload represents a single ciphertext item for bulk decryption
type BulkDecryptPayload struct {
	Ciphertext  *Encrypted   `json:"ciphertext"`
	LockContext *LockContext `json:"lockContext,omitempty"`
}

// DecryptBulkOptions represents options for bulk decryption
type DecryptBulkOptions struct {
	Ciphertexts       []BulkDecryptPayload `json:"ciphertexts"`
	ServiceToken      *string              `json:"serviceToken,omitempty"`
	UnverifiedContext interface{}          `json:"unverifiedContext,omitempty"`
}

// Encrypted represents an encrypted value with its metadata
type Encrypted struct {
	Identifier  Identifier  `json:"i"`
	Version     uint16      `json:"v"`
	Ciphertext  *string     `json:"c,omitempty"`
	OreIndex    *[]string   `json:"ob,omitempty"`
	MatchIndex  *[]uint16   `json:"bf,omitempty"`
	UniqueIndex *string     `json:"hm,omitempty"`
	SteVecIndex interface{} `json:"sv,omitempty"`
}

// DecryptResult represents the result of a fallible decryption operation
type DecryptResult struct {
	Data  interface{} `json:"data,omitempty"`
	Error *string     `json:"error,omitempty"`
}

// QueryOp represents the type of query operation for encrypted search
type QueryOp string

const (
	QueryOpDefault        QueryOp = "default"
	QueryOpSteVecSelector QueryOp = "ste_vec_selector"
	QueryOpSteVecTerm     QueryOp = "ste_vec_term"
)

// IndexType represents the type of index to use for encrypted search
type IndexType string

const (
	IndexTypeOre    IndexType = "ore"
	IndexTypeUnique IndexType = "unique"
	IndexTypeMatch  IndexType = "match"
	IndexTypeSteVec IndexType = "ste_vec"
)

// EncryptQueryOptions represents options for encrypting a query value
type EncryptQueryOptions struct {
	Plaintext         interface{}  `json:"plaintext"`
	Column            string       `json:"column"`
	Table             string       `json:"table"`
	IndexType         IndexType    `json:"indexType"`
	QueryOp           QueryOp      `json:"queryOp,omitempty"`
	LockContext       *LockContext `json:"lockContext,omitempty"`
	ServiceToken      *string      `json:"serviceToken,omitempty"`
	UnverifiedContext interface{}  `json:"unverifiedContext,omitempty"`
}

// QueryPayload represents a single query item for bulk query encryption
type QueryPayload struct {
	Plaintext   interface{}  `json:"plaintext"`
	Column      string       `json:"column"`
	Table       string       `json:"table"`
	IndexType   IndexType    `json:"indexType"`
	QueryOp     QueryOp      `json:"queryOp,omitempty"`
	LockContext *LockContext `json:"lockContext,omitempty"`
}

// EncryptQueryBulkOptions represents options for bulk query encryption
type EncryptQueryBulkOptions struct {
	Queries           []QueryPayload `json:"queries"`
	ServiceToken      *string        `json:"serviceToken,omitempty"`
	UnverifiedContext interface{}    `json:"unverifiedContext,omitempty"`
}

// NewClient creates a new protect FFI client
func NewClient(options NewClientOptions) (*Client, error) {
	optionsJSON, err := json.Marshal(options)
	if err != nil {
		return nil, err
	}

	cOptionsJSON := C.CString(string(optionsJSON))
	defer C.free(unsafe.Pointer(cOptionsJSON))

	result := C.protect_new_client(cOptionsJSON)

	if !result.success {
		errorStr := C.GoString(result.error)
		C.protect_free_string(result.error)
		return nil, newEncryptionError(errorStr)
	}

	return &Client{ptr: unsafe.Pointer(result.data)}, nil
}

// Free releases the resources held by the client
func (c *Client) Free() {
	if c.ptr != nil {
		C.protect_free_client((*C.struct_Client)(c.ptr))
		c.ptr = nil
	}
}

// Encrypt encrypts a single plaintext value
func (c *Client) Encrypt(options EncryptOptions) (*Encrypted, error) {
	if c.ptr == nil {
		return nil, newEncryptionError("client has been freed")
	}

	optionsJSON, err := json.Marshal(options)
	if err != nil {
		return nil, err
	}

	cOptionsJSON := C.CString(string(optionsJSON))
	defer C.free(unsafe.Pointer(cOptionsJSON))

	result := C.protect_encrypt((*C.struct_Client)(c.ptr), cOptionsJSON)

	if !result.success {
		errorStr := C.GoString(result.error)
		C.protect_free_string(result.error)
		return nil, newEncryptionError(errorStr)
	}

	encryptedJSON := C.GoString(result.data)
	C.protect_free_string(result.data)

	var encrypted Encrypted
	if err := json.Unmarshal([]byte(encryptedJSON), &encrypted); err != nil {
		return nil, err
	}

	return &encrypted, nil
}

// EncryptBulk encrypts multiple plaintext values
func (c *Client) EncryptBulk(options EncryptBulkOptions) ([]Encrypted, error) {
	if c.ptr == nil {
		return nil, newEncryptionError("client has been freed")
	}

	optionsJSON, err := json.Marshal(options)
	if err != nil {
		return nil, err
	}

	cOptionsJSON := C.CString(string(optionsJSON))
	defer C.free(unsafe.Pointer(cOptionsJSON))

	result := C.protect_encrypt_bulk((*C.struct_Client)(c.ptr), cOptionsJSON)

	if !result.success {
		errorStr := C.GoString(result.error)
		C.protect_free_string(result.error)
		return nil, newEncryptionError(errorStr)
	}

	encryptedJSON := C.GoString(result.data)
	C.protect_free_string(result.data)

	var encrypted []Encrypted
	if err := json.Unmarshal([]byte(encryptedJSON), &encrypted); err != nil {
		return nil, err
	}

	return encrypted, nil
}

// EncryptQuery encrypts a value for searching against encrypted columns
func (c *Client) EncryptQuery(options EncryptQueryOptions) (*Encrypted, error) {
	if c.ptr == nil {
		return nil, newEncryptionError("client has been freed")
	}

	optionsJSON, err := json.Marshal(options)
	if err != nil {
		return nil, err
	}

	cOptionsJSON := C.CString(string(optionsJSON))
	defer C.free(unsafe.Pointer(cOptionsJSON))

	result := C.protect_encrypt_query((*C.struct_Client)(c.ptr), cOptionsJSON)

	if !result.success {
		errorStr := C.GoString(result.error)
		C.protect_free_string(result.error)
		return nil, newEncryptionError(errorStr)
	}

	encryptedJSON := C.GoString(result.data)
	C.protect_free_string(result.data)

	var encrypted Encrypted
	if err := json.Unmarshal([]byte(encryptedJSON), &encrypted); err != nil {
		return nil, err
	}

	return &encrypted, nil
}

// EncryptQueryBulk encrypts multiple values for searching against encrypted columns
func (c *Client) EncryptQueryBulk(options EncryptQueryBulkOptions) ([]Encrypted, error) {
	if c.ptr == nil {
		return nil, newEncryptionError("client has been freed")
	}

	optionsJSON, err := json.Marshal(options)
	if err != nil {
		return nil, err
	}

	cOptionsJSON := C.CString(string(optionsJSON))
	defer C.free(unsafe.Pointer(cOptionsJSON))

	result := C.protect_encrypt_query_bulk((*C.struct_Client)(c.ptr), cOptionsJSON)

	if !result.success {
		errorStr := C.GoString(result.error)
		C.protect_free_string(result.error)
		return nil, newEncryptionError(errorStr)
	}

	encryptedJSON := C.GoString(result.data)
	C.protect_free_string(result.data)

	var encrypted []Encrypted
	if err := json.Unmarshal([]byte(encryptedJSON), &encrypted); err != nil {
		return nil, err
	}

	return encrypted, nil
}

// Decrypt decrypts a single ciphertext value
func (c *Client) Decrypt(options DecryptOptions) (interface{}, error) {
	if c.ptr == nil {
		return nil, newEncryptionError("client has been freed")
	}

	optionsJSON, err := json.Marshal(options)
	if err != nil {
		return nil, err
	}

	cOptionsJSON := C.CString(string(optionsJSON))
	defer C.free(unsafe.Pointer(cOptionsJSON))

	result := C.protect_decrypt((*C.struct_Client)(c.ptr), cOptionsJSON)

	if !result.success {
		errorStr := C.GoString(result.error)
		C.protect_free_string(result.error)
		return nil, newEncryptionError(errorStr)
	}

	plaintextJSON := C.GoString(result.data)
	C.protect_free_string(result.data)

	var plaintext interface{}
	if err := json.Unmarshal([]byte(plaintextJSON), &plaintext); err != nil {
		return nil, err
	}

	return plaintext, nil
}

// DecryptBulk decrypts multiple ciphertext values
func (c *Client) DecryptBulk(options DecryptBulkOptions) ([]interface{}, error) {
	if c.ptr == nil {
		return nil, newEncryptionError("client has been freed")
	}

	optionsJSON, err := json.Marshal(options)
	if err != nil {
		return nil, err
	}

	cOptionsJSON := C.CString(string(optionsJSON))
	defer C.free(unsafe.Pointer(cOptionsJSON))

	result := C.protect_decrypt_bulk((*C.struct_Client)(c.ptr), cOptionsJSON)

	if !result.success {
		errorStr := C.GoString(result.error)
		C.protect_free_string(result.error)
		return nil, newEncryptionError(errorStr)
	}

	plaintextJSON := C.GoString(result.data)
	C.protect_free_string(result.data)

	var plaintexts []interface{}
	if err := json.Unmarshal([]byte(plaintextJSON), &plaintexts); err != nil {
		return nil, err
	}

	return plaintexts, nil
}

// DecryptBulkFallible decrypts multiple ciphertext values with individual error handling
func (c *Client) DecryptBulkFallible(options DecryptBulkOptions) ([]DecryptResult, error) {
	if c.ptr == nil {
		return nil, newEncryptionError("client has been freed")
	}

	optionsJSON, err := json.Marshal(options)
	if err != nil {
		return nil, err
	}

	cOptionsJSON := C.CString(string(optionsJSON))
	defer C.free(unsafe.Pointer(cOptionsJSON))

	result := C.protect_decrypt_bulk_fallible((*C.struct_Client)(c.ptr), cOptionsJSON)

	if !result.success {
		errorStr := C.GoString(result.error)
		C.protect_free_string(result.error)
		return nil, newEncryptionError(errorStr)
	}

	resultsJSON := C.GoString(result.data)
	C.protect_free_string(result.data)

	var results []DecryptResult
	if err := json.Unmarshal([]byte(resultsJSON), &results); err != nil {
		return nil, err
	}

	return results, nil
}

// IsEncrypted checks if a value is a valid encrypted payload.
// This is a standalone function that does not require a Client.
func IsEncrypted(value interface{}) bool {
	valueJSON, err := json.Marshal(value)
	if err != nil {
		return false
	}

	cValueJSON := C.CString(string(valueJSON))
	defer C.free(unsafe.Pointer(cValueJSON))

	return bool(C.protect_is_encrypted(cValueJSON))
}
