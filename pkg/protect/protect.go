package protect

/*
#cgo LDFLAGS: -L../../target/release -lprotect_ffi
#include "../../protect_ffi.h"
#include <stdlib.h>
*/
import "C"
import (
	"encoding/json"
	"errors"
	"unsafe"
)

// Client represents a protect FFI client
type Client struct {
	ptr unsafe.Pointer
}

// CastAs represents the different data types for column casting
type CastAs string

const (
	CastAsBigInt   CastAs = "big_int"
	CastAsBoolean  CastAs = "boolean"
	CastAsDate     CastAs = "date"
	CastAsReal     CastAs = "real"
	CastAsDouble   CastAs = "double"
	CastAsInt      CastAs = "int"
	CastAsSmallInt CastAs = "small_int"
	CastAsText     CastAs = "text"
	CastAsJsonB    CastAs = "jsonb"
)

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
	Prefix string `json:"prefix"`
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

// ClientOpts represents client configuration options
type ClientOpts struct {
	WorkspaceCrn *string `json:"workspaceCrn,omitempty"`
	AccessKey    *string `json:"accessKey,omitempty"`
	ClientID     *string `json:"clientId,omitempty"`
	ClientKey    *string `json:"clientKey,omitempty"`
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
	Plaintext         string       `json:"plaintext"`
	Column            string       `json:"column"`
	Table             string       `json:"table"`
	LockContext       *LockContext `json:"lockContext,omitempty"`
	ServiceToken      *string      `json:"serviceToken,omitempty"`
	UnverifiedContext interface{}  `json:"unverifiedContext,omitempty"`
}

// PlaintextPayload represents a single plaintext item for bulk encryption
type PlaintextPayload struct {
	Plaintext   string       `json:"plaintext"`
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
	Ciphertext        string       `json:"ciphertext"`
	LockContext       *LockContext `json:"lockContext,omitempty"`
	ServiceToken      *string      `json:"serviceToken,omitempty"`
	UnverifiedContext interface{}  `json:"unverifiedContext,omitempty"`
}

// BulkDecryptPayload represents a single ciphertext item for bulk decryption
type BulkDecryptPayload struct {
	Ciphertext  string       `json:"ciphertext"`
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
	Kind string `json:"k"`
	// For ciphertext type
	Ciphertext  *string    `json:"c,omitempty"`
	OreIndex    *[]string  `json:"ob,omitempty"`
	MatchIndex  *[]uint16  `json:"bf,omitempty"`
	UniqueIndex *string    `json:"hm,omitempty"`
	Identifier  Identifier `json:"i"`
	Version     uint16     `json:"v"`
	// For SteVec type
	SteVecIndex interface{} `json:"sv,omitempty"`
}

// DecryptResult represents the result of a fallible decryption operation
type DecryptResult struct {
	Data  *string `json:"data,omitempty"`
	Error *string `json:"error,omitempty"`
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
		return nil, errors.New(errorStr)
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
		return nil, errors.New("client has been freed")
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
		return nil, errors.New(errorStr)
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
		return nil, errors.New("client has been freed")
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
		return nil, errors.New(errorStr)
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
func (c *Client) Decrypt(options DecryptOptions) (string, error) {
	if c.ptr == nil {
		return "", errors.New("client has been freed")
	}

	optionsJSON, err := json.Marshal(options)
	if err != nil {
		return "", err
	}

	cOptionsJSON := C.CString(string(optionsJSON))
	defer C.free(unsafe.Pointer(cOptionsJSON))

	result := C.protect_decrypt((*C.struct_Client)(c.ptr), cOptionsJSON)

	if !result.success {
		errorStr := C.GoString(result.error)
		C.protect_free_string(result.error)
		return "", errors.New(errorStr)
	}

	plaintext := C.GoString(result.data)
	C.protect_free_string(result.data)

	return plaintext, nil
}

// DecryptBulk decrypts multiple ciphertext values
func (c *Client) DecryptBulk(options DecryptBulkOptions) ([]string, error) {
	if c.ptr == nil {
		return nil, errors.New("client has been freed")
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
		return nil, errors.New(errorStr)
	}

	plaintextJSON := C.GoString(result.data)
	C.protect_free_string(result.data)

	var plaintexts []string
	if err := json.Unmarshal([]byte(plaintextJSON), &plaintexts); err != nil {
		return nil, err
	}

	return plaintexts, nil
}

// DecryptBulkFallible decrypts multiple ciphertext values with individual error handling
func (c *Client) DecryptBulkFallible(options DecryptBulkOptions) ([]DecryptResult, error) {
	if c.ptr == nil {
		return nil, errors.New("client has been freed")
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
		return nil, errors.New(errorStr)
	}

	resultsJSON := C.GoString(result.data)
	C.protect_free_string(result.data)

	var results []DecryptResult
	if err := json.Unmarshal([]byte(resultsJSON), &results); err != nil {
		return nil, err
	}

	return results, nil
}
