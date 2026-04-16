// Package protect provides field-level encryption with searchable encryption support,
// powered by CipherStash ZeroKMS.
//
// Define your schema using struct tags or the programmatic builder, then use
// the Client to encrypt, decrypt, and query encrypted data.
//
//	users, err := protect.TableSchema("users", User{})
//	client, err := protect.NewClient(ctx, protect.WithSchemas(users))
//	defer client.Close()
//
//	encrypted, err := client.Encrypt(ctx, users.Column("email"), "john@example.com")
//
// # Concurrency
//
// A Client is safe for concurrent use by multiple goroutines. All exported
// methods synchronize access to the underlying FFI handle.
//
// # Credentials
//
// If no explicit credentials are provided via [WithCredentials], the client
// reads configuration from environment variables (CS_WORKSPACE_CRN,
// CS_CLIENT_ACCESS_KEY, CS_CLIENT_ID, CS_CLIENT_KEY) or from
// cipherstash.toml / cipherstash.secret.toml in the working directory.
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
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sync"
	"unsafe"
)

// Compile-time interface assertions.
var _ io.Closer = (*Client)(nil)

// ---------------------------------------------------------------------------
// Core types
// ---------------------------------------------------------------------------

// Client is the main entry point for encryption and decryption operations.
// Create one with [NewClient] and release resources with [Client.Close].
//
// A Client is safe for concurrent use by multiple goroutines.
type Client struct {
	mu  sync.RWMutex
	ptr unsafe.Pointer
}

// Close releases resources held by the client. Implements [io.Closer].
// It is safe to call Close multiple times; subsequent calls are no-ops.
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ptr == nil {
		return nil
	}
	C.protect_free_client((*C.struct_Client)(c.ptr))
	c.ptr = nil
	return nil
}

// acquirePtr returns the FFI pointer under a read lock, or an error if the
// client is closed. The caller must call the returned unlock function when done.
func (c *Client) acquirePtr(op string) (unsafe.Pointer, func(), error) {
	c.mu.RLock()
	if c.ptr == nil {
		c.mu.RUnlock()
		return nil, nil, &Error{Op: op, Err: ErrClientClosed, Message: "protect: client is closed"}
	}
	return c.ptr, c.mu.RUnlock, nil
}

// ColumnRef is a reference to an encrypted column within a table schema.
// Created by TableDef.Column; carries the table and column names for use
// in Encrypt, Decrypt, and query operations.
type ColumnRef struct {
	table  string
	column string
}

// QueryType identifies the type of encrypted search to perform.
type QueryType string

const (
	// Equality produces a unique (HMAC) index for exact-match lookups.
	Equality QueryType = "unique"

	// FreeTextSearch produces a match (bloom filter) index for full-text search.
	FreeTextSearch QueryType = "match"

	// OrderAndRange produces an ORE index for range and ordering queries.
	OrderAndRange QueryType = "ore"

	// JSONSelector produces an ste_vec selector index for JSON path queries.
	JSONSelector QueryType = "ste_vec_selector"

	// JSONContains produces an ste_vec term index for JSON containment queries.
	JSONContains QueryType = "ste_vec_term"
)

// ---------------------------------------------------------------------------
// CastAs and schema config types (exported for schema building and FFI JSON)
// ---------------------------------------------------------------------------

// CastAs represents the target data type for column casting in the encryption config.
type CastAs string

const (
	CastAsBigInt  CastAs = "bigint"
	CastAsBoolean CastAs = "boolean"
	CastAsDate    CastAs = "date"
	CastAsNumber  CastAs = "number"
	CastAsString  CastAs = "string"
	CastAsText    CastAs = "text"
	CastAsJSON    CastAs = "json"

	// CastAsJson is a deprecated alias for [CastAsJSON].
	//
	// Deprecated: Use CastAsJSON instead.
	CastAsJson = CastAsJSON
)

// Identifier represents a table and column identifier in the EQL wire format.
type Identifier struct {
	Table  string `json:"t"`
	Column string `json:"c"`
}

// OreIndexOpts represents options for an ORE (order-revealing encryption) index.
type OreIndexOpts struct{}

// UniqueIndexOpts represents options for a unique (HMAC) index.
type UniqueIndexOpts struct {
	TokenFilters []TokenFilter `json:"token_filters,omitempty"`
}

// TokenFilter represents a token filter configuration (e.g., downcase).
type TokenFilter struct {
	Kind string `json:"kind"`
}

// MatchIndexOpts represents options for a match (bloom filter) index.
type MatchIndexOpts struct {
	Tokenizer       *Tokenizer    `json:"tokenizer,omitempty"`
	TokenFilters    []TokenFilter `json:"token_filters,omitempty"`
	K               *int          `json:"k,omitempty"`
	M               *int          `json:"m,omitempty"`
	IncludeOriginal *bool         `json:"include_original,omitempty"`
}

// Tokenizer represents tokenizer configuration for a match index.
type Tokenizer struct {
	Kind        string `json:"kind"`
	TokenLength *int   `json:"token_length,omitempty"`
}

// SteVecIndexOpts represents options for an SteVec (structured encryption vector) index.
type SteVecIndexOpts struct {
	Prefix         string        `json:"prefix"`
	TermFilters    []TokenFilter `json:"term_filters,omitempty"`
	ArrayIndexMode *string       `json:"array_index_mode,omitempty"`
}

// Indexes represents the index configuration for an encrypted column.
type Indexes struct {
	OreIndex    *OreIndexOpts    `json:"ore,omitempty"`
	UniqueIndex *UniqueIndexOpts `json:"unique,omitempty"`
	MatchIndex  *MatchIndexOpts  `json:"match,omitempty"`
	SteVecIndex *SteVecIndexOpts `json:"ste_vec,omitempty"`
}

// Column represents the encryption configuration for a single column.
type Column struct {
	CastAs  *CastAs  `json:"cast_as,omitempty"`
	Indexes *Indexes `json:"indexes,omitempty"`
}

// Table represents a table configuration with its columns.
type Table map[string]Column

// Tables represents all table configurations.
type Tables map[string]Table

// EncryptConfig represents the complete encryption configuration sent to the FFI.
type EncryptConfig struct {
	Version uint32 `json:"v"`
	Tables  Tables `json:"tables"`
}

// LockContext represents identity claims for identity-aware encryption.
type LockContext struct {
	IdentityClaim []string `json:"identityClaim"`
}

// Encrypted represents an encrypted value with its metadata and indexes.
// The JSON tags match the EQL wire format and must not be changed.
type Encrypted struct {
	Identifier  Identifier `json:"i"`
	Version     uint16     `json:"v"`
	Ciphertext  *string    `json:"c,omitempty"`
	OreIndex    *[]string  `json:"ob,omitempty"`
	MatchIndex  *[]uint16  `json:"bf,omitempty"`
	UniqueIndex *string    `json:"hm,omitempty"`
	SteVecIndex any        `json:"sv,omitempty"`
}

// PlaintextItem is a single value for bulk encryption via [Client.EncryptBulk].
type PlaintextItem struct {
	// Column identifies the table and column for encryption.
	Column ColumnRef
	// Plaintext is the value to encrypt. Must be JSON-serializable.
	Plaintext any
	// LockContext optionally overrides the call-level lock context for this item.
	LockContext *LockContext
}

// QueryItem is a single query for bulk query encryption via [Client.EncryptQueryBulk].
type QueryItem struct {
	// Column identifies the table and column to query.
	Column ColumnRef
	// QueryType selects the index type for the search.
	QueryType QueryType
	// Plaintext is the search term. Must be JSON-serializable.
	Plaintext any
	// LockContext optionally overrides the call-level lock context for this item.
	LockContext *LockContext
}

// DecryptResult represents the result of a single item in a fallible bulk
// decryption via [Client.DecryptBulkFallible]. Exactly one of Data or Err
// is populated.
type DecryptResult struct {
	// Data holds the decrypted plaintext as a JSON-deserialized Go value.
	Data any
	// Err holds the decryption error for this item, if any.
	Err error
}

// ---------------------------------------------------------------------------
// Client options (functional options for NewClient)
// ---------------------------------------------------------------------------

type clientConfig struct {
	schemas      []*TableDef
	workspaceCRN string
	accessKey    string
	clientID     string
	clientKey    string
	keysetName   string
	keysetID     string
}

// ClientOption configures the Client during construction.
type ClientOption func(*clientConfig)

// WithSchemas registers one or more table schemas with the client.
// The schemas define which tables and columns can be encrypted.
func WithSchemas(schemas ...*TableDef) ClientOption {
	return func(c *clientConfig) {
		c.schemas = append(c.schemas, schemas...)
	}
}

// WithCredentials sets explicit credentials for the client.
// If not provided, the client falls back to environment variables.
func WithCredentials(workspaceCRN, accessKey, clientID, clientKey string) ClientOption {
	return func(c *clientConfig) {
		c.workspaceCRN = workspaceCRN
		c.accessKey = accessKey
		c.clientID = clientID
		c.clientKey = clientKey
	}
}

// WithKeyset selects a named keyset for multi-tenant key isolation.
func WithKeyset(name string) ClientOption {
	return func(c *clientConfig) {
		c.keysetName = name
	}
}

// WithKeysetID selects a keyset by its unique identifier.
func WithKeysetID(id string) ClientOption {
	return func(c *clientConfig) {
		c.keysetID = id
	}
}

// ---------------------------------------------------------------------------
// Operation options (functional options for Encrypt/Decrypt/Query calls)
// ---------------------------------------------------------------------------

type callOpts struct {
	lockContext       *LockContext
	serviceToken      *string
	unverifiedContext any
}

// Option configures optional parameters for encrypt, decrypt, and query operations.
type Option func(*callOpts)

// WithLockContext attaches identity claims for identity-aware encryption.
func WithLockContext(lc *LockContext) Option {
	return func(o *callOpts) { o.lockContext = lc }
}

// WithServiceToken sets an explicit service token for the operation.
func WithServiceToken(token string) Option {
	return func(o *callOpts) { o.serviceToken = &token }
}

// WithAuditContext attaches unverified context for audit logging.
func WithAuditContext(ctx any) Option {
	return func(o *callOpts) { o.unverifiedContext = ctx }
}

func buildCallOpts(opts []Option) callOpts {
	var co callOpts
	for _, opt := range opts {
		opt(&co)
	}
	return co
}

// ---------------------------------------------------------------------------
// NewClient
// ---------------------------------------------------------------------------

// NewClient creates a new protect client configured with the given options.
// The ctx parameter is checked for cancellation before the FFI call.
func NewClient(ctx context.Context, opts ...ClientOption) (*Client, error) {
	cfg := &clientConfig{}
	for _, opt := range opts {
		opt(cfg)
	}

	encryptConfig := buildEncryptConfigFromSchemas(cfg.schemas)

	type ffiKeyset struct {
		Name *string `json:"name,omitempty"`
		ID   *string `json:"id,omitempty"`
	}
	type ffiClientOpts struct {
		WorkspaceCrn *string    `json:"workspaceCrn,omitempty"`
		AccessKey    *string    `json:"accessKey,omitempty"`
		ClientID     *string    `json:"clientId,omitempty"`
		ClientKey    *string    `json:"clientKey,omitempty"`
		Keyset       *ffiKeyset `json:"keyset,omitempty"`
	}
	type ffiNewClientOptions struct {
		EncryptConfig EncryptConfig  `json:"encryptConfig"`
		ClientOpts    *ffiClientOpts `json:"clientOpts,omitempty"`
	}

	ffiOpts := ffiNewClientOptions{
		EncryptConfig: encryptConfig,
	}

	if cfg.workspaceCRN != "" || cfg.accessKey != "" || cfg.clientID != "" || cfg.clientKey != "" || cfg.keysetName != "" || cfg.keysetID != "" {
		co := &ffiClientOpts{}
		if cfg.workspaceCRN != "" {
			co.WorkspaceCrn = &cfg.workspaceCRN
		}
		if cfg.accessKey != "" {
			co.AccessKey = &cfg.accessKey
		}
		if cfg.clientID != "" {
			co.ClientID = &cfg.clientID
		}
		if cfg.clientKey != "" {
			co.ClientKey = &cfg.clientKey
		}
		if cfg.keysetName != "" || cfg.keysetID != "" {
			ks := &ffiKeyset{}
			if cfg.keysetName != "" {
				ks.Name = &cfg.keysetName
			}
			if cfg.keysetID != "" {
				ks.ID = &cfg.keysetID
			}
			co.Keyset = ks
		}
		ffiOpts.ClientOpts = co
	}

	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("protect: NewClient: %w", err)
	}

	optionsJSON, err := json.Marshal(ffiOpts)
	if err != nil {
		return nil, fmt.Errorf("protect: NewClient: marshaling options: %w", err)
	}

	cOptionsJSON := C.CString(string(optionsJSON))
	defer C.free(unsafe.Pointer(cOptionsJSON))

	result := C.protect_new_client(cOptionsJSON)
	if !result.success {
		errorStr := C.GoString(result.error)
		C.protect_free_string(result.error)
		return nil, newError("NewClient", errorStr)
	}

	return &Client{ptr: unsafe.Pointer(result.data)}, nil
}

func buildEncryptConfigFromSchemas(schemas []*TableDef) EncryptConfig {
	tbls := make(Tables, len(schemas))
	for _, td := range schemas {
		tbl := make(Table, len(td.columns))
		for colName, col := range td.columns {
			tbl[colName] = col
		}
		tbls[td.name] = tbl
	}
	return EncryptConfig{
		Version: 1,
		Tables:  tbls,
	}
}

// ---------------------------------------------------------------------------
// Encrypt
// ---------------------------------------------------------------------------

// Encrypt encrypts a single plaintext value for the given column.
//
// The plaintext can be any JSON-serializable value. The returned [Encrypted]
// payload contains the ciphertext and any configured search indexes.
func (c *Client) Encrypt(ctx context.Context, col ColumnRef, plaintext any, opts ...Option) (*Encrypted, error) {
	const op = "Encrypt"

	ptr, unlock, err := c.acquirePtr(op)
	if err != nil {
		return nil, err
	}
	defer unlock()

	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("protect: %s: %w", op, err)
	}

	co := buildCallOpts(opts)

	type ffiEncryptOptions struct {
		Plaintext         any          `json:"plaintext"`
		Column            string       `json:"column"`
		Table             string       `json:"table"`
		LockContext       *LockContext `json:"lockContext,omitempty"`
		ServiceToken      *string      `json:"serviceToken,omitempty"`
		UnverifiedContext any          `json:"unverifiedContext,omitempty"`
	}

	ffiOpts := ffiEncryptOptions{
		Plaintext:         plaintext,
		Column:            col.column,
		Table:             col.table,
		LockContext:       co.lockContext,
		ServiceToken:      co.serviceToken,
		UnverifiedContext: co.unverifiedContext,
	}

	optionsJSON, err := json.Marshal(ffiOpts)
	if err != nil {
		return nil, fmt.Errorf("protect: %s: marshaling options: %w", op, err)
	}

	cOptionsJSON := C.CString(string(optionsJSON))
	defer C.free(unsafe.Pointer(cOptionsJSON))

	result := C.protect_encrypt((*C.struct_Client)(ptr), cOptionsJSON)
	if !result.success {
		errorStr := C.GoString(result.error)
		C.protect_free_string(result.error)
		return nil, newError(op, errorStr)
	}

	encryptedJSON := C.GoString(result.data)
	C.protect_free_string(result.data)

	var encrypted Encrypted
	if err := json.Unmarshal([]byte(encryptedJSON), &encrypted); err != nil {
		return nil, fmt.Errorf("protect: %s: unmarshaling result: %w", op, err)
	}

	return &encrypted, nil
}

// ---------------------------------------------------------------------------
// Decrypt
// ---------------------------------------------------------------------------

// Decrypt decrypts a single encrypted value and returns the plaintext.
//
// The returned value is a JSON-deserialized Go value: string, float64, bool,
// nil, map[string]any, or []any, depending on what was originally encrypted.
func (c *Client) Decrypt(ctx context.Context, encrypted *Encrypted, opts ...Option) (any, error) {
	const op = "Decrypt"

	ptr, unlock, err := c.acquirePtr(op)
	if err != nil {
		return nil, err
	}
	defer unlock()

	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("protect: %s: %w", op, err)
	}

	co := buildCallOpts(opts)

	type ffiDecryptOptions struct {
		Ciphertext        *Encrypted   `json:"ciphertext"`
		LockContext       *LockContext `json:"lockContext,omitempty"`
		ServiceToken      *string      `json:"serviceToken,omitempty"`
		UnverifiedContext any          `json:"unverifiedContext,omitempty"`
	}

	ffiOpts := ffiDecryptOptions{
		Ciphertext:        encrypted,
		LockContext:       co.lockContext,
		ServiceToken:      co.serviceToken,
		UnverifiedContext: co.unverifiedContext,
	}

	optionsJSON, err := json.Marshal(ffiOpts)
	if err != nil {
		return nil, fmt.Errorf("protect: %s: marshaling options: %w", op, err)
	}

	cOptionsJSON := C.CString(string(optionsJSON))
	defer C.free(unsafe.Pointer(cOptionsJSON))

	result := C.protect_decrypt((*C.struct_Client)(ptr), cOptionsJSON)
	if !result.success {
		errorStr := C.GoString(result.error)
		C.protect_free_string(result.error)
		return nil, newError(op, errorStr)
	}

	plaintextJSON := C.GoString(result.data)
	C.protect_free_string(result.data)

	var plaintext any
	if err := json.Unmarshal([]byte(plaintextJSON), &plaintext); err != nil {
		return nil, fmt.Errorf("protect: %s: unmarshaling result: %w", op, err)
	}

	return plaintext, nil
}

// ---------------------------------------------------------------------------
// EncryptBulk
// ---------------------------------------------------------------------------

// EncryptBulk encrypts multiple plaintext values in a single operation.
// This is significantly more efficient than calling [Client.Encrypt] in a loop
// because it uses a single KMS call for all items.
func (c *Client) EncryptBulk(ctx context.Context, items []PlaintextItem, opts ...Option) ([]Encrypted, error) {
	const op = "EncryptBulk"

	ptr, unlock, err := c.acquirePtr(op)
	if err != nil {
		return nil, err
	}
	defer unlock()

	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("protect: %s: %w", op, err)
	}

	co := buildCallOpts(opts)

	type ffiPlaintextPayload struct {
		Plaintext   any          `json:"plaintext"`
		Column      string       `json:"column"`
		Table       string       `json:"table"`
		LockContext *LockContext `json:"lockContext,omitempty"`
	}
	type ffiBulkOptions struct {
		Plaintexts        []ffiPlaintextPayload `json:"plaintexts"`
		ServiceToken      *string               `json:"serviceToken,omitempty"`
		UnverifiedContext any                   `json:"unverifiedContext,omitempty"`
	}

	payloads := make([]ffiPlaintextPayload, len(items))
	for i, item := range items {
		lc := item.LockContext
		if lc == nil {
			lc = co.lockContext
		}
		payloads[i] = ffiPlaintextPayload{
			Plaintext:   item.Plaintext,
			Column:      item.Column.column,
			Table:       item.Column.table,
			LockContext: lc,
		}
	}

	ffiOpts := ffiBulkOptions{
		Plaintexts:        payloads,
		ServiceToken:      co.serviceToken,
		UnverifiedContext: co.unverifiedContext,
	}

	optionsJSON, err := json.Marshal(ffiOpts)
	if err != nil {
		return nil, fmt.Errorf("protect: %s: marshaling options: %w", op, err)
	}

	cOptionsJSON := C.CString(string(optionsJSON))
	defer C.free(unsafe.Pointer(cOptionsJSON))

	result := C.protect_encrypt_bulk((*C.struct_Client)(ptr), cOptionsJSON)
	if !result.success {
		errorStr := C.GoString(result.error)
		C.protect_free_string(result.error)
		return nil, newError(op, errorStr)
	}

	encryptedJSON := C.GoString(result.data)
	C.protect_free_string(result.data)

	var encrypted []Encrypted
	if err := json.Unmarshal([]byte(encryptedJSON), &encrypted); err != nil {
		return nil, fmt.Errorf("protect: %s: unmarshaling result: %w", op, err)
	}

	return encrypted, nil
}

// ---------------------------------------------------------------------------
// DecryptBulk
// ---------------------------------------------------------------------------

// DecryptBulk decrypts multiple encrypted values in a single operation.
// Use [WithLockContext] to apply a shared lock context to all items.
func (c *Client) DecryptBulk(ctx context.Context, items []*Encrypted, opts ...Option) ([]any, error) {
	const op = "DecryptBulk"

	ptr, unlock, err := c.acquirePtr(op)
	if err != nil {
		return nil, err
	}
	defer unlock()

	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("protect: %s: %w", op, err)
	}

	co := buildCallOpts(opts)

	type ffiBulkDecryptPayload struct {
		Ciphertext  *Encrypted   `json:"ciphertext"`
		LockContext *LockContext `json:"lockContext,omitempty"`
	}
	type ffiBulkDecryptOptions struct {
		Ciphertexts       []ffiBulkDecryptPayload `json:"ciphertexts"`
		ServiceToken      *string                 `json:"serviceToken,omitempty"`
		UnverifiedContext any                     `json:"unverifiedContext,omitempty"`
	}

	payloads := make([]ffiBulkDecryptPayload, len(items))
	for i, item := range items {
		payloads[i] = ffiBulkDecryptPayload{
			Ciphertext:  item,
			LockContext: co.lockContext,
		}
	}

	ffiOpts := ffiBulkDecryptOptions{
		Ciphertexts:       payloads,
		ServiceToken:      co.serviceToken,
		UnverifiedContext: co.unverifiedContext,
	}

	optionsJSON, err := json.Marshal(ffiOpts)
	if err != nil {
		return nil, fmt.Errorf("protect: %s: marshaling options: %w", op, err)
	}

	cOptionsJSON := C.CString(string(optionsJSON))
	defer C.free(unsafe.Pointer(cOptionsJSON))

	result := C.protect_decrypt_bulk((*C.struct_Client)(ptr), cOptionsJSON)
	if !result.success {
		errorStr := C.GoString(result.error)
		C.protect_free_string(result.error)
		return nil, newError(op, errorStr)
	}

	plaintextJSON := C.GoString(result.data)
	C.protect_free_string(result.data)

	var plaintexts []any
	if err := json.Unmarshal([]byte(plaintextJSON), &plaintexts); err != nil {
		return nil, fmt.Errorf("protect: %s: unmarshaling result: %w", op, err)
	}

	return plaintexts, nil
}

// ---------------------------------------------------------------------------
// DecryptBulkFallible
// ---------------------------------------------------------------------------

// DecryptBulkFallible decrypts multiple encrypted values, returning per-item
// results where each item independently succeeds or fails.
//
// Unlike [Client.DecryptBulk], a single item's failure does not cause the
// entire operation to fail. Check each [DecryptResult.Err] individually.
func (c *Client) DecryptBulkFallible(ctx context.Context, items []*Encrypted, opts ...Option) ([]DecryptResult, error) {
	const op = "DecryptBulkFallible"

	ptr, unlock, err := c.acquirePtr(op)
	if err != nil {
		return nil, err
	}
	defer unlock()

	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("protect: %s: %w", op, err)
	}

	co := buildCallOpts(opts)

	type ffiBulkDecryptPayload struct {
		Ciphertext  *Encrypted   `json:"ciphertext"`
		LockContext *LockContext `json:"lockContext,omitempty"`
	}
	type ffiBulkDecryptOptions struct {
		Ciphertexts       []ffiBulkDecryptPayload `json:"ciphertexts"`
		ServiceToken      *string                 `json:"serviceToken,omitempty"`
		UnverifiedContext any                     `json:"unverifiedContext,omitempty"`
	}

	payloads := make([]ffiBulkDecryptPayload, len(items))
	for i, item := range items {
		payloads[i] = ffiBulkDecryptPayload{
			Ciphertext:  item,
			LockContext: co.lockContext,
		}
	}

	ffiOpts := ffiBulkDecryptOptions{
		Ciphertexts:       payloads,
		ServiceToken:      co.serviceToken,
		UnverifiedContext: co.unverifiedContext,
	}

	optionsJSON, err := json.Marshal(ffiOpts)
	if err != nil {
		return nil, fmt.Errorf("protect: %s: marshaling options: %w", op, err)
	}

	cOptionsJSON := C.CString(string(optionsJSON))
	defer C.free(unsafe.Pointer(cOptionsJSON))

	result := C.protect_decrypt_bulk_fallible((*C.struct_Client)(ptr), cOptionsJSON)
	if !result.success {
		errorStr := C.GoString(result.error)
		C.protect_free_string(result.error)
		return nil, newError(op, errorStr)
	}

	resultsJSON := C.GoString(result.data)
	C.protect_free_string(result.data)

	type ffiDecryptResult struct {
		Data  any     `json:"data,omitempty"`
		Error *string `json:"error,omitempty"`
	}

	var ffiResults []ffiDecryptResult
	if err := json.Unmarshal([]byte(resultsJSON), &ffiResults); err != nil {
		return nil, fmt.Errorf("protect: %s: unmarshaling result: %w", op, err)
	}

	results := make([]DecryptResult, len(ffiResults))
	for i, r := range ffiResults {
		if r.Error != nil {
			results[i] = DecryptResult{Err: newError(op, *r.Error)}
		} else {
			results[i] = DecryptResult{Data: r.Data}
		}
	}

	return results, nil
}

// ---------------------------------------------------------------------------
// EncryptQuery
// ---------------------------------------------------------------------------

// EncryptQuery encrypts a value for searching against an encrypted column.
//
// The queryType determines which index is used for the search. For example,
// [Equality] produces an HMAC for exact-match, [FreeTextSearch] produces a
// bloom filter for full-text search, and [OrderAndRange] produces an ORE
// ciphertext for range comparisons.
func (c *Client) EncryptQuery(ctx context.Context, col ColumnRef, queryType QueryType, plaintext any, opts ...Option) (*Encrypted, error) {
	const op = "EncryptQuery"

	ptr, unlock, err := c.acquirePtr(op)
	if err != nil {
		return nil, err
	}
	defer unlock()

	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("protect: %s: %w", op, err)
	}

	co := buildCallOpts(opts)

	indexType, queryOp := resolveQueryType(queryType)

	type ffiEncryptQueryOptions struct {
		Plaintext         any          `json:"plaintext"`
		Column            string       `json:"column"`
		Table             string       `json:"table"`
		IndexType         string       `json:"indexType"`
		QueryOp           string       `json:"queryOp,omitempty"`
		LockContext       *LockContext `json:"lockContext,omitempty"`
		ServiceToken      *string      `json:"serviceToken,omitempty"`
		UnverifiedContext any          `json:"unverifiedContext,omitempty"`
	}

	ffiOpts := ffiEncryptQueryOptions{
		Plaintext:         plaintext,
		Column:            col.column,
		Table:             col.table,
		IndexType:         indexType,
		QueryOp:           queryOp,
		LockContext:       co.lockContext,
		ServiceToken:      co.serviceToken,
		UnverifiedContext: co.unverifiedContext,
	}

	optionsJSON, err := json.Marshal(ffiOpts)
	if err != nil {
		return nil, fmt.Errorf("protect: %s: marshaling options: %w", op, err)
	}

	cOptionsJSON := C.CString(string(optionsJSON))
	defer C.free(unsafe.Pointer(cOptionsJSON))

	result := C.protect_encrypt_query((*C.struct_Client)(ptr), cOptionsJSON)
	if !result.success {
		errorStr := C.GoString(result.error)
		C.protect_free_string(result.error)
		return nil, newError(op, errorStr)
	}

	encryptedJSON := C.GoString(result.data)
	C.protect_free_string(result.data)

	var encrypted Encrypted
	if err := json.Unmarshal([]byte(encryptedJSON), &encrypted); err != nil {
		return nil, fmt.Errorf("protect: %s: unmarshaling result: %w", op, err)
	}

	return &encrypted, nil
}

// ---------------------------------------------------------------------------
// EncryptQueryBulk
// ---------------------------------------------------------------------------

// EncryptQueryBulk encrypts multiple query values in a single operation.
func (c *Client) EncryptQueryBulk(ctx context.Context, queries []QueryItem, opts ...Option) ([]Encrypted, error) {
	const op = "EncryptQueryBulk"

	ptr, unlock, err := c.acquirePtr(op)
	if err != nil {
		return nil, err
	}
	defer unlock()

	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("protect: %s: %w", op, err)
	}

	co := buildCallOpts(opts)

	type ffiQueryPayload struct {
		Plaintext   any          `json:"plaintext"`
		Column      string       `json:"column"`
		Table       string       `json:"table"`
		IndexType   string       `json:"indexType"`
		QueryOp     string       `json:"queryOp,omitempty"`
		LockContext *LockContext `json:"lockContext,omitempty"`
	}
	type ffiBulkQueryOptions struct {
		Queries           []ffiQueryPayload `json:"queries"`
		ServiceToken      *string           `json:"serviceToken,omitempty"`
		UnverifiedContext any               `json:"unverifiedContext,omitempty"`
	}

	payloads := make([]ffiQueryPayload, len(queries))
	for i, q := range queries {
		indexType, queryOp := resolveQueryType(q.QueryType)
		lc := q.LockContext
		if lc == nil {
			lc = co.lockContext
		}
		payloads[i] = ffiQueryPayload{
			Plaintext:   q.Plaintext,
			Column:      q.Column.column,
			Table:       q.Column.table,
			IndexType:   indexType,
			QueryOp:     queryOp,
			LockContext: lc,
		}
	}

	ffiOpts := ffiBulkQueryOptions{
		Queries:           payloads,
		ServiceToken:      co.serviceToken,
		UnverifiedContext: co.unverifiedContext,
	}

	optionsJSON, err := json.Marshal(ffiOpts)
	if err != nil {
		return nil, fmt.Errorf("protect: %s: marshaling options: %w", op, err)
	}

	cOptionsJSON := C.CString(string(optionsJSON))
	defer C.free(unsafe.Pointer(cOptionsJSON))

	result := C.protect_encrypt_query_bulk((*C.struct_Client)(ptr), cOptionsJSON)
	if !result.success {
		errorStr := C.GoString(result.error)
		C.protect_free_string(result.error)
		return nil, newError(op, errorStr)
	}

	encryptedJSON := C.GoString(result.data)
	C.protect_free_string(result.data)

	var encrypted []Encrypted
	if err := json.Unmarshal([]byte(encryptedJSON), &encrypted); err != nil {
		return nil, fmt.Errorf("protect: %s: unmarshaling result: %w", op, err)
	}

	return encrypted, nil
}

// ---------------------------------------------------------------------------
// IsEncrypted
// ---------------------------------------------------------------------------

// IsEncrypted checks whether a value is a valid EQL encrypted payload.
// This is a standalone function that does not require a [Client].
//
// Note: this function makes a CGO call to validate the payload structure.
func IsEncrypted(value any) bool {
	valueJSON, err := json.Marshal(value)
	if err != nil {
		return false
	}

	cValueJSON := C.CString(string(valueJSON))
	defer C.free(unsafe.Pointer(cValueJSON))

	return bool(C.protect_is_encrypted(cValueJSON))
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

// resolveQueryType maps a public QueryType to the FFI's indexType and queryOp
// string values. For standard index types (unique, match, ore), queryOp is
// "default". For ste_vec variants, the indexType is "ste_vec" and queryOp
// carries the specific operation.
func resolveQueryType(qt QueryType) (indexType string, queryOp string) {
	switch qt {
	case Equality:
		return "unique", "default"
	case FreeTextSearch:
		return "match", "default"
	case OrderAndRange:
		return "ore", "default"
	case JSONSelector:
		return "ste_vec", "ste_vec_selector"
	case JSONContains:
		return "ste_vec", "ste_vec_term"
	default:
		return string(qt), "default"
	}
}
