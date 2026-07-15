// Package encryption provides field-level encryption with searchable encryption support,
// powered by CipherStash ZeroKMS.
//
// Define your schema using struct tags or the programmatic builder, then use
// the Client to encrypt, decrypt, and query encrypted data.
//
//	users, err := encryption.TableSchema("users", User{})
//	client, err := encryption.NewClient(ctx, encryption.WithSchemas(users))
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
package encryption

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
#include <stdint.h>

// protectgoGetToken is the Go token callback exported in callback.go. It is
// declared here (a declaration, not a definition) so the static bridge
// functions below can reference it as a C function pointer of type
// ProtectTokenFn.
extern char *protectgoGetToken(uint64_t handle);

// protectNewClientWithToken calls protect_new_client wiring the exported Go
// token callback for the given cgo.Handle value.
static struct CResult protectNewClientWithToken(const char *opts, uint64_t handle) {
    return protect_new_client(opts, protectgoGetToken, handle);
}

// protectNewClientNoToken calls protect_new_client with no token callback,
// passing a NULL function pointer and a zero handle.
static struct CResult protectNewClientNoToken(const char *opts) {
    return protect_new_client(opts, NULL, 0);
}
*/
import "C"
import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"runtime/cgo"
	"sync"
	"time"
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

	// tokenHandle references the per-client token provider registered with the
	// native layer when an authentication strategy callback is configured. It
	// is released by Close. hasToken reports whether tokenHandle is live.
	tokenHandle cgo.Handle
	hasToken    bool
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
	if c.hasToken {
		c.tokenHandle.Delete()
		c.hasToken = false
	}
	return nil
}

// acquirePtr returns the FFI pointer under a read lock, or an error if the
// client is closed. The caller must call the returned unlock function when done.
func (c *Client) acquirePtr(op string) (unsafe.Pointer, func(), error) {
	c.mu.RLock()
	if c.ptr == nil {
		c.mu.RUnlock()
		return nil, nil, &Error{Op: op, Err: ErrClientClosed, Message: "encryption: client is closed"}
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

// CastAs represents the target data type for column casting in the encryption
// config. Values are normalized to their canonical form when the configuration
// is sent to the native layer, so both the canonical constants and the legacy
// aliases below produce identical wire output.
//
// Canonical types: [CastAsText], [CastAsBigInt], [CastAsInt], [CastAsSmallInt],
// [CastAsFloat], [CastAsDecimal], [CastAsBoolean], [CastAsDate],
// [CastAsTimestamp], and [CastAsJSON].
type CastAs string

const (
	// Canonical cast types.

	CastAsText      CastAs = "text"
	CastAsBigInt    CastAs = "bigint"
	CastAsInt       CastAs = "int"
	CastAsSmallInt  CastAs = "small_int"
	CastAsFloat     CastAs = "float"
	CastAsDecimal   CastAs = "decimal"
	CastAsBoolean   CastAs = "boolean"
	CastAsDate      CastAs = "date"
	CastAsTimestamp CastAs = "timestamp"
	CastAsJSON      CastAs = "json"

	// CastAsString is a legacy alias for [CastAsText]. It is normalized to
	// "text" on the wire.
	CastAsString CastAs = "string"

	// CastAsNumber is a legacy alias for [CastAsFloat]. It is normalized to
	// "float" on the wire.
	CastAsNumber CastAs = "number"

	// CastAsJson is a deprecated alias for [CastAsJSON].
	//
	// Deprecated: Use CastAsJSON instead.
	CastAsJson = CastAsJSON
)

// normalizeCastAs maps a public CastAs value to its canonical wire name.
// Legacy aliases are rewritten: string→text, number→float, bigint→big_int.
// All other values are already canonical and returned unchanged.
func normalizeCastAs(c CastAs) CastAs {
	switch c {
	case CastAsString:
		return CastAsText
	case CastAsNumber:
		return CastAsFloat
	case CastAsBigInt:
		return "big_int"
	default:
		return c
	}
}

// Identifier represents a table and column identifier in the encrypted wire format.
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
// The JSON tags match the native wire format and must not be changed.
// Fields are preserved verbatim so that a ciphertext round-tripped through Go
// is byte-for-byte compatible with what the native layer emits.
type Encrypted struct {
	Identifier  Identifier `json:"i"`
	Version     uint16     `json:"v"`
	K           *string    `json:"k,omitempty"`
	Ciphertext  *string    `json:"c,omitempty"`
	OreIndex    *[]string  `json:"ob,omitempty"`
	MatchIndex  *[]uint16  `json:"bf,omitempty"`
	UniqueIndex *string    `json:"hm,omitempty"`
	SteVecIndex any        `json:"sv,omitempty"`
	Op          *string    `json:"op,omitempty"`
}

// QueryTerm is an opaque encrypted query term produced by [Client.EncryptQuery]
// and [Client.EncryptQueryBulk]. Bind it directly into a SQL statement as the
// search value against an encrypted column.
//
// Depending on the column's index configuration, a query term may serialize as
// a JSON object or as a bare JSON string. Treat it as an opaque value: inspect
// it with [QueryTerm.Bytes] or [QueryTerm.String], and marshal it with
// encoding/json to obtain the exact payload the database expects. Do not depend
// on its internal shape.
type QueryTerm struct {
	raw json.RawMessage
}

// MarshalJSON returns the raw query-term JSON. A zero-value QueryTerm marshals
// as JSON null.
func (q QueryTerm) MarshalJSON() ([]byte, error) {
	if len(q.raw) == 0 {
		return []byte("null"), nil
	}
	return q.raw, nil
}

// UnmarshalJSON stores the raw JSON verbatim without interpreting its shape.
func (q *QueryTerm) UnmarshalJSON(data []byte) error {
	q.raw = append(q.raw[:0], data...)
	return nil
}

// Bytes returns the raw JSON encoding of the query term. The returned slice
// must not be modified.
func (q QueryTerm) Bytes() []byte { return q.raw }

// String returns the raw JSON encoding of the query term as a string.
func (q QueryTerm) String() string { return string(q.raw) }

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

	// oidcGetToken, when set, selects the OIDC federation auth strategy.
	oidcGetToken func(ctx context.Context) (string, error)
	// tokenProviderGetToken, when set, selects the direct token provider
	// auth strategy.
	tokenProviderGetToken func(ctx context.Context) (string, error)

	// encryptedFormat selects the ciphertext format version. The zero value
	// means "use the default" ([EncryptedFormatV2]).
	encryptedFormat EncryptedFormat
}

// ClientOption configures the Client during construction.
type ClientOption func(*clientConfig)

// EncryptedFormat selects the on-disk ciphertext format version produced by the
// client. Use it with [WithEncryptedFormat].
type EncryptedFormat int

const (
	// EncryptedFormatV2 is the default ciphertext format, compatible with
	// databases initialized with the v2 CipherStash database schema.
	EncryptedFormatV2 EncryptedFormat = 2

	// EncryptedFormatV3 targets databases initialized with the v3 CipherStash
	// database schema. Select it only when your database has been provisioned
	// for the v3 schema.
	EncryptedFormatV3 EncryptedFormat = 3
)

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

// WithOIDCFederation configures per-user identity federation. The provided
// getToken returns a fresh third-party OIDC access token (a JWT) from your
// application's identity provider (Clerk, Auth0, Supabase, and similar).
//
// The client exchanges that token for a short-lived CipherStash service token
// and caches it until expiry, invoking getToken again only when it must
// re-federate. This makes every encryption and decryption identity-aware at the
// client level, without threading any per-operation context through your calls.
//
// A workspace CRN is required: supply it via [WithCredentials] or the
// CS_WORKSPACE_CRN environment variable. [NewClient] returns an error wrapping
// [ErrAuthStrategy] if neither is present.
//
// WithOIDCFederation and [WithTokenProvider] are mutually exclusive.
func WithOIDCFederation(getToken func(ctx context.Context) (string, error)) ClientOption {
	return func(c *clientConfig) {
		c.oidcGetToken = getToken
	}
}

// WithTokenProvider supplies a CipherStash service token directly. The provided
// getToken is called on every keyservice request and must return a valid
// service token; caching is the caller's responsibility.
//
// This is an advanced option for callers that mint or broker CipherStash
// service tokens themselves. Most applications should prefer
// [WithOIDCFederation], which handles token exchange and caching.
//
// WithTokenProvider and [WithOIDCFederation] are mutually exclusive.
func WithTokenProvider(getToken func(ctx context.Context) (string, error)) ClientOption {
	return func(c *clientConfig) {
		c.tokenProviderGetToken = getToken
	}
}

// WithEncryptedFormat selects the ciphertext format version. The default is
// [EncryptedFormatV2]. Select [EncryptedFormatV3] only for databases that have
// been initialized with the v3 CipherStash database schema.
func WithEncryptedFormat(f EncryptedFormat) ClientOption {
	return func(c *clientConfig) {
		c.encryptedFormat = f
	}
}

// ---------------------------------------------------------------------------
// Operation options (functional options for Encrypt/Decrypt/Query calls)
// ---------------------------------------------------------------------------

type callOpts struct {
	lockContext       *LockContext
	unverifiedContext any
}

// Option configures optional parameters for encrypt, decrypt, and query operations.
type Option func(*callOpts)

// WithLockContext attaches identity claims for identity-aware encryption.
func WithLockContext(lc *LockContext) Option {
	return func(o *callOpts) { o.lockContext = lc }
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

// FFI-facing option types for NewClient. Field names use camelCase to match
// the native wire contract.
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

type ffiAuthStrategy struct {
	Type string `json:"type"`
}

type ffiNewClientOptions struct {
	EncryptConfig EncryptConfig    `json:"encryptConfig"`
	ClientOpts    *ffiClientOpts   `json:"clientOpts,omitempty"`
	AuthStrategy  *ffiAuthStrategy `json:"authStrategy,omitempty"`
	EqlVersion    int              `json:"eqlVersion"`
}

// NewClient creates a new encryption client configured with the given options.
// The ctx parameter is checked for cancellation before the FFI call.
func NewClient(ctx context.Context, opts ...ClientOption) (*Client, error) {
	const op = "NewClient"

	cfg := &clientConfig{}
	for _, opt := range opts {
		opt(cfg)
	}

	// Resolve the authentication strategy. WithOIDCFederation and
	// WithTokenProvider are mutually exclusive.
	if cfg.oidcGetToken != nil && cfg.tokenProviderGetToken != nil {
		return nil, &Error{
			Op:      op,
			Err:     ErrAuthStrategy,
			Message: "encryption: NewClient: WithOIDCFederation and WithTokenProvider are mutually exclusive",
		}
	}

	ffiOpts := ffiNewClientOptions{
		EncryptConfig: buildEncryptConfigFromSchemas(cfg.schemas),
		ClientOpts:    buildClientOpts(cfg),
		EqlVersion:    resolveEqlVersion(cfg.encryptedFormat),
	}

	var getToken func(ctx context.Context) (string, error)
	switch {
	case cfg.oidcGetToken != nil:
		// OIDC federation requires a workspace CRN, from WithCredentials or
		// the CS_WORKSPACE_CRN environment variable. Validate before the FFI
		// call so the caller gets a clear, native-independent error.
		crn := cfg.workspaceCRN
		if crn == "" {
			crn = os.Getenv("CS_WORKSPACE_CRN")
		}
		if crn == "" {
			return nil, &Error{
				Op:      op,
				Err:     ErrAuthStrategy,
				Message: "encryption: NewClient: WithOIDCFederation requires a workspace CRN: set it via WithCredentials or the CS_WORKSPACE_CRN environment variable (workspaceCrn is required)",
			}
		}
		if ffiOpts.ClientOpts == nil {
			ffiOpts.ClientOpts = &ffiClientOpts{}
		}
		if ffiOpts.ClientOpts.WorkspaceCrn == nil {
			ffiOpts.ClientOpts.WorkspaceCrn = &crn
		}
		ffiOpts.AuthStrategy = &ffiAuthStrategy{Type: "oidcFederation"}
		getToken = cfg.oidcGetToken
	case cfg.tokenProviderGetToken != nil:
		ffiOpts.AuthStrategy = &ffiAuthStrategy{Type: "tokenProvider"}
		getToken = cfg.tokenProviderGetToken
	}

	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("encryption: %s: %w", op, err)
	}

	optionsJSON, err := json.Marshal(ffiOpts)
	if err != nil {
		return nil, fmt.Errorf("encryption: %s: marshaling options: %w", op, err)
	}

	cOptionsJSON := C.CString(string(optionsJSON))
	defer C.free(unsafe.Pointer(cOptionsJSON))

	// When an auth strategy callback is configured, register the provider with
	// a cgo.Handle and pass the exported Go callback to the native layer.
	if getToken != nil {
		handle := cgo.NewHandle(&tokenProvider{getToken: getToken})
		result := C.protectNewClientWithToken(cOptionsJSON, C.uint64_t(handle))
		if !result.success {
			handle.Delete()
			errorStr := C.GoString(result.error)
			C.protect_free_string(result.error)
			return nil, newError(op, errorStr)
		}
		return &Client{
			ptr:         unsafe.Pointer(result.data),
			tokenHandle: handle,
			hasToken:    true,
		}, nil
	}

	result := C.protectNewClientNoToken(cOptionsJSON)
	if !result.success {
		errorStr := C.GoString(result.error)
		C.protect_free_string(result.error)
		return nil, newError(op, errorStr)
	}

	return &Client{ptr: unsafe.Pointer(result.data)}, nil
}

// resolveEqlVersion maps an EncryptedFormat to its wire version, defaulting to
// EncryptedFormatV2 when unset.
func resolveEqlVersion(f EncryptedFormat) int {
	if f == 0 {
		return int(EncryptedFormatV2)
	}
	return int(f)
}

// fillEnvCredentials populates credential fields that were not set via
// WithCredentials from the standard environment variables. The native layer
// resolves workspace and access-key auth from the environment on its own, but
// the client key pair must be supplied by the SDK: CS_CLIENT_ID and
// CS_CLIENT_KEY are only used together — a lone half of the pair is ignored.
func fillEnvCredentials(cfg *clientConfig) {
	if cfg.clientID == "" && cfg.clientKey == "" {
		id, key := os.Getenv("CS_CLIENT_ID"), os.Getenv("CS_CLIENT_KEY")
		if id != "" && key != "" {
			cfg.clientID = id
			cfg.clientKey = key
		}
	}
	if cfg.workspaceCRN == "" {
		cfg.workspaceCRN = os.Getenv("CS_WORKSPACE_CRN")
	}
	if cfg.accessKey == "" {
		cfg.accessKey = os.Getenv("CS_ACCESS_KEY")
		if cfg.accessKey == "" {
			cfg.accessKey = os.Getenv("CS_CLIENT_ACCESS_KEY")
		}
	}
}

// buildClientOpts assembles the optional clientOpts object, or returns nil when
// no credential fields are configured.
func buildClientOpts(cfg *clientConfig) *ffiClientOpts {
	fillEnvCredentials(cfg)
	if cfg.workspaceCRN == "" && cfg.accessKey == "" && cfg.clientID == "" &&
		cfg.clientKey == "" && cfg.keysetName == "" && cfg.keysetID == "" {
		return nil
	}
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
	return co
}

func buildEncryptConfigFromSchemas(schemas []*TableDef) EncryptConfig {
	tbls := make(Tables, len(schemas))
	for _, td := range schemas {
		tbl := make(Table, len(td.columns))
		for colName, col := range td.columns {
			tbl[colName] = canonicalizeColumn(col)
		}
		tbls[td.name] = tbl
	}
	return EncryptConfig{
		Version: 1,
		Tables:  tbls,
	}
}

// canonicalizeColumn returns a copy of col ready for the wire: cast_as is
// normalized to its canonical name, and an unset ste_vec array_index_mode is
// defaulted to "none" (the native library default differs). The input column
// stored in the schema is left unmodified.
func canonicalizeColumn(col Column) Column {
	out := col
	if col.CastAs != nil {
		norm := normalizeCastAs(*col.CastAs)
		out.CastAs = &norm
	}
	if col.Indexes != nil && col.Indexes.SteVecIndex != nil &&
		col.Indexes.SteVecIndex.ArrayIndexMode == nil {
		// Copy the indexes and ste_vec opts so we can inject the default
		// without mutating the stored schema.
		idx := *col.Indexes
		sv := *col.Indexes.SteVecIndex
		none := "none"
		sv.ArrayIndexMode = &none
		idx.SteVecIndex = &sv
		out.Indexes = &idx
	}
	return out
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
		return nil, fmt.Errorf("encryption: %s: %w", op, err)
	}

	co := buildCallOpts(opts)

	type ffiEncryptOptions struct {
		Plaintext         any          `json:"plaintext"`
		Column            string       `json:"column"`
		Table             string       `json:"table"`
		LockContext       *LockContext `json:"lockContext,omitempty"`
		UnverifiedContext any          `json:"unverifiedContext,omitempty"`
	}

	ffiOpts := ffiEncryptOptions{
		Plaintext:         normalizePlaintext(plaintext),
		Column:            col.column,
		Table:             col.table,
		LockContext:       co.lockContext,
		UnverifiedContext: co.unverifiedContext,
	}

	optionsJSON, err := json.Marshal(ffiOpts)
	if err != nil {
		return nil, fmt.Errorf("encryption: %s: marshaling options: %w", op, err)
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
		return nil, fmt.Errorf("encryption: %s: unmarshaling result: %w", op, err)
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
		return nil, fmt.Errorf("encryption: %s: %w", op, err)
	}

	co := buildCallOpts(opts)

	type ffiDecryptOptions struct {
		Ciphertext        *Encrypted   `json:"ciphertext"`
		LockContext       *LockContext `json:"lockContext,omitempty"`
		UnverifiedContext any          `json:"unverifiedContext,omitempty"`
	}

	ffiOpts := ffiDecryptOptions{
		Ciphertext:        encrypted,
		LockContext:       co.lockContext,
		UnverifiedContext: co.unverifiedContext,
	}

	optionsJSON, err := json.Marshal(ffiOpts)
	if err != nil {
		return nil, fmt.Errorf("encryption: %s: marshaling options: %w", op, err)
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
	if err := decodeFFIJSON([]byte(plaintextJSON), &plaintext); err != nil {
		return nil, fmt.Errorf("encryption: %s: unmarshaling result: %w", op, err)
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
		return nil, fmt.Errorf("encryption: %s: %w", op, err)
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
		UnverifiedContext any                   `json:"unverifiedContext,omitempty"`
	}

	payloads := make([]ffiPlaintextPayload, len(items))
	for i, item := range items {
		lc := item.LockContext
		if lc == nil {
			lc = co.lockContext
		}
		payloads[i] = ffiPlaintextPayload{
			Plaintext:   normalizePlaintext(item.Plaintext),
			Column:      item.Column.column,
			Table:       item.Column.table,
			LockContext: lc,
		}
	}

	ffiOpts := ffiBulkOptions{
		Plaintexts:        payloads,
		UnverifiedContext: co.unverifiedContext,
	}

	optionsJSON, err := json.Marshal(ffiOpts)
	if err != nil {
		return nil, fmt.Errorf("encryption: %s: marshaling options: %w", op, err)
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
		return nil, fmt.Errorf("encryption: %s: unmarshaling result: %w", op, err)
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
		return nil, fmt.Errorf("encryption: %s: %w", op, err)
	}

	co := buildCallOpts(opts)

	type ffiBulkDecryptPayload struct {
		Ciphertext  *Encrypted   `json:"ciphertext"`
		LockContext *LockContext `json:"lockContext,omitempty"`
	}
	type ffiBulkDecryptOptions struct {
		Ciphertexts       []ffiBulkDecryptPayload `json:"ciphertexts"`
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
		UnverifiedContext: co.unverifiedContext,
	}

	optionsJSON, err := json.Marshal(ffiOpts)
	if err != nil {
		return nil, fmt.Errorf("encryption: %s: marshaling options: %w", op, err)
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
	if err := decodeFFIJSON([]byte(plaintextJSON), &plaintexts); err != nil {
		return nil, fmt.Errorf("encryption: %s: unmarshaling result: %w", op, err)
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
		return nil, fmt.Errorf("encryption: %s: %w", op, err)
	}

	co := buildCallOpts(opts)

	type ffiBulkDecryptPayload struct {
		Ciphertext  *Encrypted   `json:"ciphertext"`
		LockContext *LockContext `json:"lockContext,omitempty"`
	}
	type ffiBulkDecryptOptions struct {
		Ciphertexts       []ffiBulkDecryptPayload `json:"ciphertexts"`
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
		UnverifiedContext: co.unverifiedContext,
	}

	optionsJSON, err := json.Marshal(ffiOpts)
	if err != nil {
		return nil, fmt.Errorf("encryption: %s: marshaling options: %w", op, err)
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
	if err := decodeFFIJSON([]byte(resultsJSON), &ffiResults); err != nil {
		return nil, fmt.Errorf("encryption: %s: unmarshaling result: %w", op, err)
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

// EncryptQuery encrypts a value for searching against an encrypted column and
// returns an opaque [QueryTerm] to bind into a SQL statement.
//
// The queryType determines which index is used for the search: [Equality] for
// exact-match, [FreeTextSearch] for full-text search, [OrderAndRange] for range
// and ordering comparisons, and the JSON query types for path and containment
// queries. The returned term should be treated as opaque; see [QueryTerm].
func (c *Client) EncryptQuery(ctx context.Context, col ColumnRef, queryType QueryType, plaintext any, opts ...Option) (*QueryTerm, error) {
	const op = "EncryptQuery"

	ptr, unlock, err := c.acquirePtr(op)
	if err != nil {
		return nil, err
	}
	defer unlock()

	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("encryption: %s: %w", op, err)
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
		UnverifiedContext any          `json:"unverifiedContext,omitempty"`
	}

	ffiOpts := ffiEncryptQueryOptions{
		Plaintext:         normalizePlaintext(plaintext),
		Column:            col.column,
		Table:             col.table,
		IndexType:         indexType,
		QueryOp:           queryOp,
		LockContext:       co.lockContext,
		UnverifiedContext: co.unverifiedContext,
	}

	optionsJSON, err := json.Marshal(ffiOpts)
	if err != nil {
		return nil, fmt.Errorf("encryption: %s: marshaling options: %w", op, err)
	}

	cOptionsJSON := C.CString(string(optionsJSON))
	defer C.free(unsafe.Pointer(cOptionsJSON))

	result := C.protect_encrypt_query((*C.struct_Client)(ptr), cOptionsJSON)
	if !result.success {
		errorStr := C.GoString(result.error)
		C.protect_free_string(result.error)
		return nil, newError(op, errorStr)
	}

	termJSON := C.GoString(result.data)
	C.protect_free_string(result.data)

	return &QueryTerm{raw: json.RawMessage(termJSON)}, nil
}

// ---------------------------------------------------------------------------
// EncryptQueryBulk
// ---------------------------------------------------------------------------

// EncryptQueryBulk encrypts multiple query values in a single operation. Each
// result is an opaque [QueryTerm] positioned to match its input query.
func (c *Client) EncryptQueryBulk(ctx context.Context, queries []QueryItem, opts ...Option) ([]*QueryTerm, error) {
	const op = "EncryptQueryBulk"

	ptr, unlock, err := c.acquirePtr(op)
	if err != nil {
		return nil, err
	}
	defer unlock()

	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("encryption: %s: %w", op, err)
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
			Plaintext:   normalizePlaintext(q.Plaintext),
			Column:      q.Column.column,
			Table:       q.Column.table,
			IndexType:   indexType,
			QueryOp:     queryOp,
			LockContext: lc,
		}
	}

	ffiOpts := ffiBulkQueryOptions{
		Queries:           payloads,
		UnverifiedContext: co.unverifiedContext,
	}

	optionsJSON, err := json.Marshal(ffiOpts)
	if err != nil {
		return nil, fmt.Errorf("encryption: %s: marshaling options: %w", op, err)
	}

	cOptionsJSON := C.CString(string(optionsJSON))
	defer C.free(unsafe.Pointer(cOptionsJSON))

	result := C.protect_encrypt_query_bulk((*C.struct_Client)(ptr), cOptionsJSON)
	if !result.success {
		errorStr := C.GoString(result.error)
		C.protect_free_string(result.error)
		return nil, newError(op, errorStr)
	}

	termsJSON := C.GoString(result.data)
	C.protect_free_string(result.data)

	var raw []json.RawMessage
	if err := json.Unmarshal([]byte(termsJSON), &raw); err != nil {
		return nil, fmt.Errorf("encryption: %s: unmarshaling result: %w", op, err)
	}

	terms := make([]*QueryTerm, len(raw))
	for i := range raw {
		terms[i] = &QueryTerm{raw: raw[i]}
	}
	return terms, nil
}

// ---------------------------------------------------------------------------
// IsEncrypted
// ---------------------------------------------------------------------------

// IsEncrypted reports whether a value is a valid encrypted payload.
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

// normalizePlaintext converts Go values that need explicit wire formatting
// before encryption. time.Time values are formatted as RFC 3339 strings so the
// native layer can parse them for date and timestamp columns. A nil *time.Time
// becomes a JSON null. All other values pass through unchanged.
func normalizePlaintext(v any) any {
	switch t := v.(type) {
	case time.Time:
		return t.Format(time.RFC3339Nano)
	case *time.Time:
		if t == nil {
			return nil
		}
		return t.Format(time.RFC3339Nano)
	default:
		return v
	}
}

// decodeFFIJSON decodes an FFI JSON response into v using json.Number for
// numeric values, so integers beyond 2^53 survive without precision loss.
func decodeFFIJSON(data []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	return dec.Decode(v)
}

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
