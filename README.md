<h1 align="center">
  <img alt="CipherStash Logo" loading="lazy" width="128" height="128" decoding="async" data-nimg="1"   style="color:transparent" src="https://cipherstash.com/assets/cs-github.png">
  </br>
  CipherStash Go Encryption SDK
</h1>
<p align="center">
  Implement robust data security without sacrificing performance or usability
  <br/>
  <div align="center" style="display: flex; justify-content: center; gap: 1rem;">
    <a href="https://cipherstash.com">
      <img
        src="https://raw.githubusercontent.com/cipherstash/meta/refs/heads/main/csbadge.svg"
        alt="Built by CipherStash"
      />
    </a>
    <a href="https://github.com/cipherstash/goencryption/blob/main/LICENSE.md">
      <img
        alt="License"
        src="https://img.shields.io/npm/l/@cipherstash/protect.svg?style=for-the-badge&labelColor=000000"
      />
    </a>
  </div>
</p>
<br/>

<!-- start -->

> [!WARNING]
> This is a work in progress.
> The package is not yet available on pkg.go.dev.

The CipherStash Go Encryption SDK encrypts, decrypts, and searches encrypted data. Every value you encrypt has a unique key, made possible by CipherStash [ZeroKMS](https://cipherstash.com/products/zerokms)'s bulk key operations, backed by a root key in [AWS KMS](https://docs.aws.amazon.com/kms/latest/developerguide/overview.html). The encrypted data is stored as a JSON payload in any database that supports JSONB.

> [!IMPORTANT]
> Searching, sorting, and filtering on encrypted data requires PostgreSQL.

## Contents

- [Quick start](#quick-start)
- [Installing](#installing)
- [Credentials and authentication](#credentials-and-authentication)
- [Defining your schema](#defining-your-schema)
- [Creating a client](#creating-a-client)
- [Encrypting and decrypting](#encrypting-and-decrypting)
- [Querying encrypted data](#querying-encrypted-data)
- [Identity-aware encryption](#identity-aware-encryption)
- [PostgreSQL setup](#postgresql-setup)
- [Error handling](#error-handling)
- [API reference](#api-reference)
- [Prebuilt libraries](#prebuilt-libraries)

## Quick start

```go
package main

import (
    "context"
    "log"

    "github.com/cipherstash/goencryption/pkg/encryption"
)

// Define your model. The `cs` tag marks fields for encryption.
type User struct {
    ID    int    `json:"id"`
    Email string `json:"email" cs:"email,unique(downcase),match"`
    Name  string `json:"name"  cs:"name,match"`
    Age   int    `json:"age"   cs:"age,ore"`
    Role  string `json:"role"`
}

func main() {
    ctx := context.Background()

    // Build schema from struct tags
    users, err := encryption.TableSchema("users", User{})
    if err != nil {
        log.Fatal(err)
    }

    // Create client — credentials from env vars or config files
    client, err := encryption.NewClient(ctx, encryption.WithSchemas(users))
    if err != nil {
        log.Fatal(err)
    }
    defer client.Close()

    // Encrypt a model
    user := User{ID: 1, Email: "john@example.com", Name: "John", Age: 30, Role: "admin"}
    encrypted, err := client.EncryptModel(ctx, users, user)
    if err != nil {
        log.Fatal(err)
    }

    // Decrypt back to struct
    var decrypted User
    if err := client.DecryptModel(ctx, users, encrypted, &decrypted); err != nil {
        log.Fatal(err)
    }
    log.Printf("%s <%s>", decrypted.Name, decrypted.Email)
}
```

## Installing

```bash
go get github.com/cipherstash/goencryption/pkg/encryption
```

The SDK links a precompiled native library via cgo — no Rust toolchain is
required, but `CGO_ENABLED=1` (the default) and a C toolchain are. See
[Prebuilt libraries](#prebuilt-libraries) for the supported platforms.

## Credentials and authentication

### Setting up credentials

```bash
# macOS
brew install cipherstash/tap/stash

# Then set up credentials
stash setup
```

This creates `cipherstash.toml` and `cipherstash.secret.toml` in your project.

> [!WARNING]
> Don't commit `cipherstash.secret.toml` to git.

You can also use environment variables (see `.env.example`):

| Variable | Description |
|---|---|
| `CS_WORKSPACE_CRN` | Workspace CRN, e.g. `crn:ap-southeast-2.aws:WORKSPACEID` |
| `CS_CLIENT_ACCESS_KEY` | Access key (`CS_ACCESS_KEY` is also accepted) |
| `CS_CLIENT_ID` | Client ID (used only when `CS_CLIENT_KEY` is also set) |
| `CS_CLIENT_KEY` | Client key |

Or pass everything explicitly:

```go
client, err := encryption.NewClient(ctx,
    encryption.WithSchemas(users),
    encryption.WithCredentials(workspaceCRN, accessKey, clientID, clientKey),
)
```

Two independent things are being configured here:

- **Authentication** — how the client proves who it is to CipherStash. By
  default this is the access key; alternatively use
  [OIDC federation](#per-user-identity-with-oidc-federation) or a custom
  token provider.
- **Key material** — the client ID and client key pair. This is **always
  required** to encrypt and decrypt values, regardless of which
  authentication strategy you use.

### Per-user identity with OIDC federation

`WithOIDCFederation` makes every encryption and decryption identity-aware at
the client level — no per-operation configuration required. Supply a function
that returns a fresh OIDC access token (a JWT) from your application's
identity provider (Clerk, Auth0, Supabase, and similar). The client exchanges
that token for a short-lived CipherStash service token, verifies it belongs to
your workspace, and caches it until expiry — your function is called again
only when re-federation is needed.

```go
client, err := encryption.NewClient(ctx,
    encryption.WithSchemas(users),
    encryption.WithCredentials(crn, "", clientID, clientKey), // no access key needed
    encryption.WithOIDCFederation(func(ctx context.Context) (string, error) {
        return identityProvider.AccessToken(ctx) // your app's IdP JWT
    }),
)
```

A workspace CRN is required — supply it via `WithCredentials` or
`CS_WORKSPACE_CRN`. `NewClient` returns an error wrapping `ErrAuthStrategy` if
neither is present.

Because federation happens per client, the natural pattern for per-user
isolation is one client per user session (or per request), each federating
that user's JWT. Key operations are then attributed to that user in
CipherStash audit logs and governed by that user's policy.

### Custom token provider

For advanced setups, `WithTokenProvider` supplies a CipherStash service token
directly. Your function is called on every keyservice request — caching and
refresh are your responsibility:

```go
client, err := encryption.NewClient(ctx,
    encryption.WithSchemas(users),
    encryption.WithTokenProvider(func(ctx context.Context) (string, error) {
        return myTokenCache.Current(ctx)
    }),
)
```

`WithOIDCFederation` and `WithTokenProvider` are mutually exclusive.

## Defining your schema

### Struct tags

The `cs` tag defines the encryption schema directly on your Go structs. The
first tag element is the column name; the rest are directives:

```go
type User struct {
    ID       int       `json:"id"`                                          // not encrypted
    Email    string    `json:"email" cs:"email,unique(downcase),match"`     // exact match + full-text
    Name     string    `json:"name"  cs:"name,match"`                       // full-text search
    Age      int       `json:"age"   cs:"age,ore"`                          // range queries
    Salary   float64   `json:"salary" cs:"salary,cast=decimal"`             // exact decimal storage
    Started  time.Time `json:"started" cs:"started,ore"`                    // sortable timestamp
    Metadata any       `json:"metadata" cs:"metadata,ste_vec(prefix=users/metadata)"` // JSON queries
    Role     string    `json:"role"`                                        // not encrypted
}

users, err := encryption.TableSchema("users", User{})
```

#### Index directives

| Directive | Enables |
|---|---|
| `unique` | Exact-match queries (`encryption.Equality`) |
| `unique(downcase)` | Case-insensitive exact match |
| `match` | Full-text search (`encryption.FreeTextSearch`) — ngram tokenizer, token length 3, k=6, m=2048 by default |
| `match(k=8,m=1024,tokenizer=standard,token_length=3,include_original=true)` | Full-text search with tuned parameters |
| `ore` | Range queries and sorting (`encryption.OrderAndRange`) |
| `ste_vec(prefix=table/column)` | JSON path and containment queries (`encryption.JSONSelector`, `encryption.JSONContains`) — forces the column to `json` |

#### Type inference

The storage type is inferred from the Go field type. Override with
`cast=<type>`:

| Go type | Inferred type | Common overrides |
|---|---|---|
| `string` | `text` | `cast=date`, `cast=timestamp`, `cast=json` |
| signed/unsigned ints | `big_int` | `cast=int`, `cast=small_int` |
| `float32`, `float64` | `float` | `cast=decimal` (exact, no float rounding) |
| `bool` | `boolean` | |
| `time.Time` | `timestamp` | `cast=date` |
| `map`, `any`, slices | `json` | |

The full set of types is `text`, `big_int`, `int`, `small_int`, `float`,
`decimal`, `boolean`, `date`, `timestamp`, and `json` (constants
`encryption.CastAsText` … `encryption.CastAsJSON`). The legacy names `string`
(→ `text`) and `number` (→ `float`) are still accepted and normalized
automatically.

### Programmatic builder

For dynamic schemas or when you prefer builders over tags:

```go
users := encryption.NewSchema("users").
    Column("email", encryption.CastAsText).Equality(encryption.TokenFilter{Kind: "downcase"}).FreeTextSearch().Done().
    Column("name", encryption.CastAsText).FreeTextSearch(encryption.WithK(8), encryption.WithM(1024)).Done().
    Column("age", encryption.CastAsBigInt).OrderAndRange().Done().
    Column("salary", encryption.CastAsDecimal).Done().
    Column("profile", encryption.CastAsJSON).SearchableJSON("users/profile").Done().
    Build()
```

### Multiple tables

```go
client, err := encryption.NewClient(ctx,
    encryption.WithSchemas(users, orders, products),
)
```

## Creating a client

```go
// Minimal — credentials from env vars or config files
client, err := encryption.NewClient(ctx, encryption.WithSchemas(users))

// Explicit credentials
client, err := encryption.NewClient(ctx,
    encryption.WithSchemas(users),
    encryption.WithCredentials(crn, accessKey, clientID, clientKey),
)

// Multi-tenant keyset isolation — scope this client to one tenant's keys
client, err := encryption.NewClient(ctx,
    encryption.WithSchemas(users),
    encryption.WithKeyset("tenant-a"),   // by name, or WithKeysetID("<uuid>")
)

defer client.Close()
```

`Client` is safe for concurrent use. `Close` releases the native resources;
operations on a closed client return `ErrClientClosed`.

### Ciphertext format version

The SDK can produce two on-disk payload formats. The default,
`EncryptedFormatV2`, matches databases provisioned with the v2 database
schema. Select `EncryptedFormatV3` for databases provisioned with the v3
schema (typed encrypted columns — see [PostgreSQL setup](#postgresql-setup)):

```go
client, err := encryption.NewClient(ctx,
    encryption.WithSchemas(users),
    encryption.WithEncryptedFormat(encryption.EncryptedFormatV3),
)
```

The two formats' search terms are not interchangeable — pick the format that
matches your database schema. Decryption accepts both formats regardless of
this setting, so you can read old data while writing new-format data during a
migration.

> [!NOTE]
> V3 maps each column's index configuration onto a typed database column. A
> few combinations have no v3 equivalent (for example `unique` + `match` with
> no `ore` on a text column, or `boolean` columns with any index). Rather than
> silently dropping a search capability, `NewClient` fails with
> `ErrUnsupportedFormat` and a hint about what to change.

## Encrypting and decrypting

### Models

The fastest way to encrypt data. Fields with a `cs` tag are encrypted;
everything else passes through:

```go
user := User{ID: 1, Email: "alice@example.com", Name: "Alice", Age: 28, Role: "admin"}

// Encrypt — returns a map with encrypted values for tagged fields
encrypted, err := client.EncryptModel(ctx, users, user)

// Decrypt — populates the struct from the encrypted map
var decrypted User
err = client.DecryptModel(ctx, users, encrypted, &decrypted)
```

### Bulk models

One keyservice round trip for all fields across all models — use this for
anything more than a single record:

```go
encryptedModels, err := client.BulkEncryptModels(ctx, users, userSlice)

var decryptedUsers []User
err = client.BulkDecryptModels(ctx, users, encryptedModels, &decryptedUsers)
```

### Single values

Column references come from the schema — no string arguments:

```go
encrypted, err := client.Encrypt(ctx, users.Column("email"), "alice@example.com")
plaintext, err := client.Decrypt(ctx, encrypted)
```

### Bulk values

```go
items := []encryption.PlaintextItem{
    {Column: users.Column("email"), Plaintext: "alice@example.com"},
    {Column: users.Column("email"), Plaintext: "bob@example.com"},
}
encrypted, err := client.EncryptBulk(ctx, items)

plaintexts, err := client.DecryptBulk(ctx, encrypted)

// Per-item error handling instead of all-or-nothing:
results, err := client.DecryptBulkFallible(ctx, encrypted)
for _, r := range results {
    if r.Err != nil { /* this item failed */ }
}
```

### Value types

What you can pass in, and what `Decrypt` hands back, by column type:

| Column type | Accepted plaintext | `Decrypt` returns |
|---|---|---|
| `text` | `string` | `string` |
| `big_int`, `int`, `small_int` | any Go integer, or a whole `float64` | `json.Number` (exact, full `int64` range) |
| `float` | any Go number | `json.Number` |
| `decimal` | any Go number (stored exactly — `0.1` stays `0.1`) | `string` |
| `boolean` | `bool` | `bool` |
| `date` | `time.Time`, or `"YYYY-MM-DD"` / RFC 3339 `string` | `string` (`"YYYY-MM-DD"`) |
| `timestamp` | `time.Time`, or RFC 3339 `string` | `string` (RFC 3339) |
| `json` | `map[string]any`, slices, anything JSON-marshalable | `map[string]any` / `[]any` |

Integer conversions are exact-or-error: fractional, out-of-range, `NaN`, and
`Inf` values are rejected rather than truncated. `DecryptModel` and
`BulkDecryptModels` convert these raw values back into your struct's field
types (including `time.Time` and all integer widths) automatically.

## Querying encrypted data

Encrypt search terms to query encrypted columns without exposing plaintext.
`EncryptQuery` returns an opaque `*encryption.QueryTerm` — bind it directly as a
SQL parameter. Depending on the column configuration and format version, a
term may serialize as a JSON object or a bare JSON string; always treat it as
opaque.

```go
// Exact match
term, err := client.EncryptQuery(ctx, users.Column("email"), encryption.Equality, "alice@example.com")

// Full-text search
term, err = client.EncryptQuery(ctx, users.Column("name"), encryption.FreeTextSearch, "alice")

// Range comparison (works for numbers, dates, timestamps)
term, err = client.EncryptQuery(ctx, users.Column("age"), encryption.OrderAndRange, 25)

// JSON containment — does the document contain this structure?
term, err = client.EncryptQuery(ctx, users.Column("metadata"), encryption.JSONContains,
    map[string]any{"role": "admin"})

// JSON path — target one field of the document
term, err = client.EncryptQuery(ctx, users.Column("metadata"), encryption.JSONSelector, "$.role")

// Inspect the raw payload if needed
_ = term.String() // or term.Bytes()

// Bulk — one keyservice round trip for many terms
terms, err := client.EncryptQueryBulk(ctx, []encryption.QueryItem{
    {Column: users.Column("email"), QueryType: encryption.Equality, Plaintext: "alice@example.com"},
    {Column: users.Column("name"), QueryType: encryption.FreeTextSearch, Plaintext: "bob"},
})
```

| Query type | Requires directive | SQL shape |
|---|---|---|
| `encryption.Equality` | `unique` | `WHERE col = $1` |
| `encryption.FreeTextSearch` | `match` | `WHERE col LIKE $1` (v2) / `WHERE col @> $1` (v3) |
| `encryption.OrderAndRange` | `ore` | `WHERE col > $1`, `ORDER BY` |
| `encryption.JSONSelector` | `ste_vec` | `WHERE col -> $1 IS NOT NULL` |
| `encryption.JSONContains` | `ste_vec` | `WHERE col @> $1` |

See [PostgreSQL setup](#postgresql-setup) for the exact SQL, including the
casts each format version needs.

## Identity-aware encryption

The recommended way to bind data access to end users is
[OIDC federation](#per-user-identity-with-oidc-federation): authentication,
authorization, and audit attribution all follow the federated user with no
per-operation code.

### Lock context

A lock context goes further and ties **individual ciphertexts** to identity
claims — the same claims must be presented to decrypt:

```go
lc := &encryption.LockContext{IdentityClaim: []string{"sub"}}

encrypted, err := client.Encrypt(ctx, users.Column("email"), "secret",
    encryption.WithLockContext(lc))

plaintext, err := client.Decrypt(ctx, encrypted,
    encryption.WithLockContext(lc))
```

> [!IMPORTANT]
> Lock contexts require the client to authenticate with an identity-bearing
> token — that is, `WithOIDCFederation`. With plain access-key authentication
> the platform rejects lock-context operations as forbidden.

> [!CAUTION]
> Data encrypted with a lock context can only be decrypted with the same
> context. Losing the identity claims means losing the data.

### Audit context

Attach arbitrary application context to key operations for your CipherStash
audit logs (informational — not verified, and not part of the key
derivation):

```go
encrypted, err := client.Encrypt(ctx, users.Column("email"), "alice@example.com",
    encryption.WithAuditContext(map[string]any{"request_id": reqID, "actor": "billing-service"}),
)
```

## PostgreSQL setup

Searchable encryption requires the CipherStash encrypted-column database
extension — plain SQL, no superuser or native extension install needed. The
names below (`eql_v2_encrypted`, `eql_v3_*`, and the `eql_v3.query_*` casts)
are defined by that extension; use them exactly as shown.

### v2 schema (default, `EncryptedFormatV2`)

```bash
curl -fsSLO https://github.com/cipherstash/encrypt-query-language/releases/download/eql-2.3.1/cipherstash-encrypt.sql
psql -f cipherstash-encrypt.sql
```

Every encrypted column uses the one generic column type:

```sql
CREATE TABLE users (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    email eql_v2_encrypted,
    age   eql_v2_encrypted
);
```

Insert ciphertexts and bind query terms as `jsonb`:

```sql
INSERT INTO users (email, age) VALUES ($1::jsonb, $2::jsonb);

SELECT email::jsonb FROM users WHERE email = $1::jsonb;         -- Equality
SELECT email::jsonb FROM users WHERE email LIKE $1::jsonb;      -- FreeTextSearch
SELECT age::jsonb   FROM users WHERE age > $1::jsonb
    ORDER BY eql_v2.order_by(age) ASC;                          -- OrderAndRange
```

### v3 schema (`EncryptedFormatV3`)

```bash
curl -fsSLO https://github.com/cipherstash/encrypt-query-language/releases/download/eql-3.0.0/cipherstash-encrypt.sql
psql -f cipherstash-encrypt.sql
```

v3 replaces the generic column type with typed columns, so the database
enforces exactly which search capabilities each column carries. Pick the
column type from your schema definition:

| Go schema configuration | v3 column type |
|---|---|
| no indexes (storage only) | `eql_v3_<family>` |
| `Equality` | `eql_v3_<family>_eq` |
| `OrderAndRange` (with or without `Equality`) | `eql_v3_<family>_ord_ore` |
| `FreeTextSearch` only (text) | `eql_v3_text_match` |
| `Equality` + `FreeTextSearch` + `OrderAndRange` (text) | `eql_v3_text_search_ore` |
| `SearchableJSON` | `eql_v3_json` |

where `<family>` is `text`, `bigint`, `integer`, `smallint`, `double`,
`numeric`, `boolean`, `date`, or `timestamp`, matching the column's cast
type (`big_int` → `bigint`, `int` → `integer`, `float` → `double`,
`decimal` → `numeric`).

```sql
CREATE TABLE users (
    id       BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    email    eql_v3_text_eq,          -- unique
    age      eql_v3_bigint_ord_ore,   -- ore
    bio      eql_v3_text_search_ore,  -- unique + match + ore
    metadata eql_v3_json              -- ste_vec
);
```

Insert ciphertexts as `jsonb`; cast query terms to the matching
`eql_v3.query_<column type>` type (the column type name without the
`eql_v3_` prefix):

```sql
INSERT INTO users (email, age) VALUES ($1::jsonb, $2::jsonb);

-- Equality
SELECT email::jsonb FROM users
WHERE email = $1::jsonb::eql_v3.query_text_eq;

-- OrderAndRange
SELECT age::jsonb FROM users
WHERE age > $1::jsonb::eql_v3.query_bigint_ord_ore
ORDER BY eql_v3.ord_term_ore(age) ASC;

-- FreeTextSearch
SELECT bio::jsonb FROM users
WHERE bio @> $1::jsonb::eql_v3.query_text_search_ore;

-- JSONContains
SELECT metadata::jsonb FROM users
WHERE metadata @> $1::jsonb::eql_v3.query_jsonb;

-- JSONSelector: the term is a bare string — bind it as text
SELECT metadata -> $1::text FROM users
WHERE metadata -> $1::text IS NOT NULL;
```

Every operator also has a callable function equivalent (`eql_v3.eq(...)`,
`eql_v3.lt(...)`, …) for systems that expose the database through RPC.

## Error handling

All errors support `errors.Is()` for programmatic handling:

```go
_, err := client.EncryptQuery(ctx, users.Column("email"), encryption.OrderAndRange, "x")

switch {
case errors.Is(err, encryption.ErrMissingIndex):
    // the column has no `ore` directive
case errors.Is(err, encryption.ErrUnknownColumn):
    // column not in any registered schema
case errors.Is(err, encryption.ErrClientClosed):
    // client was already closed
}
```

| Sentinel | Meaning |
|---|---|
| `ErrUnknownColumn` | Column not found in the encryption schema |
| `ErrMissingIndex` | The query type needs an index directive the column doesn't have |
| `ErrInvalidQueryInput` | Wrong value type for the query operation |
| `ErrInvalidJSONPath` | Invalid JSON path for a selector query (paths start with `$`) |
| `ErrInvalidCiphertext` | Value is not a valid ciphertext |
| `ErrUnsupportedFormat` | The column's index configuration has no equivalent in the selected format version |
| `ErrAuthStrategy` | Authentication strategy misconfigured (e.g. OIDC federation without a workspace CRN, or combined with a token provider) |
| `ErrSteVecRequiresJSON` | A JSON-search directive on a non-`json` column |
| `ErrClientClosed` | Client has been closed |

Errors are `*encryption.Error` values carrying the failing operation
(`Encrypt`, `NewClient`, …) and the underlying cause via `Unwrap`.

## API reference

### Schema

```go
func TableSchema(tableName string, model any) (*TableDef, error)
func NewSchema(tableName string) *SchemaBuilder

func (td *TableDef) Name() string
func (td *TableDef) Column(name string) ColumnRef        // panics on unknown column
func (td *TableDef) ColumnOK(name string) (ColumnRef, bool)
```

### Client

```go
func NewClient(ctx context.Context, opts ...ClientOption) (*Client, error)
func (c *Client) Close() error

// Options
func WithSchemas(schemas ...*TableDef) ClientOption
func WithCredentials(workspaceCRN, accessKey, clientID, clientKey string) ClientOption
func WithKeyset(name string) ClientOption
func WithKeysetID(id string) ClientOption
func WithOIDCFederation(getToken func(ctx context.Context) (string, error)) ClientOption
func WithTokenProvider(getToken func(ctx context.Context) (string, error)) ClientOption
func WithEncryptedFormat(f EncryptedFormat) ClientOption   // EncryptedFormatV2 (default) | EncryptedFormatV3
```

### Operations

```go
func (c *Client) Encrypt(ctx context.Context, col ColumnRef, plaintext any, opts ...Option) (*Encrypted, error)
func (c *Client) Decrypt(ctx context.Context, e *Encrypted, opts ...Option) (any, error)
func (c *Client) EncryptBulk(ctx context.Context, items []PlaintextItem, opts ...Option) ([]Encrypted, error)
func (c *Client) DecryptBulk(ctx context.Context, items []*Encrypted, opts ...Option) ([]any, error)
func (c *Client) DecryptBulkFallible(ctx context.Context, items []*Encrypted, opts ...Option) ([]DecryptResult, error)
func (c *Client) EncryptQuery(ctx context.Context, col ColumnRef, qt QueryType, plaintext any, opts ...Option) (*QueryTerm, error)
func (c *Client) EncryptQueryBulk(ctx context.Context, queries []QueryItem, opts ...Option) ([]*QueryTerm, error)

// Per-operation options
func WithLockContext(lc *LockContext) Option
func WithAuditContext(ctx any) Option
```

### Models

```go
func (c *Client) EncryptModel(ctx context.Context, schema *TableDef, model any) (map[string]any, error)
func (c *Client) DecryptModel(ctx context.Context, schema *TableDef, data map[string]any, dest any) error
func (c *Client) BulkEncryptModels(ctx context.Context, schema *TableDef, models any) ([]map[string]any, error)
func (c *Client) BulkDecryptModels(ctx context.Context, schema *TableDef, data []map[string]any, dest any) error
```

### Utilities

```go
func IsEncrypted(value any) bool   // true for stored ciphertexts (either format); false for query terms
```

## Prebuilt libraries

The SDK ships with precompiled static libraries for all supported platforms.
No Rust toolchain required.

| Platform | Library |
|---|---|
| macOS ARM64 | `libprotect_ffi_darwin_arm64.a` |
| macOS Intel | `libprotect_ffi_darwin_x64.a` |
| Linux ARM64 | `libprotect_ffi_linux_arm64.a` |
| Linux x64 | `libprotect_ffi_linux_x64.a` |
| Linux ARM64 (musl) | `libprotect_ffi_linux_arm64_musl.a` |
| Linux x64 (musl) | `libprotect_ffi_linux_x64_musl.a` |

On Alpine Linux (musl libc), build with the `musl` tag:

```bash
go build -tags=musl ./...
```

## Running the examples

```bash
cp .env.example .env   # fill in your workspace credentials
go run ./examples

# Alpine Linux / musl
go run -tags=musl ./examples
```

See [DEVELOPMENT.md](DEVELOPMENT.md) for building the native library from
source.

---

[Missing something?](https://github.com/cipherstash/goencryption/issues/new?template=docs-feedback.yml&title=[Docs:]%20Feedback%20on%20README.md)
