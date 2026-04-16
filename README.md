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
    <a href="https://github.com/cipherstash/protectgo/blob/main/LICENSE.md">
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

## Quick start

```go
package main

import (
    "context"
    "log"

    "github.com/cipherstash/protectgo/pkg/protect"
)

// Define your model. The `cs` tag marks fields for encryption.
type User struct {
    ID    int    `json:"id"`
    Email string `json:"email" cs:"email,unique(downcase),match"`
    Name  string `json:"name"  cs:"name,match"`
    Age   int    `json:"age"   cs:"age,cast=number,ore"`
    Role  string `json:"role"`
}

func main() {
    ctx := context.Background()

    // Build schema from struct tags
    users, _ := protect.TableSchema("users", User{})

    // Create client — credentials from env vars or config files
    client, err := protect.NewClient(ctx, protect.WithSchemas(users))
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
    client.DecryptModel(ctx, users, encrypted, &decrypted)
    log.Printf("%s <%s>", decrypted.Name, decrypted.Email)
}
```

## Installing

```bash
go get github.com/cipherstash/protectgo/pkg/protect
```

### CipherStash CLI

```bash
# macOS
brew install cipherstash/tap/stash

# Then set up credentials
stash setup
```

This creates `cipherstash.toml` and `cipherstash.secret.toml` in your project.

> [!WARNING]  
> Don't commit `cipherstash.secret.toml` to git.

You can also use environment variables:

| Variable | Description |
|---|---|
| `CS_WORKSPACE_CRN` | Workspace CRN |
| `CS_CLIENT_ACCESS_KEY` | Access key |
| `CS_CLIENT_ID` | Client ID |
| `CS_CLIENT_KEY` | Client key |

## Defining your schema

### Struct tags

The `cs` tag defines the encryption schema directly on your Go structs:

```go
type User struct {
    ID       int    `json:"id"`                                          // not encrypted
    Email    string `json:"email" cs:"email,unique(downcase),match"`     // exact match + full-text
    Name     string `json:"name"  cs:"name,match"`                      // full-text search
    Age      int    `json:"age"   cs:"age,cast=number,ore"`             // range queries
    Metadata any    `json:"metadata" cs:"metadata,ste_vec(prefix=u/m)"` // JSON queries
    Role     string `json:"role"`                                        // not encrypted
}

users, err := protect.TableSchema("users", User{})
```

#### Index directives

| Directive | Description |
|---|---|
| `unique` | Exact match queries (`WHERE email = ?`) |
| `unique(downcase)` | Case-insensitive exact match |
| `match` | Full-text search (ngram tokenizer, k=6, m=2048) |
| `match(tokenizer=standard)` | Full-text with word-boundary tokenizer |
| `ore` | Range queries (`<`, `>`, `BETWEEN`, `ORDER BY`) |
| `ste_vec(prefix=t/c)` | JSON path and containment queries |

#### Type inference

Cast type is inferred from the Go field type. Override with `cast=<type>`:

| Go type | Inferred cast | Override example |
|---|---|---|
| `string` | `string` | `cast=text` |
| `int`, `float64` | `number` | `cast=bigint` |
| `bool` | `boolean` | |
| `map`, `any`, `[]T` | `json` | |

### Programmatic builder

For complex schemas or when you prefer type safety over struct tags:

```go
users := protect.NewSchema("users").
    Column("email", protect.CastAsString).Equality().FreeTextSearch().Done().
    Column("name", protect.CastAsString).FreeTextSearch().Done().
    Column("age", protect.CastAsNumber).OrderAndRange().Done().
    Column("profile", protect.CastAsJson).SearchableJSON("users/profile").Done().
    Build()
```

### Multiple tables

```go
client, err := protect.NewClient(ctx,
    protect.WithSchemas(users, orders, products),
)
```

## Creating a client

```go
// Minimal — credentials from env vars or config files
client, err := protect.NewClient(ctx, protect.WithSchemas(users))

// Explicit credentials
client, err := protect.NewClient(ctx,
    protect.WithSchemas(users),
    protect.WithCredentials(crn, accessKey, clientID, clientKey),
)

// Multi-tenant keyset isolation
client, err := protect.NewClient(ctx,
    protect.WithSchemas(users),
    protect.WithKeyset("tenant-a"),
)

defer client.Close()
```

## Encrypting and decrypting

### Models

The fastest way to encrypt data. Fields with a `cs` tag are encrypted; everything else passes through.

```go
user := User{ID: 1, Email: "alice@example.com", Name: "Alice", Age: 28, Role: "admin"}

// Encrypt — returns map with *Encrypted values for tagged fields
encrypted, err := client.EncryptModel(ctx, users, user)

// Decrypt — populates struct from encrypted map
var decrypted User
err = client.DecryptModel(ctx, users, encrypted, &decrypted)
```

### Bulk models

Single KMS call for all fields across all models:

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
items := []protect.PlaintextItem{
    {Column: users.Column("email"), Plaintext: "alice@example.com"},
    {Column: users.Column("email"), Plaintext: "bob@example.com"},
}
encrypted, err := client.EncryptBulk(ctx, items)
```

### With options

```go
lc := &protect.LockContext{IdentityClaim: []string{"user:123"}}

encrypted, err := client.Encrypt(ctx, users.Column("email"), "alice@example.com",
    protect.WithLockContext(lc),
)

plaintext, err := client.Decrypt(ctx, encrypted,
    protect.WithLockContext(lc),
)
```

> [!CAUTION]  
> Data encrypted with a lock context can only be decrypted with the same context.

## Querying encrypted data

Encrypt search terms to query encrypted columns without exposing plaintext:

```go
// Exact match
query, _ := client.EncryptQuery(ctx, users.Column("email"), protect.Equality, "alice@example.com")
// Use query.UniqueIndex in SQL

// Full-text search
query, _ := client.EncryptQuery(ctx, users.Column("name"), protect.FreeTextSearch, "alice")
// Use query.MatchIndex in SQL

// Range comparison
query, _ := client.EncryptQuery(ctx, users.Column("age"), protect.OrderAndRange, 25)
// Use query.OreIndex in SQL

// JSON containment
query, _ := client.EncryptQuery(ctx, users.Column("metadata"), protect.JSONContains, map[string]any{"role": "admin"})

// Bulk queries
queries, _ := client.EncryptQueryBulk(ctx, []protect.QueryItem{
    {Column: users.Column("email"), QueryType: protect.Equality, Plaintext: "alice@example.com"},
    {Column: users.Column("name"), QueryType: protect.FreeTextSearch, Plaintext: "bob"},
})
```

| Query Type | Use Case |
|---|---|
| `protect.Equality` | Exact match (`=`) |
| `protect.FreeTextSearch` | Substring/fuzzy search |
| `protect.OrderAndRange` | Range comparisons, sorting |
| `protect.JSONSelector` | JSON path queries (`$.field`) |
| `protect.JSONContains` | JSON containment (`@>`) |

## Error handling

All errors support `errors.Is()` for programmatic handling:

```go
_, err := client.Encrypt(ctx, users.Column("email"), "value")

if errors.Is(err, protect.ErrUnknownColumn) {
    // column not in schema
}
if errors.Is(err, protect.ErrMissingIndex) {
    // index not configured for this query type
}
if errors.Is(err, protect.ErrClientClosed) {
    // client was already closed
}
```

| Sentinel | Description |
|---|---|
| `ErrUnknownColumn` | Column not found in encryption schema |
| `ErrMissingIndex` | Required index not configured |
| `ErrInvalidQueryInput` | Wrong value type for query operation |
| `ErrInvalidJSONPath` | Invalid JSON path for selector query |
| `ErrClientClosed` | Client has been closed |

## API reference

### Schema

```go
func TableSchema(tableName string, model any) (*TableDef, error)
func NewSchema(tableName string) *SchemaBuilder
func (td *TableDef) Column(name string) ColumnRef
func (td *TableDef) Name() string
```

### Client

```go
func NewClient(ctx context.Context, opts ...ClientOption) (*Client, error)
func (c *Client) Close() error

// Options
func WithSchemas(schemas ...*TableDef) ClientOption
func WithCredentials(workspaceCRN, accessKey, clientID, clientKey string) ClientOption
func WithKeyset(name string) ClientOption
```

### Operations

```go
func (c *Client) Encrypt(ctx, col, plaintext, ...Option) (*Encrypted, error)
func (c *Client) Decrypt(ctx, encrypted, ...Option) (any, error)
func (c *Client) EncryptBulk(ctx, items, ...Option) ([]Encrypted, error)
func (c *Client) DecryptBulk(ctx, items, ...Option) ([]any, error)
func (c *Client) DecryptBulkFallible(ctx, items, ...Option) ([]DecryptResult, error)
func (c *Client) EncryptQuery(ctx, col, queryType, plaintext, ...Option) (*Encrypted, error)
func (c *Client) EncryptQueryBulk(ctx, queries, ...Option) ([]Encrypted, error)

// Options
func WithLockContext(lc *LockContext) Option
func WithServiceToken(token string) Option
func WithAuditContext(ctx any) Option
```

### Models

```go
func (c *Client) EncryptModel(ctx, schema, model) (map[string]any, error)
func (c *Client) DecryptModel(ctx, schema, data, dest) error
func (c *Client) BulkEncryptModels(ctx, schema, models) ([]map[string]any, error)
func (c *Client) BulkDecryptModels(ctx, schema, data, dest) error
```

### Utilities

```go
func IsEncrypted(value any) bool
```

## PostgreSQL setup

Searchable encryption requires the EQL extension:

```bash
curl -sLo cipherstash-encrypt.sql \
  https://github.com/cipherstash/encrypt-query-language/releases/latest/download/cipherstash-encrypt.sql
psql -f cipherstash-encrypt.sql
```

```sql
CREATE TABLE users (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    email eql_v2_encrypted
);
```

## Prebuilt libraries

The SDK ships with precompiled static libraries for all supported platforms. No Rust toolchain required.

| Platform | Library |
|---|---|
| macOS ARM64 | `libprotect_ffi_darwin_arm64.a` |
| macOS Intel | `libprotect_ffi_darwin_x64.a` |
| Linux ARM64 | `libprotect_ffi_linux_arm64.a` |
| Linux x64 | `libprotect_ffi_linux_x64.a` |
| Linux ARM64 (musl) | `libprotect_ffi_linux_arm64_musl.a` |
| Linux x64 (musl) | `libprotect_ffi_linux_x64_musl.a` |

## Running the examples

```bash
go run examples/basic_usage.go

# Alpine Linux / musl
go run -tags=musl examples/basic_usage.go
```

---

[Missing something?](https://github.com/cipherstash/protectgo/issues/new?template=docs-feedback.yml&title=[Docs:]%20Feedback%20on%20README.md)
