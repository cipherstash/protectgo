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

The CipherStash Go Encryption SDK is a Go module for encrypting, decrypting, and searching encrypted data. Encryption operations happen directly in your app, and the ciphertext is stored in your database. Every value you encrypt has a unique key, made possible by CipherStash [ZeroKMS](https://cipherstash.com/products/zerokms)'s blazing fast bulk key operations, and backed by a root key in [AWS KMS](https://docs.aws.amazon.com/kms/latest/developerguide/overview.html). The encrypted data is structured as a JSON payload and can be stored in any database that supports JSONB.

> [!IMPORTANT]  
> Searching, sorting, and filtering on encrypted data is currently only supported when storing encrypted data in PostgreSQL.

## Table of contents

- [Features](#features)
- [Installing](#installing)
- [Getting started](#getting-started)
- [Defining your schema](#defining-your-schema)
- [Encrypting and decrypting models](#encrypting-and-decrypting-models)
- [Query encryption](#query-encryption)
- [Single value operations](#single-value-operations)
- [Bulk operations](#bulk-operations)
- [Identity-aware encryption](#identity-aware-encryption)
- [Multi-tenant keysets](#multi-tenant-keysets)
- [Error handling](#error-handling)
- [API reference](#api-reference)
- [Searchable encryption with PostgreSQL](#searchable-encryption-with-postgresql)
- [Prebuilt libraries](#prebuilt-libraries)
- [Running the examples](#running-the-examples)

## Features

- **Schema from struct tags**: Define your encryption schema directly on your Go structs using the `cs` struct tag. No manual configuration maps needed.
- **Model encryption**: Encrypt and decrypt entire structs in one call. Non-encrypted fields pass through unchanged.
- **Query encryption**: Encrypt search terms to query encrypted columns in PostgreSQL without decrypting the data first.
- **Multi-type support**: Encrypt strings, numbers, booleans, and JSON values.
- **Bulk operations**: Encrypt and decrypt thousands of records at once with a single KMS call per operation.
- **Identity-aware encryption**: Require a valid JWT identity claim to decrypt data.
- **Multi-tenant keysets**: Isolate encryption keys per tenant.
- **Searchable encryption**: Exact match, full-text search, range queries, and JSON containment on encrypted data.
- **Really fast**: [ZeroKMS](https://cipherstash.com/products/zerokms) makes millions of unique keys feasible and performant.

## Installing

### Prerequisites

- Go 1.21 or later
- A [CipherStash](https://cipherstash.com) account

### Install the package

```bash
go get github.com/cipherstash/protectgo/pkg/protect
```

### Install the CipherStash CLI

```bash
# macOS
brew install cipherstash/tap/stash

# Linux — download the binary for your platform
# ARM64: https://github.com/cipherstash/cli-releases/releases/latest/download/stash-aarch64-unknown-linux-gnu
# x86_64: https://github.com/cipherstash/cli-releases/releases/latest/download/stash-x86_64-unknown-linux-gnu
```

## Getting started

### 1. Set up credentials

```bash
stash setup
```

This creates `cipherstash.toml` (configuration) and `cipherstash.secret.toml` (credentials) in your project directory.

> [!WARNING]  
> Don't commit `cipherstash.secret.toml` to git — it contains sensitive credentials.

You can also use environment variables:

| Variable | Description |
|---|---|
| `CS_WORKSPACE_CRN` | Workspace CRN |
| `CS_CLIENT_ACCESS_KEY` | Access key |
| `CS_CLIENT_ID` | Client ID |
| `CS_CLIENT_KEY` | Client key |

### 2. Define your schema and create a client

```go
package main

import (
    "log"
    "github.com/cipherstash/protectgo/pkg/protect"
)

// Define your model with encryption using struct tags.
// Fields with a `cs` tag are encrypted. Fields without it pass through unchanged.
type User struct {
    ID    int    `json:"id"`
    Email string `json:"email" cs:"email,unique(downcase),match"`
    Name  string `json:"name"  cs:"name,match"`
    Age   int    `json:"age"   cs:"age,cast=number,ore"`
    Role  string `json:"role"` // not encrypted
}

func main() {
    // Build encryption config from your struct
    config := protect.BuildEncryptConfig(
        protect.TableSchema("users", User{}),
    )

    // Create the client
    client, err := protect.NewClient(protect.NewClientOptions{
        EncryptConfig: config,
    })
    if err != nil {
        log.Fatal(err)
    }
    defer client.Free()

    // You're ready to encrypt!
}
```

## Defining your schema

The `cs` struct tag defines the encryption schema for each field. The format is:

```
cs:"<column_name>,<directives...>"
```

### Index directives

| Directive | Description | Use case |
|---|---|---|
| `unique` | Exact match index | Equality queries (`WHERE email = ?`) |
| `unique(downcase)` | Case-insensitive exact match | Case-insensitive lookups |
| `match` | Full-text search index | Substring and fuzzy search (`LIKE`, `ILIKE`) |
| `match(tokenizer=standard)` | Full-text with standard tokenizer | Word-boundary search |
| `match(k=8,m=4096)` | Full-text with custom parameters | Tuning precision/recall |
| `ore` | Order-revealing encryption index | Range queries (`<`, `>`, `BETWEEN`, `ORDER BY`) |
| `ste_vec(prefix=table/col)` | JSON containment/path index | JSON path and `@>` queries |

### Cast type override

By default, the Go field type determines the encryption cast type:

| Go type | Inferred cast |
|---|---|
| `string` | `string` |
| `int`, `int64`, `float64`, etc. | `number` |
| `bool` | `boolean` |
| `map`, `struct`, `interface{}`, `[]T` | `json` |

Override with `cast=<type>`:

```go
Age int `json:"age" cs:"age,cast=number,ore"`
```

Available cast types: `string`, `text`, `number`, `bigint`, `boolean`, `date`, `json`

### Full example

```go
type User struct {
    // Not encrypted — no `cs` tag
    ID        int    `json:"id"`
    Role      string `json:"role"`

    // Encrypted with exact match + full-text search
    Email     string `json:"email"   cs:"email,unique(downcase),match"`

    // Encrypted with full-text search only
    Name      string `json:"name"    cs:"name,match"`

    // Encrypted with range queries (explicit number cast for int field)
    Age       int    `json:"age"     cs:"age,cast=number,ore"`

    // Encrypted, no search indexes
    Active    bool   `json:"active"  cs:"active,cast=boolean"`

    // Encrypted JSON with path and containment queries
    Metadata  any    `json:"metadata" cs:"metadata,ste_vec(prefix=users/metadata)"`
}
```

### Multiple tables

```go
config := protect.BuildEncryptConfig(
    protect.TableSchema("users", User{}),
    protect.TableSchema("orders", Order{}),
    protect.TableSchema("products", Product{}),
)
```

## Encrypting and decrypting models

The model interface encrypts and decrypts entire Go structs. Fields with a `cs` tag are encrypted; all other fields pass through unchanged.

### Encrypt a model

```go
user := User{
    ID:    1,
    Email: "alice@example.com",
    Name:  "Alice Smith",
    Age:   30,
    Role:  "admin",
}

// Returns a map with encrypted fields as *Encrypted values
// and plain fields as their original values
encrypted, err := client.EncryptModel(user, "users")
// encrypted["id"]    = 1         (plain)
// encrypted["role"]  = "admin"   (plain)
// encrypted["email"] = *Encrypted{...}
// encrypted["name"]  = *Encrypted{...}
// encrypted["age"]   = *Encrypted{...}
```

### Decrypt a model

```go
var decrypted User
err = client.DecryptModel(encrypted, "users", &decrypted)
// decrypted.Email == "alice@example.com"
// decrypted.Name  == "Alice Smith"
// decrypted.Age   == 30
// decrypted.Role  == "admin"
```

### Bulk model operations

Bulk operations collect all encrypted field values across all models and make a single KMS call, which is much faster than encrypting models one at a time.

```go
users := []User{
    {ID: 1, Email: "alice@example.com", Name: "Alice", Age: 28, Role: "admin"},
    {ID: 2, Email: "bob@example.com", Name: "Bob", Age: 35, Role: "user"},
}

// Single KMS call for all fields across all models
encryptedModels, err := client.BulkEncryptModels(users, "users")

// Decrypt back to structs
var decryptedUsers []User
err = client.BulkDecryptModels(encryptedModels, "users", &decryptedUsers)
```

## Query encryption

Encrypt search terms to query encrypted columns without exposing plaintext in your queries. Use the encrypted index values in your SQL `WHERE` clauses.

### Exact match

```go
query, err := client.EncryptQuery(protect.EncryptQueryOptions{
    Plaintext: "alice@example.com",
    Table:     "users",
    Column:    "email",
    IndexType: protect.IndexTypeUnique,
})
// Use query.UniqueIndex in: WHERE email_encrypted->>'hm' = ?
```

### Full-text search

```go
query, err := client.EncryptQuery(protect.EncryptQueryOptions{
    Plaintext: "alice",
    Table:     "users",
    Column:    "name",
    IndexType: protect.IndexTypeMatch,
})
// Use query.MatchIndex for full-text matching
```

### Range query

```go
query, err := client.EncryptQuery(protect.EncryptQueryOptions{
    Plaintext: 25,
    Table:     "users",
    Column:    "age",
    IndexType: protect.IndexTypeOre,
})
// Use query.OreIndex for: WHERE age_encrypted > ?
```

### JSON containment

```go
// Path query — find records that have a specific JSON path
query, err := client.EncryptQuery(protect.EncryptQueryOptions{
    Plaintext: "$.user.email",
    Table:     "users",
    Column:    "metadata",
    IndexType: protect.IndexTypeSteVec,
    QueryOp:   protect.QueryOpSteVecSelector,
})

// Containment query — find records matching a JSON fragment
query, err := client.EncryptQuery(protect.EncryptQueryOptions{
    Plaintext: map[string]interface{}{"role": "admin"},
    Table:     "users",
    Column:    "metadata",
    IndexType: protect.IndexTypeSteVec,
    QueryOp:   protect.QueryOpSteVecTerm,
})
```

### Bulk query encryption

```go
queries, err := client.EncryptQueryBulk(protect.EncryptQueryBulkOptions{
    Queries: []protect.QueryPayload{
        {Plaintext: "alice@example.com", Table: "users", Column: "email", IndexType: protect.IndexTypeUnique},
        {Plaintext: "bob", Table: "users", Column: "name", IndexType: protect.IndexTypeMatch},
    },
})
```

## Single value operations

For fine-grained control, encrypt and decrypt individual values directly.

### Encrypt

```go
encrypted, err := client.Encrypt(protect.EncryptOptions{
    Plaintext: "alice@example.com",  // string, number, bool, or JSON
    Table:     "users",
    Column:    "email",
})
```

### Decrypt

```go
plaintext, err := client.Decrypt(protect.DecryptOptions{
    Ciphertext: encrypted,
})
// plaintext is interface{} — the original value type is preserved
```

### Validate encrypted data

```go
protect.IsEncrypted(encrypted)       // true
protect.IsEncrypted("plain string")  // false
```

## Bulk operations

Bulk operations use a single KMS call for all values, making them much faster than individual operations.

```go
// Encrypt
bulkEncrypted, err := client.EncryptBulk(protect.EncryptBulkOptions{
    Plaintexts: []protect.PlaintextPayload{
        {Plaintext: "alice@example.com", Table: "users", Column: "email"},
        {Plaintext: "bob@example.com", Table: "users", Column: "email"},
    },
})

// Decrypt
ciphertexts := make([]protect.BulkDecryptPayload, len(bulkEncrypted))
for i := range bulkEncrypted {
    ciphertexts[i] = protect.BulkDecryptPayload{Ciphertext: &bulkEncrypted[i]}
}

plaintexts, err := client.DecryptBulk(protect.DecryptBulkOptions{
    Ciphertexts: ciphertexts,
})

// Fallible decrypt — per-item error handling instead of all-or-nothing
results, err := client.DecryptBulkFallible(protect.DecryptBulkOptions{
    Ciphertexts: ciphertexts,
})
for _, r := range results {
    if r.Error != nil {
        fmt.Printf("Failed: %s\n", *r.Error)
    } else {
        fmt.Printf("Value: %v\n", r.Data)
    }
}
```

## Identity-aware encryption

Lock down access to sensitive data by requiring a valid identity claim to decrypt. Data encrypted with a lock context can only be decrypted with the same context.

```go
lockContext := &protect.LockContext{
    IdentityClaim: []string{"user:12345"}, // Extract from JWT
}

// Encrypt with lock context
encrypted, err := client.Encrypt(protect.EncryptOptions{
    Plaintext:   "sensitive-data",
    Table:       "users",
    Column:      "email",
    LockContext: lockContext,
})

// Must use the same lock context to decrypt
plaintext, err := client.Decrypt(protect.DecryptOptions{
    Ciphertext:  encrypted,
    LockContext: lockContext,
})
```

> [!CAUTION]  
> You must use the same lock context to encrypt and decrypt data.  
> If you use different lock contexts, you will be unable to decrypt the data.

Lock context also works with model operations and bulk operations.

## Multi-tenant keysets

Isolate encryption keys per tenant by specifying a keyset when creating the client:

```go
client, err := protect.NewClient(protect.NewClientOptions{
    EncryptConfig: config,
    ClientOpts: &protect.ClientOpts{
        Keyset: &protect.KeysetConfig{
            Name: ptr("tenant-a"),
        },
    },
})
```

Each keyset provides cryptographic isolation — data encrypted with one keyset cannot be decrypted with another.

## Error handling

All operations return structured errors with error codes for programmatic handling:

```go
encrypted, err := client.Encrypt(opts)
if err != nil {
    if encErr, ok := err.(*protect.EncryptionError); ok {
        switch encErr.Code {
        case protect.ErrUnknownColumn:
            log.Printf("Column not in schema: %s", encErr.Message)
        case protect.ErrMissingIndex:
            log.Printf("Index not configured: %s", encErr.Message)
        case protect.ErrInvalidQueryInput:
            log.Printf("Bad query input: %s", encErr.Message)
        default:
            log.Printf("Error [%s]: %s", encErr.Code, encErr.Message)
        }
    }
}
```

| Error Code | Description |
|---|---|
| `ErrUnknownColumn` | Column not found in encryption schema |
| `ErrMissingIndex` | Required index not configured on column |
| `ErrInvalidQueryInput` | Wrong value type for query operation |
| `ErrInvalidJsonPath` | Invalid JSON path for SteVec selector |
| `ErrSteVecRequiresJsonCastAs` | SteVec index requires `cast=json` |
| `ErrUnknownQueryOp` | Unrecognized query operation |
| `ErrInvariantViolation` | Internal SDK bug |

## API reference

### Schema

| Function | Description |
|---|---|
| `TableSchema(name, model) *TableDef` | Build a table schema from a struct's `cs` tags |
| `BuildEncryptConfig(tables...) EncryptConfig` | Assemble table schemas into an encryption config |

### Client

| Method | Description |
|---|---|
| `NewClient(options) (*Client, error)` | Create an encryption client |
| `client.Free()` | Release client resources |

### Encryption

| Method | Description |
|---|---|
| `client.Encrypt(opts) (*Encrypted, error)` | Encrypt a single value |
| `client.EncryptBulk(opts) ([]Encrypted, error)` | Encrypt multiple values |
| `client.Decrypt(opts) (interface{}, error)` | Decrypt a single value |
| `client.DecryptBulk(opts) ([]interface{}, error)` | Decrypt multiple values |
| `client.DecryptBulkFallible(opts) ([]DecryptResult, error)` | Decrypt with per-item error handling |

### Models

| Method | Description |
|---|---|
| `client.EncryptModel(model, table) (map[string]interface{}, error)` | Encrypt a struct |
| `client.DecryptModel(data, table, &dest) error` | Decrypt to a struct |
| `client.BulkEncryptModels(models, table) ([]map[string]interface{}, error)` | Encrypt a slice of structs |
| `client.BulkDecryptModels(data, table, &dest) error` | Decrypt to a slice of structs |

### Query encryption

| Method | Description |
|---|---|
| `client.EncryptQuery(opts) (*Encrypted, error)` | Encrypt a search term |
| `client.EncryptQueryBulk(opts) ([]Encrypted, error)` | Encrypt multiple search terms |

### Utilities

| Function | Description |
|---|---|
| `IsEncrypted(value) bool` | Check if a value is a valid encrypted payload |

## Searchable encryption with PostgreSQL

> [!IMPORTANT]  
> Searchable encryption requires PostgreSQL with EQL extensions installed.

1. Install EQL in your database:

   ```bash
   curl -sLo cipherstash-encrypt.sql \
     https://github.com/cipherstash/encrypt-query-language/releases/latest/download/cipherstash-encrypt.sql
   psql -f cipherstash-encrypt.sql
   ```

2. Create tables with the `eql_v2_encrypted` type:

   ```sql
   CREATE TABLE users (
       id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
       email eql_v2_encrypted
   );
   ```

Read more about [searching encrypted data](./docs/concepts/searchable-encryption.md) in the docs.

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

The correct library is selected automatically at build time based on your OS and architecture.

## Running the examples

```bash
# Default (glibc)
go run examples/basic_usage.go

# Alpine Linux / musl
go run -tags=musl examples/basic_usage.go

# Static binary
CGO_ENABLED=1 go build -ldflags '-linkmode external -extldflags "-static"' -tags=musl examples/basic_usage.go
```

---

[Missing something from the docs?](https://github.com/cipherstash/protectgo/issues/new?template=docs-feedback.yml&title=[Docs:]%20Feedback%20on%20README.md)
