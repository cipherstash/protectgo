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
- [Prebuilt Libraries](#prebuilt-libraries)
- [Installing](#installing)
- [Getting started](#getting-started)
- [Basic usage](#basic-usage)
- [Query encryption](#query-encryption)
- [Model interface](#model-interface)
- [Multi-tenant keysets](#multi-tenant-keysets)
- [Configuration](#configuration)
- [Identity-aware encryption](#identity-aware-encryption)
- [Supported data types](#supported-data-types)
- [Searchable encryption](#searchable-encryption)
- [API Reference](#api-reference)
- [Building from source](#building-from-source)
- [Example applications](#example-applications)
- [Contributing](#contributing)
- [License](#license)

For more specific documentation, refer to the [docs](./docs).

## Features

The CipherStash Go Encryption SDK protects data using industry-standard AES encryption with [ZeroKMS](https://cipherstash.com/products/zerokms) for bulk encryption and decryption operations. This enables every encrypted value, in every column, in every row in your database to have a unique key — without sacrificing performance.

**Features:**

- **Bulk encryption and decryption**: Encrypt and decrypt thousands of records at once using [ZeroKMS](https://cipherstash.com/products/zerokms), with a unique key for every value.
- **Single item encryption and decryption**: Encrypt and decrypt individual values with a simple API.
- **Query encryption**: Encrypt search terms to query encrypted columns without decrypting the data first.
- **Model interface**: Encrypt and decrypt entire Go structs using struct tags — no manual field-by-field encryption.
- **Multi-type support**: Encrypt strings, numbers, booleans, and JSON values.
- **Multi-tenant keysets**: Isolate encryption keys per tenant for multi-tenant applications.
- **Really fast**: ZeroKMS's performance makes using millions of unique keys feasible and performant.
- **Identity-aware encryption**: Lock down access to sensitive data by requiring a valid JWT to decrypt.
- **Audit trail**: Every decryption event is logged in ZeroKMS to help prove compliance.
- **Searchable encryption**: Search encrypted data in PostgreSQL using equality, full-text, range, and JSON containment queries.
- **Structured errors**: Error codes for programmatic error handling.

**Use cases:**

- **Trusted data access**: make sure only your end-users can access their sensitive data stored in your product.
- **Meet compliance requirements faster**: meet and exceed the data encryption requirements of SOC2 and ISO27001.
- **Reduce the blast radius of data breaches**: limit the impact of exploited vulnerabilities to only the data your end-users can decrypt.

## Prebuilt Libraries

The SDK uses prebuilt static libraries to provide native cryptographic functionality across different platforms. The core encryption and decryption operations are implemented in Rust and compiled into platform-specific static libraries that are embedded directly into the Go package.

### What libraries are prebuilt

The following static libraries are prebuilt and included in the Go package:

- **macOS ARM64**: `libprotect_ffi_darwin_arm64.a`
- **macOS Intel**: `libprotect_ffi_darwin_x64.a`  
- **Linux ARM64**: `libprotect_ffi_linux_arm64.a`
- **Linux x64**: `libprotect_ffi_linux_x64.a`
- **Linux ARM64 (musl)**: `libprotect_ffi_linux_arm64_musl.a`
- **Linux x64 (musl)**: `libprotect_ffi_linux_x64_musl.a`

### How the libraries work

1. **Rust Implementation**: Core encryption logic is implemented in Rust in the `crates/protect-ffi-c` directory
2. **C FFI Layer**: The Rust code exports C-compatible functions using FFI (Foreign Function Interface)
3. **Header Generation**: C headers are automatically generated using `cbindgen` during the build process
4. **Static Linking**: The Go package uses CGO to statically link against the appropriate prebuilt library for your platform
5. **Platform Selection**: The correct library is automatically selected at build time based on your OS and architecture

This approach ensures that the SDK can leverage high-performance Rust cryptographic implementations while providing a native Go API, without requiring users to install Rust or compile anything themselves.

## Installing

### Prerequisites

- Go 1.21 or later
- CipherStash CLI (for configuration)

### Install the Go package

```bash
go get github.com/cipherstash/protectgo/pkg/protect
```

### Install the CipherStash CLI

- On macOS:
  ```bash
  brew install cipherstash/tap/stash
  ```

- On Linux, download the binary for your platform, and put it on your `PATH`:
  - [Linux ARM64](https://github.com/cipherstash/cli-releases/releases/latest/download/stash-aarch64-unknown-linux-gnu)
  - [Linux x86_64](https://github.com/cipherstash/cli-releases/releases/latest/download/stash-x86_64-unknown-linux-gnu)

## Getting started

### Configuration

> [!IMPORTANT]  
> Make sure you have [installed the CipherStash CLI](#installing) before following these steps.

To set up all the configuration and credentials required:

```bash
stash setup
```

If you haven't already signed up for a CipherStash account, this will prompt you to do so along the way.

At the end of `stash setup`, you will have two files in your project:

- `cipherstash.toml` which contains the configuration
- `cipherstash.secret.toml`: which contains the credentials

> [!WARNING]  
> Don't commit `cipherstash.secret.toml` to git; it contains sensitive credentials.  
> The `stash setup` command will attempt to append to your `.gitignore` file with the `cipherstash.secret.toml` file.

### Environment Variables

The library respects the following environment variables:

- `CS_WORKSPACE_CRN` - Workspace CRN
- `CS_CLIENT_ACCESS_KEY` - Access key
- `CS_CLIENT_ID` - Client ID  
- `CS_CLIENT_KEY` - Client key

## Basic usage

### Simple encryption and decryption

```go
package main

import (
    "log"

    "github.com/cipherstash/protectgo/pkg/protect"
)

func main() {
    // Configure encryption settings
    castAs := protect.CastAsString
    config := protect.EncryptConfig{
        Version: 1,
        Tables: protect.Tables{
            "users": protect.Table{
                "email": protect.Column{
                    CastAs: &castAs,
                    Indexes: &protect.Indexes{
                        UniqueIndex: &protect.UniqueIndexOpts{
                            TokenFilters: []protect.TokenFilter{
                                {Kind: "downcase"},
                            },
                        },
                    },
                },
            },
        },
    }

    // Create client
    client, err := protect.NewClient(protect.NewClientOptions{
        EncryptConfig: config,
    })
    if err != nil {
        log.Fatal(err)
    }
    defer client.Free()

    // Encrypt data
    encrypted, err := client.Encrypt(protect.EncryptOptions{
        Plaintext: "john.doe@example.com",
        Table:     "users",
        Column:    "email",
    })
    if err != nil {
        log.Fatal(err)
    }

    log.Printf("Encrypted successfully")

    // Decrypt data
    plaintext, err := client.Decrypt(protect.DecryptOptions{
        Ciphertext: encrypted,
    })
    if err != nil {
        log.Fatal(err)
    }

    log.Printf("Decrypted: %v", plaintext)
}
```

### Bulk operations

```go
// Bulk encryption
bulkEncrypted, err := client.EncryptBulk(protect.EncryptBulkOptions{
    Plaintexts: []protect.PlaintextPayload{
        {
            Plaintext: "alice@example.com",
            Table:     "users",
            Column:    "email",
        },
        {
            Plaintext: "bob@example.com",
            Table:     "users",
            Column:    "email",
        },
    },
})
if err != nil {
    log.Fatal(err)
}

// Bulk decryption
ciphertexts := make([]protect.BulkDecryptPayload, len(bulkEncrypted))
for i := range bulkEncrypted {
    ciphertexts[i] = protect.BulkDecryptPayload{
        Ciphertext: &bulkEncrypted[i],
    }
}

plaintexts, err := client.DecryptBulk(protect.DecryptBulkOptions{
    Ciphertexts: ciphertexts,
})
if err != nil {
    log.Fatal(err)
}

log.Printf("Decrypted values: %v", plaintexts)
```

## Query encryption

Encrypt search terms to query encrypted columns without exposing plaintext in your queries.

```go
// Encrypt a query term for exact match
queryEncrypted, err := client.EncryptQuery(protect.EncryptQueryOptions{
    Plaintext: "john.doe@example.com",
    Table:     "users",
    Column:    "email",
    IndexType: protect.IndexTypeUnique,
})
if err != nil {
    log.Fatal(err)
}

// Use queryEncrypted.UniqueIndex in your SQL WHERE clause

// Encrypt a query term for full-text search
searchEncrypted, err := client.EncryptQuery(protect.EncryptQueryOptions{
    Plaintext: "john",
    Table:     "users",
    Column:    "name",
    IndexType: protect.IndexTypeMatch,
})
if err != nil {
    log.Fatal(err)
}

// Batch encrypt multiple query terms
batchEncrypted, err := client.EncryptQueryBulk(protect.EncryptQueryBulkOptions{
    Queries: []protect.QueryPayload{
        {
            Plaintext: "alice@example.com",
            Table:     "users",
            Column:    "email",
            IndexType: protect.IndexTypeUnique,
        },
        {
            Plaintext: "bob",
            Table:     "users",
            Column:    "name",
            IndexType: protect.IndexTypeMatch,
        },
    },
})
```

### Query types

| Index Type | Use Case | QueryOp |
|---|---|---|
| `IndexTypeUnique` | Exact match (`=`) | `QueryOpDefault` |
| `IndexTypeMatch` | Full-text search (`LIKE`, `ILIKE`) | `QueryOpDefault` |
| `IndexTypeOre` | Range comparisons (`<`, `>`, `<=`, `>=`) | `QueryOpDefault` |
| `IndexTypeSteVec` | JSON path queries | `QueryOpSteVecSelector` |
| `IndexTypeSteVec` | JSON containment (`@>`) | `QueryOpSteVecTerm` |

## Model interface

Encrypt and decrypt entire Go structs using the `cs` struct tag. Fields tagged with `cs:"column_name"` are automatically encrypted/decrypted. Non-tagged fields pass through unchanged.

```go
type User struct {
    ID    int    `json:"id"`
    Email string `json:"email" cs:"email"`
    Name  string `json:"name"  cs:"name"`
    Role  string `json:"role"`  // not encrypted
}

// Encrypt a model
user := User{ID: 1, Email: "john@example.com", Name: "John", Role: "admin"}
encrypted, err := client.EncryptModel(user, "users")
// encrypted["id"] = 1
// encrypted["email"] = *Encrypted{...}
// encrypted["name"] = *Encrypted{...}
// encrypted["role"] = "admin"

// Decrypt back to a struct
var decrypted User
err = client.DecryptModel(encrypted, "users", &decrypted)
// decrypted.Email == "john@example.com"
// decrypted.Role == "admin"

// Bulk encrypt models (single KMS call for all fields across all models)
users := []User{
    {ID: 1, Email: "alice@example.com", Name: "Alice", Role: "admin"},
    {ID: 2, Email: "bob@example.com", Name: "Bob", Role: "user"},
}
encryptedModels, err := client.BulkEncryptModels(users, "users")

// Bulk decrypt models
var decryptedUsers []User
err = client.BulkDecryptModels(encryptedModels, "users", &decryptedUsers)
```

## Multi-tenant keysets

Isolate encryption keys per tenant by specifying a keyset when creating the client:

```go
client, err := protect.NewClient(protect.NewClientOptions{
    EncryptConfig: config,
    ClientOpts: &protect.ClientOpts{
        Keyset: &protect.KeysetConfig{
            Name: stringPtr("tenant-a"),
        },
    },
})
```

Each keyset provides cryptographic isolation — data encrypted with one keyset cannot be decrypted with another.

## Configuration

### Encryption Configuration

```go
config := protect.EncryptConfig{
    Version: 1,
    Tables: protect.Tables{
        "users": protect.Table{
            "email": protect.Column{
                CastAs: &protect.CastAsString,
                Indexes: &protect.Indexes{
                    UniqueIndex: &protect.UniqueIndexOpts{},
                    MatchIndex:  &protect.MatchIndexOpts{},
                    OreIndex:    &protect.OreIndexOpts{},
                },
            },
            "profile": protect.Column{
                CastAs: &protect.CastAsJson,
                Indexes: &protect.Indexes{
                    SteVecIndex: &protect.SteVecIndexOpts{
                        Prefix: "users/profile",
                    },
                },
            },
        },
    },
}
```

### Client Configuration

```go
type ClientOpts struct {
    WorkspaceCrn *string       `json:"workspaceCrn,omitempty"`
    AccessKey    *string       `json:"accessKey,omitempty"`
    ClientID     *string       `json:"clientId,omitempty"`
    ClientKey    *string       `json:"clientKey,omitempty"`
    Keyset       *KeysetConfig `json:"keyset,omitempty"`
}
```

### Index Types

- **ORE Index**: For range queries and ordering (`<`, `>`, `<=`, `>=`)
- **Match Index**: For full-text search with configurable tokenizers
- **Unique Index**: For exact matching with optional case-insensitive filters
- **SteVec Index**: For JSON path queries and containment searches

### Data Types

Supported `CastAs` types:

| Go Constant | Description |
|---|---|
| `CastAsString` | UTF-8 strings (default) |
| `CastAsText` | UTF-8 strings (alias) |
| `CastAsBigInt` | 64-bit integers |
| `CastAsNumber` | Floating point numbers |
| `CastAsBoolean` | Boolean values |
| `CastAsDate` | Date values |
| `CastAsJson` | JSON data (required for SteVec index) |

## Identity-aware encryption

> [!IMPORTANT]  
> Identity-aware encryption requires implementing JWT validation in your application.

Lock down access to sensitive data by requiring a valid identity claim to decrypt. This ensures that only the user who encrypted data is able to decrypt it.

### Using Lock Context

```go
// Create lock context from JWT claims
lockContext := protect.LockContext{
    IdentityClaim: []string{"user:12345"}, // Extract from JWT
}

// Encrypt with lock context
encrypted, err := client.Encrypt(protect.EncryptOptions{
    Plaintext:   "sensitive-data",
    Table:       "users",
    Column:      "email",
    LockContext: &lockContext,
})

// Decrypt with the same lock context
plaintext, err := client.Decrypt(protect.DecryptOptions{
    Ciphertext:  encrypted,
    LockContext: &lockContext,
})
```

> [!CAUTION]  
> You must use the same lock context to encrypt and decrypt data.  
> If you use different lock contexts, you will be unable to decrypt the data.

## Supported data types

The SDK supports encrypting and decrypting multiple data types:

- **Strings** — text values
- **Numbers** — floating point values (coerced to integer types based on `CastAs`)
- **Booleans** — true/false values
- **JSON** — objects and arrays (required for SteVec searchable encryption)

## Searchable encryption

> [!IMPORTANT]  
> Searchable encryption requires PostgreSQL with EQL extensions installed.

To enable searchable encryption, you need to install EQL in your PostgreSQL database:

1. Download the latest EQL install script:
   ```bash
   curl -sLo cipherstash-encrypt.sql \
     https://github.com/cipherstash/encrypt-query-language/releases/latest/download/cipherstash-encrypt.sql
   ```

2. Run this command to install the custom types and functions:
   ```bash
   psql -f cipherstash-encrypt.sql
   ```

3. Create tables with the `eql_v2_encrypted` type:
   ```sql
   CREATE TABLE users (
       id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
       email eql_v2_encrypted
   );
   ```

Read more about [searching encrypted data](./docs/concepts/searchable-encryption.md) in the docs.

## API Reference

### Client Methods

| Method | Description |
|---|---|
| `NewClient(options) (*Client, error)` | Create a new encryption client |
| `client.Free()` | Release client resources |
| `client.Encrypt(options) (*Encrypted, error)` | Encrypt a single value |
| `client.EncryptBulk(options) ([]Encrypted, error)` | Encrypt multiple values |
| `client.Decrypt(options) (interface{}, error)` | Decrypt a single value |
| `client.DecryptBulk(options) ([]interface{}, error)` | Decrypt multiple values |
| `client.DecryptBulkFallible(options) ([]DecryptResult, error)` | Decrypt with per-item error handling |
| `client.EncryptQuery(options) (*Encrypted, error)` | Encrypt a search term |
| `client.EncryptQueryBulk(options) ([]Encrypted, error)` | Encrypt multiple search terms |
| `client.EncryptModel(model, table) (map[string]interface{}, error)` | Encrypt a struct |
| `client.DecryptModel(data, table, dest) error` | Decrypt to a struct |
| `client.BulkEncryptModels(models, table) ([]map[string]interface{}, error)` | Encrypt multiple structs |
| `client.BulkDecryptModels(data, table, dest) error` | Decrypt to multiple structs |

### Standalone Functions

| Function | Description |
|---|---|
| `IsEncrypted(value) bool` | Check if a value is a valid encrypted payload |

### Error Handling

All operations return structured errors with error codes for programmatic handling:

```go
encrypted, err := client.Encrypt(opts)
if err != nil {
    if encErr, ok := err.(*protect.EncryptionError); ok {
        switch encErr.Code {
        case protect.ErrUnknownColumn:
            log.Printf("Column not found in schema: %s", encErr.Message)
        case protect.ErrMissingIndex:
            log.Printf("Index not configured: %s", encErr.Message)
        default:
            log.Printf("Encryption error [%s]: %s", encErr.Code, encErr.Message)
        }
    }
}
```

## Running the basic usage example

### Running with glibc (default)

For most Linux distributions that use glibc:

```bash
go run examples/basic_usage.go
```

### Running with musl (Alpine Linux)

For Alpine Linux or musl-based systems:

```bash
go run -tags=musl examples/basic_usage.go
```

### Building a static binary with musl

To create a completely static binary of the example:

```bash
# Build static Go binary
CGO_ENABLED=1 go build -ldflags '-linkmode external -extldflags "-static"' -tags=musl examples/basic_usage.go

# Run the static binary
./basic_usage_static
```

### Didn't find what you wanted?

[Click here to let us know what was missing from our docs.](https://github.com/cipherstash/protectgo/issues/new?template=docs-feedback.yml&title=[Docs:]%20Feedback%20on%20README.md) 
