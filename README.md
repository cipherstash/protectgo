<h1 align="center">
  <img alt="CipherStash Logo" loading="lazy" width="128" height="128" decoding="async" data-nimg="1"   style="color:transparent" src="https://cipherstash.com/assets/cs-github.png">
  </br>
  Protect.go
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

Protect.go is a Go module for encrypting and decrypting data. Encryption operations happen directly in your app, and the ciphertext is stored in your database. Every value you encrypt with Protect.go has a unique key, made possible by CipherStash [ZeroKMS](https://cipherstash.com/products/zerokms)'s blazing fast bulk key operations, and backed by a root key in [AWS KMS](https://docs.aws.amazon.com/kms/latest/developerguide/overview.html). The encrypted data is structured as an [EQL](https://github.com/cipherstash/encrypt-query-language) JSON payload, and can be stored in any database that supports JSONB.

> [!IMPORTANT]  
> Searching, sorting, and filtering on encrypted data is currently only supported when storing encrypted data in PostgreSQL.

## Table of contents

- [Features](#features)
- [Prebuilt Libraries](#prebuilt-libraries)
- [Installing Protect.go](#installing-protectgo)
- [Getting started](#getting-started)
- [Basic usage](#basic-usage)
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

Protect.go protects data using industry-standard AES encryption. Protect.go uses [ZeroKMS](https://cipherstash.com/products/zerokms) for bulk encryption and decryption operations. This enables every encrypted value, in every column, in every row in your database to have a unique key — without sacrificing performance.

**Features:**

- **Bulk encryption and decryption**: Protect.go uses [ZeroKMS](https://cipherstash.com/products/zerokms) for encrypting and decrypting thousands of records at once, while using a unique key for every value.
- **Single item encryption and decryption**: Just looking for a way to encrypt and decrypt single values? Protect.go has you covered.
- **Really fast**: ZeroKMS's performance makes using millions of unique keys feasible and performant for real-world applications built with Protect.go.
- **Identity-aware encryption**: Lock down access to sensitive data by requiring a valid JWT to perform a decryption.
- **Audit trail**: Every decryption event will be logged in ZeroKMS to help you prove compliance.
- **Searchable encryption**: Protect.go supports searching encrypted data in PostgreSQL.
- **Type safety**: Strong typing with Go structs and interfaces.

**Use cases:**

- **Trusted data access**: make sure only your end-users can access their sensitive data stored in your product.
- **Meet compliance requirements faster**: meet and exceed the data encryption requirements of SOC2 and ISO27001.
- **Reduce the blast radius of data breaches**: limit the impact of exploited vulnerabilities to only the data your end-users can decrypt.

## Prebuilt Libraries

Protect.go uses prebuilt static libraries to provide native cryptographic functionality across different platforms. The core encryption and decryption operations are implemented in Rust and compiled into platform-specific static libraries that are embedded directly into the Go package.

### What libraries are prebuilt

The following static libraries are prebuilt and included in the Go package:

- **macOS ARM64**: `libprotect_ffi_darwin_arm64.a`
- **macOS Intel**: `libprotect_ffi_darwin_x64.a`  
- **Linux ARM64**: `libprotect_ffi_linux_arm64.a`
- **Linux x64**: `libprotect_ffi_linux_x64.a`
- **Linux ARM64 (musl)**: `libprotect_ffi_linux_arm64_musl.a`
- **Linux x64 (musl)**: `libprotect_ffi_linux_x64_musl.a`

These libraries contain the compiled Rust code from the `protect-ffi-c` crate, which provides C-compatible FFI bindings for the CipherStash client functionality.

### How the libraries work

1. **Rust Implementation**: Core encryption logic is implemented in Rust in the `crates/protect-ffi-c` directory
2. **C FFI Layer**: The Rust code exports C-compatible functions using FFI (Foreign Function Interface)
3. **Header Generation**: C headers are automatically generated using `cbindgen` during the build process
4. **Static Linking**: The Go package uses CGO to statically link against the appropriate prebuilt library for your platform
5. **Platform Selection**: The correct library is automatically selected at build time based on your OS and architecture

This approach ensures that Protect.go can leverage high-performance Rust cryptographic implementations while providing a native Go API, without requiring users to install Rust or compile anything themselves.

## Installing Protect.go

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
> Make sure you have [installed the CipherStash CLI](#installing-protectgo) before following these steps.

To set up all the configuration and credentials required for Protect.go:

```bash
stash setup
```

If you haven't already signed up for a CipherStash account, this will prompt you to do so along the way.

At the end of `stash setup`, you will have two files in your project:

- `cipherstash.toml` which contains the configuration for Protect.go
- `cipherstash.secret.toml`: which contains the credentials for Protect.go

> [!WARNING]  
> Don't commit `cipherstash.secret.toml` to git; it contains sensitive credentials.  
> The `stash setup` command will attempt to append to your `.gitignore` file with the `cipherstash.secret.toml` file.

### Environment Variables

The library respects the following environment variables:

- `CIPHERSTASH_WORKSPACE_CRN` - Workspace CRN
- `CIPHERSTASH_ACCESS_KEY` - Access key
- `CIPHERSTASH_CLIENT_ID` - Client ID  
- `CIPHERSTASH_CLIENT_KEY` - Client key

## Basic usage

### Simple encryption and decryption

```go
package main

import (
    "context"
    "log"
    
    "github.com/cipherstash/protectgo/pkg/protect"
)

func main() {
    // Configure encryption settings
    config := protect.EncryptConfig{
        Version: 1,
        Tables: protect.Tables{
            "users": protect.Table{
                "email": protect.Column{
                    CastAs: &protect.CastAsText,
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

    log.Printf("Encrypted: %s", *encrypted.Ciphertext)

    // Decrypt data
    plaintext, err := client.Decrypt(protect.DecryptOptions{
        Ciphertext: *encrypted.Ciphertext,
    })
    if err != nil {
        log.Fatal(err)
    }

    log.Printf("Decrypted: %s", plaintext)
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
for i, enc := range bulkEncrypted {
    ciphertexts[i] = protect.BulkDecryptPayload{
        Ciphertext: *enc.Ciphertext,
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

## Configuration

### Encryption Configuration

```go
type EncryptConfig struct {
    Version uint32 `json:"v"`
    Tables  Tables `json:"tables"`
}

type Tables map[string]Table
type Table map[string]Column

type Column struct {
    CastAs  *CastAs  `json:"cast_as,omitempty"`
    Indexes *Indexes `json:"indexes,omitempty"`
}
```

### Client Configuration

```go
type ClientOpts struct {
    WorkspaceCrn *string `json:"workspaceCrn,omitempty"`
    AccessKey    *string `json:"accessKey,omitempty"`
    ClientID     *string `json:"clientId,omitempty"`
    ClientKey    *string `json:"clientKey,omitempty"`
}
```

### Index Types

The library supports all the same index types as other Protect libraries:

- **ORE Index**: For range queries and ordering
- **Match Index**: For full-text search  
- **Unique Index**: For exact matching and uniqueness constraints
- **SteVec Index**: For vector similarity searches

### Data Types

Supported cast types:
- `CastAsText` - UTF-8 strings
- `CastAsInt` - 32-bit integers
- `CastAsBigInt` - 64-bit integers
- `CastAsBoolean` - Boolean values
- `CastAsDate` - Date values
- `CastAsReal/CastAsDouble` - Floating point numbers
- `CastAsJsonB` - JSON data

## Identity-aware encryption

> [!IMPORTANT]  
> Identity-aware encryption requires implementing JWT validation in your application.

Protect.go can add an additional layer of protection to your data by requiring a valid JWT to perform a decryption. This ensures that only the user who encrypted data is able to decrypt it.

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
    Ciphertext:  *encrypted.Ciphertext,
    LockContext: &lockContext,
})
```

> [!CAUTION]  
> You must use the same lock context to encrypt and decrypt data.  
> If you use different lock contexts, you will be unable to decrypt the data.

## Supported data types

Protect.go currently supports encrypting and decrypting text. Other data types like booleans, dates, ints, floats, and JSON are well-supported in other CipherStash products, and will be coming to Protect.go soon.

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

- `NewClient(options NewClientOptions) (*Client, error)` - Create a new client
- `client.Free()` - Release client resources
- `client.Encrypt(options EncryptOptions) (*Encrypted, error)` - Encrypt single value
- `client.EncryptBulk(options EncryptBulkOptions) ([]Encrypted, error)` - Encrypt multiple values
- `client.Decrypt(options DecryptOptions) (string, error)` - Decrypt single value  
- `client.DecryptBulk(options DecryptBulkOptions) ([]string, error)` - Decrypt multiple values
- `client.DecryptBulkFallible(options DecryptBulkOptions) ([]DecryptResult, error)` - Decrypt with error handling per item

### Error Handling

All operations return Go-style errors. Use standard Go error handling patterns:

```go
if err != nil {
    // Handle error
    log.Printf("Encryption failed: %v", err)
    return err
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
