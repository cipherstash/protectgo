# Development Guide

This repo is a combination of the Protect.go module and the Protect.go FFI for the Rust C library which is used to create bindings for the `cipherstash-client` crate.

## Architecture

The project consists of:

1. **Rust C Library** (`crates/protect-ffi-c/`) - A Rust library that exports C-compatible functions
2. **Go Package** (`pkg/protect/`) - Go bindings that wrap the C functions 
3. **Examples** (`examples/`) - Usage examples showing how to use the library

```
protectgo/
├── crates/
│   └── protect-ffi-c/     # Rust C FFI library
├── pkg/protect/           # Go package
├── examples/              # Usage examples
```

## Building

### Prerequisites

- [mise](https://mise.jdx.dev/) (handles Go and Rust versions automatically)
- CipherStash credentials and configuration

**Note**: mise will automatically install and manage the correct versions of Go (1.24.4) and Rust (nightly) for this project.

### Build Steps

1. **Install mise** (if not already installed):
   ```bash
   # macOS
   brew install mise
   
   # Linux
   curl https://mise.run | sh
   ```

2. **Install dependencies and tools**:
   ```bash
   mise run install-deps
   ```

3. **Build the project**:
   ```bash
   mise run build
   ```

4. **Run tests**:
   ```bash
   mise run test
   ```

5. **Build and run example**:
   ```bash
   mise run example
   ./bin/example
   ```

## Development

### Project Structure

```
protectgo/
├── Cargo.toml              # Rust workspace
├── go.mod                  # Go module
├── mise.toml              # Task automation and tool management
├── Makefile               # Legacy build automation (deprecated)
├── crates/
│   └── protect-ffi-c/     # Rust C FFI library
│       ├── Cargo.toml
│       ├── build.rs       # Build script for header generation
│       ├── cbindgen.toml  # Header generation config
│       └── src/
│           ├── lib.rs     # Main FFI functions
│           └── encrypt_config.rs
├── pkg/
│   └── protect/        # Go package
│       └── protect.go  # Go bindings
└── examples/
    └── basic_usage.go     # Usage example
```

### Building from Source

1. Clone the repository
2. Install mise (see Build Steps above)
3. Run `mise run install-deps` to install dependencies and tools
4. Run `mise run build` to build the library
5. Run `mise run test` to run tests

**Available tasks**: Run `mise tasks` to see all available tasks including formatting, linting, and cleanup commands.

### Memory Management

The Go bindings automatically handle memory management:
- C strings are automatically freed after use
- Client resources must be explicitly freed with `client.Free()`
- All returned data is copied to Go-managed memory

## Testing

Run the test suite with:

```bash
mise run test
```

Additional development tasks:

```bash
mise run fmt     # Format code (Rust + Go)
mise run check   # Run linting and quality checks
mise run clean   # Clean build artifacts
```

## Support

For support and questions:
- GitHub Issues: [protectgo/issues](https://github.com/cipherstash/protectgo/issues)
- CipherStash Documentation: [docs.cipherstash.com](https://docs.cipherstash.com) 