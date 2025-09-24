#!/bin/bash
set -e

# Build the Rust library
cargo build --release

# Copy the static library to lib directory
cp target/release/libprotect_ffi.a lib/

echo "Build complete - header in include/, library in lib/"
