# GasGuard Rust Development Guide

## Structure
- **apps/rust/**: Binary crates (services, CLI tools).
- **libs/rust/**: Shared library crates.

## Workflow
The project uses a Cargo workspace defined in the root `Cargo.toml`.

To build all Rust projects:
```bash
cargo build
```
