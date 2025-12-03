# edwards-curve-signature-rs

edwards-curve-signature-rs is a lightweight Rust library that implements digital signatures using an Edwards-curve (EdDSA-style) API.  
It is intended for learning, experimentation, and integration into Rust projects needing fast, modern signature primitives.

## Features

- Keypair generation
- Message signing
- Signature verification
- Command-line signing tool (`sigtool`)

## Requirements

- Rust (stable) — tested with Rust 1.70+
- Cargo

---

# Command-line Tool (`sigtool`)

This repository includes a simple CLI tool for generating keys, signing messages, and verifying signatures.

## 🔧 Build
```bash
cargo build --release
```

## ✍️ Sign a Message
```bash
./sigtool sign –-in message.txt –-key secret.pem –-out signature.sig
```

- `--in` : Path to the message file
- `--key`: Secret key in PEM format
- `--out`: Output signature file (`.sig` is recommended)

## 🔐 Generate Public Key
```bash
./sigtool gen-key –-key secret.pem –-out ecdsa.pub
```

- `--key`: Secret key in PEM format
- `--out`: Output public key file

## ✅ Verify a Signature
```bash
./sigtool verify –-in message.txt –-key ecdsa.pub –-sig signature.sig
```
- `--in` : Path to the message file
- `--key`: Public key in PEM format
- `--sig`: Signature file to verify

---

## API

Refer to the crate's documentation (docs.rs or generated with `cargo doc --open`)  
for full API details, types, and examples.