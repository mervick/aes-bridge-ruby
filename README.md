# AesBridge Ruby

![Gem Version](https://img.shields.io/gem/v/aes-bridge.svg)
![CI Status](https://github.com/mervick/aes-bridge-ruby/actions/workflows/tests.yml/badge.svg)

**AesBridge** is a modern, secure, and cross-language **AES** encryption library. It offers a unified interface for encrypting and decrypting data across multiple programming languages. Supports **GCM**, **CBC**, and **legacy AES Everywhere** modes.


This is the **Python implementation** of the core project.  
👉 Main repository: https://github.com/mervick/aes-bridge

## Features

- 🔐 AES-256 encryption in GCM (recommended) and CBC modes
- 🌍 Unified cross-language design
- 📦 Compact binary format or base64 output
- ✅ HMAC Integrity: CBC mode includes HMAC verification
- 🔄 Backward Compatible: Supports legacy AES Everywhere format

## Quick Start

### Installation

```sh
gem install aes-bridge
```

### Usage
```rb
require 'aes_bridge'

# Encrypting a string (GCM mode is used by default)
ciphertext = AesBridge.encrypt("My secret message", "MyStrongPass")
puts "Encrypted message (base64): #{ciphertext}"

# Decrypting the string (GCM mode)
plaintext = AesBridge.decrypt(ciphertext, "MyStrongPass")
puts "Decrypted message: #{plaintext}"

# Explicit GCM example
gcm_ciphertext = AesBridge.encrypt_gcm("Message for GCM", "GCMpassword")
gcm_plaintext = AesBridge.decrypt_gcm(gcm_ciphertext, "GCMpassword")
puts "GCM decrypted: #{gcm_plaintext}"

# CBC example
cbc_ciphertext = AesBridge.encrypt_cbc("Message for CBC", "CBCpassword")
cbc_plaintext = AesBridge.decrypt_cbc(cbc_ciphertext, "CBCpassword")
puts "CBC decrypted: #{cbc_plaintext}"
```

## API Reference

### Main Functions (GCM by default)

  * `AesBridge.encrypt(data, passphrase)`
    Encrypts a string using AES-GCM (default).
    **Returns:** A base64-encoded string.

  * `AesBridge.decrypt(ciphertext, passphrase)`
    Decrypts a base64-encoded string encrypted with AES-GCM.

### GCM Mode (Recommended)

  * `AesBridge.encrypt_gcm(data, passphrase)`
    Encrypts a string using AES-GCM.
    **Returns:** A base64-encoded string.

  * `AesBridge.decrypt_gcm(ciphertext, passphrase)`
    Decrypts a base64-encoded string encrypted with `encrypt_gcm`.

  * `AesBridge.encrypt_gcm_bin(data, passphrase)`
    Returns encrypted binary data using AES-GCM.

  * `AesBridge.decrypt_gcm_bin(ciphertext, passphrase)`
    Decrypts binary data encrypted with `encrypt_gcm_bin`.

### CBC Mode

  * `AesBridge.encrypt_cbc(data, passphrase)`
    Encrypts a string using AES-CBC. HMAC is used for integrity verification.
    **Returns:** A base64-encoded string.

  * `AesBridge.decrypt_cbc(ciphertext, passphrase)`
    Decrypts a base64-encoded string encrypted with `encrypt_cbc` and verifies HMAC.

  * `AesBridge.encrypt_cbc_bin(data, passphrase)`
    Returns encrypted binary data using AES-CBC with HMAC.

  * `AesBridge.decrypt_cbc_bin(ciphertext, passphrase)`
    Decrypts binary data encrypted with `encrypt_cbc_bin` and verifies HMAC.

### Legacy Compatibility

⚠️ These functions are kept for backward compatibility only. Their usage is **strongly discouraged** in new applications.

  * `AesBridge.encrypt_legacy(data, passphrase)`
    Encrypts a string in the legacy AES Everywhere format.

  * `AesBridge.decrypt_legacy(ciphertext, passphrase)`
    Decrypts a string encrypted in the legacy AES Everywhere format.
