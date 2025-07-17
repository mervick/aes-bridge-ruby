# frozen_string_literal: true

require 'openssl'
require 'base64'
require_relative "common"

module AesBridge
  class Error < StandardError; end

  # Derives AES and HMAC keys from a passphrase and salt using PBKDF2-HMAC-SHA256.
  #
  # @param passphrase [String] The passphrase from which to derive the keys.
  # @param salt [String] The salt value to use in the key derivation process.
  # @return [Array<String>] An array containing the derived AES key and HMAC key.
  def self.derive_keys_cbc(passphrase, salt)
    key_material = OpenSSL::KDF.pbkdf2_hmac(
      passphrase,
      salt: salt,
      iterations: 100_000,
      length: 64,
      hash: 'sha256'
    )
    [key_material[0, 32], key_material[32, 32]]
  end

  # Encrypts the given plaintext using AES-CBC-256 with a randomly generated IV,
  # and HMAC-SHA-256 for integrity verification.
  #
  # @param plaintext [String] The plaintext to encrypt.
  # @param passphrase [String] The passphrase from which to derive the encryption and HMAC keys.
  # @return [String] The encrypted binary data.
  def self.encrypt_cbc_bin(plaintext, passphrase)
    plaintext = self.to_bytes(plaintext)
    passphrase = self.to_bytes(passphrase)
    salt = self.generate_random(16)
    iv = self.generate_random(16)
    aes_key, hmac_key = self.derive_keys_cbc(passphrase, salt)

    cipher = OpenSSL::Cipher.new('aes-256-cbc')
    cipher.encrypt
    cipher.key = aes_key
    cipher.iv = iv

    # fix empty plaintext encryption
    if plaintext.bytesize > 0
      ciphertext = cipher.update(plaintext) + cipher.final
    else
      ciphertext = '' + cipher.final
    end

    tag = OpenSSL::HMAC.digest('sha256', hmac_key, iv + ciphertext)
    salt + iv + ciphertext + tag
  end

  # Decrypts the given ciphertext using AES-CBC-256 and HMAC-SHA-256 for
  # integrity verification.
  #
  # @param data [String] The ciphertext to decrypt.
  # @param passphrase [String] The passphrase from which to derive the
  #   encryption and HMAC keys.
  # @return [String] The decrypted plaintext.
  def self.decrypt_cbc_bin(data, passphrase)
    data = self.to_bytes(data)
    passphrase = self.to_bytes(passphrase)

    salt = data[0, 16]
    iv = data[16, 16]
    tag = data[-32, 32]
    ciphertext = data[32...-32]

    aes_key, hmac_key = self.derive_keys_cbc(passphrase, salt)

    expected_tag = OpenSSL::HMAC.digest('sha256', hmac_key, iv + ciphertext)
    raise 'HMAC verification failed' unless expected_tag == tag

    cipher = OpenSSL::Cipher.new('aes-256-cbc')
    cipher.decrypt
    cipher.key = aes_key
    cipher.iv = iv

    # fix empty plaintext decryption
    if ciphertext.bytesize == 0
      return ''
    end
    cipher.update(ciphertext) + cipher.final
  end

  # Encrypts the given plaintext using AES-CBC-256 with a randomly generated IV,
  # and HMAC-SHA-256 for integrity verification.
  #
  # @param plaintext [String] The plaintext to encrypt.
  # @param passphrase [String] The passphrase from which to derive the
  #   encryption and HMAC keys.
  # @return [String] The encrypted, base64-encoded string.
  def self.encrypt_cbc(data, passphrase)
    Base64.strict_encode64(encrypt_cbc_bin(data, passphrase))
  end

  # Decrypts a base64-encoded string encrypted with AES-CBC-256 and verifies its integrity using HMAC-SHA-256.
  #
  # @param data [String] The base64-encoded ciphertext to decrypt.
  # @param passphrase [String] The passphrase from which to derive the encryption and HMAC keys.
  # @return [String] The decrypted plaintext.
  def self.decrypt_cbc(data, passphrase)
    decrypt_cbc_bin(Base64.decode64(data), passphrase)
  end

end
