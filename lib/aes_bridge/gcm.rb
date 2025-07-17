# frozen_string_literal: true

require 'openssl'
require 'base64'
require_relative 'common'


module AesBridge
  def self.derive_key_gcm(passphrase, salt)
    OpenSSL::KDF.pbkdf2_hmac(
      passphrase,
      salt: salt,
      iterations: 100_000,
      length: 32,
      hash: 'sha256'
    )
  end

  # Encrypts the given plaintext using AES-GCM.
  #
  # @param plaintext [String] The plaintext to encrypt.
  # @param passphrase [String] The passphrase from which to derive the encryption key.
  # @return [String] The encrypted binary data.
  def self.encrypt_gcm_bin(plaintext, passphrase)
    passphrase = to_bytes(passphrase)
    plaintext = to_bytes(plaintext)
    salt = generate_random(16)
    nonce = generate_random(12)
    key = derive_key_gcm(passphrase, salt)

    cipher = OpenSSL::Cipher.new('aes-256-gcm')
    cipher.encrypt
    cipher.key = key
    cipher.iv = nonce

    # fix empty plaintext encryption
    if plaintext.bytesize > 0
      ciphertext = cipher.update(plaintext) + cipher.final
    else
      ciphertext = '' + cipher.final
    end

    tag = cipher.auth_tag
    salt + nonce + ciphertext + tag
  end

  # Decrypts a binary string encrypted with AES-GCM.
  #
  # @param data [String] The ciphertext to decrypt.
  # @param passphrase [String] The passphrase from which to derive the encryption key.
  # @return [String] The decrypted plaintext.
  def self.decrypt_gcm_bin(data, passphrase)
    data = to_bytes(data)
    passphrase = to_bytes(passphrase)

    salt = data[0,16]
    nonce = data[16,12]
    tag = data[-16,16]
    ciphertext = data[28...-16]

    cipher = OpenSSL::Cipher.new('aes-256-gcm')
    cipher.decrypt
    cipher.key = derive_key_gcm(passphrase, salt)
    cipher.iv = nonce
    cipher.auth_tag = tag

    # fix empty plaintext decryption
    if ciphertext.bytesize == 0
      return ''
    end
    cipher.update(ciphertext) + cipher.final
  end

  # Encrypts a string using AES-GCM.
  #
  # @param data [String] The plaintext to encrypt.
  # @param passphrase [String] The passphrase from which to derive the encryption key.
  # @return [String] The encrypted, base64-encoded string.
  def self.encrypt_gcm(data, passphrase)
    Base64.strict_encode64(encrypt_gcm_bin(data, passphrase))
  end

  # Decrypts a base64-encoded string encrypted with AES-GCM and verifies its integrity
  # using an authentication tag.
  #
  # @param data [String] The base64-encoded ciphertext to decrypt.
  # @param passphrase [String] The passphrase from which to derive the encryption and HMAC keys.
  # @return [String] The decrypted plaintext.
  def self.decrypt_gcm(data, passphrase)
    decrypt_gcm_bin(Base64.decode64(to_bytes(data)), passphrase)
  end
end
