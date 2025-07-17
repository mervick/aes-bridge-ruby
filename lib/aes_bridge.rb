# frozen_string_literal: true

require_relative "aes_bridge/version"
require_relative "aes_bridge/cbc"
require_relative "aes_bridge/gcm"
require_relative "aes_bridge/legacy"


module AesBridge

  # Encrypts a string using AES-GCM.
  #
  # @param data [String] The plaintext to encrypt.
  # @param passphrase [String] The passphrase from which to derive the encryption key.
  # @return [String] The encrypted, base64-encoded string.
  def self.encrypt(plaintext, passphrase)
    self.encrypt_gcm(plaintext, passphrase)
  end

  # Decrypts a base64-encoded string encrypted with AES-GCM and verifies its integrity using an authentication tag.
  #
  # @param data [String] The base64-encoded ciphertext to decrypt.
  # @param passphrase [String] The passphrase from which to derive the encryption and HMAC keys.
  # @return [String] The decrypted plaintext.
  def self.decrypt(data, passphrase)
    self.decrypt_gcm(data, passphrase)
  end
end
