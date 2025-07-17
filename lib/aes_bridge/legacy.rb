# frozen_string_literal: true

require 'openssl'
require 'base64'

module AesBridge
  BLOCK_SIZE = 16
  KEY_LEN = 32
  IV_LEN = 16

  # Encrypts the given plaintext using the legacy AES Everywhere format with AES-256-CBC.
  # A random salt is generated and used along with the passphrase to derive the encryption key and IV.
  #
  # @param raw [String] The plaintext to encrypt.
  # @param passphrase [String] The passphrase used for key derivation.
  # @return [String] The encrypted data, encoded in base64 format, with a "Salted__" prefix.
  def self.encrypt_legacy(raw, passphrase)
    salt = OpenSSL::Random.random_bytes(8)
    key, iv = derive_key_and_iv(passphrase, salt)

    cipher = OpenSSL::Cipher.new('AES-256-CBC')
    cipher.encrypt
    cipher.key = key
    cipher.iv = iv

    # fix empty plaintext encryption
    if raw.bytesize > 0
      encrypted = cipher.update(raw) + cipher.final
    else
      encrypted = ''
    end

    result = "Salted__" + salt + encrypted
    Base64.strict_encode64(result)
  end

  # Decrypts the given ciphertext using the legacy AES Everywhere format with AES-256-CBC.
  # The ciphertext must have a "Salted__" prefix.
  #
  # @param enc [String] The base64-encoded ciphertext to decrypt.
  # @param passphrase [String] The passphrase used for key derivation.
  # @return [String] The decrypted plaintext.
  def self.decrypt_legacy(enc, passphrase)
    data = Base64.decode64(enc)
    raise 'Invalid OpenSSL header' unless data.start_with?('Salted__')

    salt = data[8, 8]
    key, iv = derive_key_and_iv(passphrase, salt)

    cipher = OpenSSL::Cipher.new('AES-256-CBC')
    cipher.decrypt
    cipher.key = key
    cipher.iv = iv
    ciphertext = data[16..]

    # fix empty plaintext decryption
    if ciphertext.bytesize == 0
      return ''
    end
    cipher.update(ciphertext) + cipher.final
  end

  # Derives an AES key and initialization vector (IV) from a passphrase and salt using an iterative hashing process.
  #
  # @param passphrase [String] The passphrase used for key derivation.
  # @param salt [String] The salt value to add randomness to the key derivation process.
  # @return [Array<String>] An array containing the derived AES key and IV.
  def self.derive_key_and_iv(passphrase, salt)
    d = +''
    prev = +''
    while d.bytesize < KEY_LEN + IV_LEN
      prev = OpenSSL::Digest::MD5.digest(prev + passphrase.b + salt.b)
      d << prev
    end
    [d[0, KEY_LEN], d[KEY_LEN, IV_LEN]]
  end
end
