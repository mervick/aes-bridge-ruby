# test/aes_bridge_test.rb
require 'minitest/autorun'
require 'json'
require 'unicode_utils'
require_relative '../lib/aes_bridge'

class AesBridgeTest < Minitest::Test
end

def add_test(name, &block)
  AesBridgeTest.define_method(name, &block)
end

def load_dynamic_tests
  test_data = JSON.parse(File.read('test/test_data.json'))

  def encrypt_cbc_not_empty(value)
    -> {
      encrypted = AesBridge.encrypt_cbc(value, value)
      refute_empty encrypted, 'Encryption result should not be empty'
    }
  end

  def encrypt_gcm_not_empty(value)
    -> {
      encrypted = AesBridge.encrypt_gcm(value, value)
      refute_empty encrypted, 'Encryption result should not be empty'
    }
  end

  def encrypt_legacy_not_empty(value)
    -> {
      encrypted = AesBridge.encrypt_legacy(value, value)
      refute_empty encrypted, 'Encryption result should not be empty'
    }
  end

  def encrypt_decrypt_cbc(value)
    -> {
      encrypted = AesBridge.encrypt_cbc(value, value)
      decrypted = AesBridge.decrypt_cbc(encrypted, value)
      assert_equal value, decrypted, 'CBC encryption/decryption failed'
    }
  end

  def encrypt_decrypt_gcm(value)
    -> {
      encrypted = AesBridge.encrypt_gcm(value, value)
      decrypted = AesBridge.decrypt_gcm(encrypted, value)
      assert_equal value, decrypted, 'GCM encryption/decryption failed'
    }
  end

  def encrypt_decrypt_legacy(value)
    -> {
      encrypted = AesBridge.encrypt_legacy(value, value)
      decrypted = AesBridge.decrypt_legacy(encrypted, value)
      assert_equal value, decrypted, 'Legacy encryption/decryption failed'
    }
  end

  def decrypt_cbc(encrypted, passphrase, result)
    -> {
      decrypted = AesBridge.decrypt_cbc(encrypted, passphrase)
      assert_equal result, decrypted, 'CBC decryption failed'
    }
  end

  def decrypt_gcm(encrypted, passphrase, result)
    -> {
      decrypted = AesBridge.decrypt_gcm(encrypted, passphrase)
      assert_equal result, decrypted, 'GCM decryption failed'
    }
  end

  def decrypt_legacy(encrypted, passphrase, result)
    -> {
      decrypted = AesBridge.decrypt_legacy(encrypted, passphrase)
      assert_equal result, decrypted, 'Legacy decryption failed'
    }
  end

  test_data['testdata']['plaintext']&.each_with_index do |text, idx|
    # val = text.encode('UTF-8')
    val = text.force_encoding("ASCII-8BIT")
    add_test("test_plaintext_encrypt_cbc_not_empty_#{idx}", &encrypt_cbc_not_empty(val))
    add_test("test_plaintext_encrypt_gcm_not_empty_#{idx}", &encrypt_gcm_not_empty(val))
    add_test("test_plaintext_encrypt_legacy_not_empty_#{idx}", &encrypt_legacy_not_empty(val))

    add_test("test_plaintext_encrypt_decrypt_cbc_#{idx}", &encrypt_decrypt_cbc(val))
    add_test("test_plaintext_encrypt_decrypt_gcm_#{idx}", &encrypt_decrypt_gcm(val))
    add_test("test_plaintext_encrypt_decrypt_legacy_#{idx}", &encrypt_decrypt_legacy(val))
  end

  test_data['testdata']['hex']&.each_with_index do |hex, idx|
    val = [hex].pack('H*')
    add_test("test_hex_encrypt_cbc_not_empty_#{idx}", &encrypt_cbc_not_empty(val))
    add_test("test_hex_encrypt_gcm_not_empty_#{idx}", &encrypt_gcm_not_empty(val))
    add_test("test_hex_encrypt_legacy_not_empty_#{idx}", &encrypt_legacy_not_empty(val))

    add_test("test_hex_encrypt_decrypt_cbc_#{idx}", &encrypt_decrypt_cbc(val))
    add_test("test_hex_encrypt_decrypt_gcm_#{idx}", &encrypt_decrypt_gcm(val))
    add_test("test_hex_encrypt_decrypt_legacy_#{idx}", &encrypt_decrypt_legacy(val))
  end

  test_data['decrypt']&.each_with_index do |test_case, idx|
    key = test_case['id'] || "case_#{idx}"
    passphrase = test_case['passphrase'].force_encoding("ASCII-8BIT")
    next unless passphrase

    plaintext = if test_case['plaintext']
                  test_case['plaintext'].force_encoding("ASCII-8BIT")
                  # test_case['plaintext'].encode('UTF-8')
                elsif test_case['hex']
                  [test_case['hex']].pack('H*')
                end

    next unless plaintext

    if test_case['encrypted-cbc']
      add_test("test_decrypt_cbc_#{key}", &decrypt_cbc(test_case['encrypted-cbc'], passphrase, plaintext))
    end
    if test_case['encrypted-gcm']
      add_test("test_decrypt_gcm_#{key}", &decrypt_gcm(test_case['encrypted-gcm'], passphrase, plaintext))
    end
    if test_case['encrypted-legacy']
      add_test("test_decrypt_legacy_#{key}", &decrypt_legacy(test_case['encrypted-legacy'], passphrase, plaintext))
    end
  end
end

load_dynamic_tests
