# frozen_string_literal: true

require 'openssl'
require 'mutex_m'

module AesBridge
  class Error < StandardError; end

  # Converts data to bytes. If data is a String, it's converted to binary encoding.
  # Otherwise, it's returned as is.
  #
  # @param data [String, Object] The data to convert.
  # @return [String] The data in binary encoding, or the original data if not a String.
  def self.to_bytes(data)
    data.is_a?(String) ? data.b : data
  end

  # A class for generating cryptographically secure random bytes using a nonce.
  class RandomGenerator
    # Class variable to store the nonce.
    @@nonce = nil
    # Mutex for safe access to nonce in a multi-threaded environment.
    @@nonce_mutex = Mutex.new

    # Updates the nonce
    def self.update_nonce
      @@nonce_mutex.synchronize do
        if @@nonce.nil?
          # Generate a random starting value for the nonce.
          nonce = OpenSSL::Random.random_bytes(8)
          @@nonce = nonce.unpack('Q>').first
        end
        @@nonce += 1
      end
    end

    # Generates cryptographically secure random bytes.
    #
    # @param size [Integer] The length of the random byte string to generate.
    # @return [String] A cryptographically secure random byte string of length `size`.
    def generate_random_bytes(size)
      self.class.update_nonce

      nonce_value = nil
      @@nonce_mutex.synchronize do
        nonce_value = @@nonce
      end

      nonce_bytes = [nonce_value].pack('Q>')

      # Generate random bytes before and after the nonce to increase entropy.
      data = OpenSSL::Random.random_bytes(13) + nonce_bytes + OpenSSL::Random.random_bytes(13)
      OpenSSL::Digest::SHA256.digest(data)[0, size]
    end
  end

  # Generates a cryptographically secure random string of a given size.
  #
  # @param size [Integer] The length of the random string to generate.
  # @return [String] A cryptographically secure random string of length `size`.
  def self.generate_random(size)
    generator = RandomGenerator.new
    generator.generate_random_bytes(size)
  end
end
