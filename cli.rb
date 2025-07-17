#!/usr/bin/env ruby
# frozen_string_literal: true

require 'optparse'
require_relative 'lib/aes_bridge'


# Custom exception for argument errors
class ValueError < StandardError; end

options = {}
OptionParser.new do |opts|
  opts.banner = "Usage: #{File.basename($PROGRAM_NAME)} [options] <action>"
  opts.separator ''
  opts.separator 'Actions:'
  opts.separator '  encrypt    Encrypt data'
  opts.separator '  decrypt    Decrypt data'
  opts.separator ''
  opts.separator 'Specific options:'

  opts.on('--mode MODE', %w[cbc gcm legacy], 'Encryption mode (cbc, gcm, legacy)') do |mode|
    options[:mode] = mode
  end

  opts.on('--data DATA', 'Data to encrypt (UTF-8 string) or decrypt (base64 string)') do |data|
    options[:data] = data
  end

  opts.on('--passphrase PASSPHRASE', 'Passphrase for key derivation') do |passphrase|
    options[:passphrase] = passphrase
  end

  opts.on('--b64', 'Accept base64 encoded input and returns base64 encoded output') do
    options[:b64] = true
  end

  opts.on('-h', '--help', 'Prints this help') do
    puts opts
    exit
  end
end.parse!

action = ARGV.shift

unless %w[encrypt decrypt].include?(action)
  warn 'Error: Action must be "encrypt" or "decrypt".'
  puts OptionParser.new.help
  exit 1
end

%i[mode data passphrase].each do |arg|
  unless options[arg]
    warn "Error: Missing required option --#{arg}."
    puts OptionParser.new.help
    exit 1
  end
end

begin
  data_input = options[:data]
  result = nil

  case action
  when 'encrypt'
    data_to_process = options[:b64] ? Base64.strict_decode64(data_input) : data_input
    case options[:mode]
    when 'cbc'
      result = AesBridge.encrypt_cbc(data_to_process, options[:passphrase])
    when 'gcm'
      result = AesBridge.encrypt_gcm(data_to_process, options[:passphrase])
    when 'legacy'
      result = AesBridge.encrypt_legacy(data_to_process, options[:passphrase])
    end
  when 'decrypt'
    case options[:mode]
    when 'cbc'
      decrypted = AesBridge.decrypt_cbc(data_input, options[:passphrase])
      result = options[:b64] ? Base64.strict_encode64(decrypted) : decrypted.force_encoding('UTF-8')
    when 'gcm'
      decrypted = AesBridge.decrypt_gcm(data_input, options[:passphrase])
      result = options[:b64] ? Base64.strict_encode64(decrypted) : decrypted.force_encoding('UTF-8')
    when 'legacy'
      decrypted = AesBridge.decrypt_legacy(data_input, options[:passphrase])
      result = options[:b64] ? Base64.strict_encode64(decrypted) : decrypted.force_encoding('UTF-8')
    end
  end

  puts result

rescue ValueError => e
  warn "Error: #{e.message}"
  exit 1
rescue StandardError => e
  warn "An unexpected error occurred: #{e.message}"
  exit 1
end