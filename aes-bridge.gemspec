# frozen_string_literal: true

require_relative "lib/aes_bridge/version"

Gem::Specification.new do |spec|
  spec.name = "aes-bridge"
  spec.version = AesBridge::VERSION
  spec.authors = ["Andrey Izman"]
  spec.email = ["izmanw@gmail.com"]
  spec.license = "MIT"

  spec.summary = "AesBridge Ruby implementation of cross-language AES encryption library"
  spec.description = "AesBridge is a modern, secure, and cross-language AES encryption library. It offers a unified interface for encrypting and decrypting data across multiple programming languages."
  spec.homepage = "https://github.com/mervick/aes-bridge-ruby"
  spec.required_ruby_version = ">= 2.5.0"

  spec.metadata["allowed_push_host"] = "https://rubygems.org"
  spec.metadata["homepage_uri"] = spec.homepage
  spec.metadata["source_code_uri"] = spec.homepage

  # Specify which files should be added to the gem when it is released.
  # The `git ls-files -z` loads the files in the RubyGem that have been added into git.
  spec.files = Dir.chdir(File.expand_path(__dir__)) do
    `git ls-files -z`.split("\x0").reject do |f|
      (f == __FILE__) || f.match(%r{\A(?:(?:bin|test|spec|features)/|\.(?:git|travis|circleci)|appveyor)})
    end
  end
  spec.bindir = "exe"
  spec.executables = spec.files.grep(%r{\Aexe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  spec.add_dependency "openssl"
  spec.add_dependency "mutex_m"
  spec.add_dependency "json"
end
