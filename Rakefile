# frozen_string_literal: true

# require "bundler/gem_tasks"
# task default: %i[]


# Rakefile
require 'rake/testtask'

Rake::TestTask.new do |t|
  t.libs << 'test'
  t.test_files = FileList['test/**/*_test.rb']
  t.warning = true
  t.verbose = true
end

task default: :test
