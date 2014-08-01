require 'rake/extensiontask'
spec = Gem::Specification.load('tweetnacl.gemspec')
Rake::ExtensionTask.new('tweetnacl', spec) do |ext|
  ext.source_pattern = "*.{c,h}"
end

require 'rake/testtask'
Rake::TestTask.new do |t|
  t.libs << "test"
  t.pattern = "test/*_test.rb"
  t.verbose = true
  t.warning = true
end

task :default => :full

desc "Run the full spec suite"
task :full => ["clean", "compile", "test"]
