# coding: utf-8
$:<< 'lib'
Gem::Specification.new do |spec|
  spec.name     = "tweetnacl"
  spec.version  = "0.3.0"
  spec.authors  = ["Franck Verrot"]
  spec.email    = ["franck@verrot.fr"]
  spec.homepage = "https://github.com/franckverrot/tweetnacl"
  spec.license  = "GPLv3"

  spec.summary     = "TweetNaCl for Ruby"
  spec.description = "TweetNaCl is a C-extension built on top of the official TweetNaCl distribution"
  spec.files       = `git ls-files -z`.split("\x0")

  spec.extensions << "ext/tweetnacl/extconf.rb"

  spec.test_files    = spec.files.grep(%r{^(test|spec|features)/})
  spec.require_paths = ["lib"]

  spec.add_development_dependency "rake-compiler"
  spec.add_development_dependency "bundler", "~> 1.5"
  spec.add_development_dependency "rake"
  spec.add_development_dependency "minitest"
end
