# coding: utf-8
$:<< 'lib'
Gem::Specification.new do |spec|
  spec.name     = "tweetnacl"
  spec.version  = "1.0.0"
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

  spec.post_install_message = <<END_OF_MESSAGE
[TweetNaCl] Breaking change in v1.0.0!

A breaking change has been introduced to `crypto_box` and `crypto_secretbox`
that makes ciphers differ.  The first 64 bits are always empty and have been
dropped from the cipher output.

This causes differences like:

-    expected_cipher = "0000000000000000FBC937C3F136E09FA8A45C58C15E801394F5BB74CE8D538FE3D726"
+    expected_cipher =                 "FBC937C3F136E09FA8A45C58C15E801394F5BB74CE8D538FE3D726"

You might need to go through all persisted ciphers and change these values.

If you have more questions, please file a ticket!  Thanks!
END_OF_MESSAGE

end
