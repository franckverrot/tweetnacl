Gem::Specification.new do |s|
  s.name    = "tweetnacl"
  s.version = "0.0.1"
  s.summary = "TweetNaCl for Ruby"
  s.description = "TweetNaCl is a C-extension built on top of the official TweetNaCl distribution"
  s.author  = "Franck Verrot"

  s.files = Dir.glob("ext/**/*.{c,rb}") +
            Dir.glob("lib/**/*.rb")

  s.extensions << "ext/tweetnacl/extconf.rb"

  s.add_development_dependency "rake-compiler"
end
