require 'tweetnacl'
require 'tweet_na_cl'
require 'tweetnacl/crypto_sign'
require 'tweetnacl/crypto_box'
require 'tweetnacl/key_pair'
require 'minitest/autorun'
require 'minitest/assertions'
require 'pp'

class String
  def hd
    self.each_byte.map { |b| sprintf("%X", b) }.join
  end
end

ValidNonce = "x" * 24
