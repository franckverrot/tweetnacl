require 'tweetnacl'
require 'tweetnacl/crypto_box'
require 'tweetnacl/key_pair'
require 'minitest/autorun'
require 'minitest/assertions'

class String
  def hd
    self.each_byte.map { |b| sprintf("%X", b) }.join
  end
end
