require 'tweetnacl'
require 'minitest/autorun'
require 'minitest/assertions'

class String
  def hd
    self.each_byte.map { |b| sprintf("%X", b) }.join
  end
end
