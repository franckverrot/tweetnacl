require 'test_helper'

class CryptoBoxTest < MiniTest::Test
  def test_initializes_with_a_keypair_object
    TweetNaCl::CryptoBox.new(Object.new)
  end

  def test_generate_a_keypair_object_if_none_provided
    TweetNaCl::CryptoBox.new
    assert :did_not_raise, "A CryptoBox object can be created without arguments"
  end
end
