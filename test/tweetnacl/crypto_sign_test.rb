require 'test_helper'

class CryptoSignTest < MiniTest::Test
  def test_initializes_with_a_keypair_object
    TweetNaCl::CryptoSign.new(Object.new)
  end

  def test_generate_a_keypair_object_if_none_provided
    TweetNaCl::CryptoSign.new
    assert :did_not_raise, "A CryptoSign object can be created without arguments"
  end

  def test_can_sign_a_message
    message = "hello world"

    sender_keypair = TweetNaCl::KeyPair.new(TweetNaCl.crypto_sign_keypair)
    signed_message = TweetNaCl::CryptoSign.new(sender_keypair)
    signed_message.sign(message)

    verified_message = TweetNaCl::CryptoSign.new(sender_keypair)
    verified_message.verify(signed_message)

    assert_equal message, verified_message.message
  end
end
