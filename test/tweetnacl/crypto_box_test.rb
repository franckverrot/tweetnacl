require 'test_helper'

class CryptoBoxTest < MiniTest::Test
  def test_initializes_with_a_keypair_object
    TweetNaCl::CryptoBox.new(Object.new)
  end

  def test_generate_a_keypair_object_if_none_provided
    TweetNaCl::CryptoBox.new
    assert :did_not_raise, "A CryptoBox object can be created without arguments"
  end

  def test_can_box_a_message_with_a_nonce
    message = "hello world"
    nonce = ValidNonce
    nonce = "*" * 24

    sender , receiver = TweetNaCl::KeyPair.new, TweetNaCl::KeyPair.new

    encryption_keypair = TweetNaCl::KeyPair.new([receiver.public_key, sender.secret_key])
    encrypted_box      = TweetNaCl::CryptoBox.new(encryption_keypair)
    encrypted_box.close(message, nonce)

    decryption_keypair = TweetNaCl::KeyPair.new([sender.public_key, receiver.secret_key])
    decryption_box     = TweetNaCl::CryptoBox.new(decryption_keypair)
    decryption_box.open(encrypted_box, nonce)

    assert_equal message, decryption_box.message
  end
end
