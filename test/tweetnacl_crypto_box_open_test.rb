require 'test_helper'

class TweetNaClCryptoBoxOpenTest < MiniTest::Test
  def test_crypto_box_open_require_cipher_to_decrypt
    assert_raises(ArgumentError) { TweetNaCl.crypto_box_open(nil, nil, nil, nil) }
  end

  def test_crypto_box_open_require_public_key
    assert_raises(ArgumentError) { TweetNaCl.crypto_box_open("foo", nil, "foo", nil) }
  end

  def test_crypto_box_open_require_secret_key
    assert_raises(ArgumentError) { TweetNaCl.crypto_box_open("foo", "foo", "foo", nil) }
  end

  def test_crypto_box_open_nonce_not_correct_length
    assert_raises(ArgumentError) { TweetNaCl.crypto_box("foo", "bar", "pk", "sk") }
  end
end
