require 'test_helper'

class TweetNaClCryptoBoxOpenTest < MiniTest::Test
  def test_crypto_box_open_require_cipher_to_decrypt
    assert_raises(ArgumentError) { TweetNaCl.crypto_box_open(nil, nil, nil, nil) }
  end

  def test_crypto_box_open_nonce_not_correct_length
    assert_raises(ArgumentError) { TweetNaCl.crypto_box("foo", "bar", "pk", "sk") }
  end

  def test_crypto_box_open_require_matching_public_and_secret_keys
    assert_raises(RuntimeError) { TweetNaCl.crypto_box_open("foo", "x"*24, "x"*32, "x"*32) }
  end

  def test_crypto_box_open_require_public_key
    assert_raises(ArgumentError) { TweetNaCl.crypto_box_open("foo", "x"*24, "foo", nil) }
  end

  def test_crypto_box_open_require_secret_key
    assert_raises(ArgumentError) { TweetNaCl.crypto_box_open("foo", "x"*24, "foo", nil) }
  end
end
