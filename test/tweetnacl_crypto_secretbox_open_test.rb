require 'test_helper'

class TweetNaClCryptoSecretboxOpenTest < MiniTest::Test
  def test_crypto_box_secretbox_open_require_cipher_to_decrypt
    assert_raises(ArgumentError) { TweetNaCl.crypto_secretbox_open(nil, nil, nil) }
  end

  def test_crypto_secretbox_open_require_secret_key
    assert_raises(ArgumentError) { TweetNaCl.crypto_secretbox_open("foo", "foo", nil) }
  end

  def test_crypto_secretbox_open_nonce_not_correct_length
    assert_raises(ArgumentError) { TweetNaCl.crypto_secretbox_open("foo", "bar", "k") }
  end
end
