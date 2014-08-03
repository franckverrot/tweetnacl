require 'test_helper'

class TweetNaClCryptoSignOpenTest < MiniTest::Test
  def test_crypto_sign_open_require_message_to_verify
    assert_raises(ArgumentError) { TweetNaCl.crypto_sign_open(nil, nil) }
  end

  def test_crypto_sign_open_require_public_key
    assert_raises(ArgumentError) { TweetNaCl.crypto_sign_open("foo", nil) }
    assert_raises(ArgumentError) { TweetNaCl.crypto_sign_open("foo", "too_short_public_key") }
  end
end
