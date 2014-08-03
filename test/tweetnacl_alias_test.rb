require 'test_helper'

class TweetNaClAliasTest < MiniTest::Test
  def test_crypto_box_aliased_curve25519xsalsa20poly1305
    assert_equal TweetNaCl.method(:crypto_box),      TweetNaCl.method(:crypto_box_curve25519xsalsa20poly1305)
    assert_equal TweetNaCl.method(:crypto_box_open), TweetNaCl.method(:crypto_box_curve25519xsalsa20poly1305_open)
  end

  def test_crypto_secretbox_aliased_xsalsa20poly1305
    assert_equal TweetNaCl.method(:crypto_secretbox),      TweetNaCl.method(:crypto_secretbox_xsalsa20poly1305)
    assert_equal TweetNaCl.method(:crypto_secretbox_open), TweetNaCl.method(:crypto_secretbox_xsalsa20poly1305_open)
  end
end
