require 'test_helper'

class TweetNaClCryptoSignKeyPairTest < MiniTest::Test
  def test_generate_a_keypair
    pk, sk = TweetNaCl.crypto_sign_keypair

    assert_equal 32, pk.length
    assert_equal 64, sk.length
  end
end
