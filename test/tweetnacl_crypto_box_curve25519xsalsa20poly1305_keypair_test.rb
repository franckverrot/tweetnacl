require 'test_helper'

class TweetNaClCryptoBoxCurve25519XSalsa20Poly1305KeyPairTest < MiniTest::Test
  def test_generate_a_keypair
    pk, sk = TweetNaCl.crypto_box_curve25519xsalsa20poly1305_keypair

    assert_equal 32, pk.length
    assert_equal 32, sk.length
  end
end
