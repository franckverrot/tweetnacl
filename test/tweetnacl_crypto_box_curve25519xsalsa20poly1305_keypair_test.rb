require 'test_helper'

class TweetNaClCryptoBoxCurve25519XSalsa20Poly1305KeyPairTest < MiniTest::Test
  def setup
    @t = TweetNaCl.new
  end

  def teardown; end

  def test_generate_a_keypair
    pk, sk = @t.crypto_box_curve25519xsalsa20poly1305_keypair

    assert_equal 32, pk.length
    assert_equal 32, sk.length
  end
end
