require 'test_helper'

class TweetNaClCryptoBoxKeyPairTest < MiniTest::Test
  def test_generate_a_keypair
    pk, sk = TweetNaCl.crypto_box_keypair

    assert_equal 32, pk.length
    assert_equal 32, sk.length
  end
end
