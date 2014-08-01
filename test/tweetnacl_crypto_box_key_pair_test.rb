require 'test_helper'

class TweetNaClCryptoBoxKeyPairTest < MiniTest::Test
  def setup
    @t = TweetNaCl.new
  end

  def teardown; end

  def test_generate_a_keypair
    pk, sk = @t.crypto_box_keypair

    assert_equal 32, pk.length
    assert_equal 32, sk.length
  end
end
