require 'test_helper'

module TweetNaCl
  class KeyPairTest < MiniTest::Test
    def test_initializes_with_a_key_pair
      kp = TweetNaCl::KeyPair.new([nil,nil])
      assert_respond_to kp, :public_key
      assert_respond_to kp, :secret_key
    end

    def test_can_generate_a_keypair_if_none_provided
      kp = TweetNaCl::KeyPair.new
      assert kp.public_key
      assert kp.secret_key
    end
  end
end
