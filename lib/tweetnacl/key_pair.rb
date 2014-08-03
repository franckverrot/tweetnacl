module TweetNaCl
  class KeyPair
    attr_reader :public_key, :secret_key

    def initialize(keypair = TweetNaCl.crypto_box_keypair)
      @public_key, @secret_key = keypair
    end
  end
end
