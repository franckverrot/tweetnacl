module TweetNaCl
  class CryptoBox
    attr_reader :keypair

    def initialize(keypair = KeyPair.new)
      @keypair = keypair
    end
  end
end
