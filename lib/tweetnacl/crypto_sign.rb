module TweetNaCl
  class CryptoSign
    attr_reader :keypair, :signed_message, :message

    def initialize(keypair = KeyPair.new(TweetNaCl.crypto_sign_keypair))
      @keypair = keypair
    end

    def sign(message)
      @signed_message = TweetNaCl.crypto_sign(message, @keypair.secret_key)
    end

    def verify(message)
      @message = TweetNaCl.crypto_sign_open(message.signed_message, @keypair.public_key)
    end
  end
end
