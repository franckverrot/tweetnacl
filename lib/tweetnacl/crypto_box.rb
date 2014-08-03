module TweetNaCl
  class CryptoBox
    attr_reader :keypair, :cipher, :message

    def initialize(keypair = KeyPair.new)
      @keypair = keypair
    end

    def close(message, nonce)
      @cipher = TweetNaCl.crypto_box(message, nonce, @keypair.public_key, @keypair.secret_key)
    end

    def open(box, nonce)
      @message = TweetNaCl.crypto_box_open(box.cipher, nonce, @keypair.public_key, @keypair.secret_key)
    end
  end
end
