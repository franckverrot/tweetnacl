require 'test_helper'

class TweetNaClCryptoSecretboxOpenTest < MiniTest::Test
  def test_crypto_box_secretbox_open_require_cipher_to_decrypt
    set = false
    begin
      TweetNaCl.crypto_secretbox_open(nil, nil, nil)
    rescue Exception => e
      set = true
    end
    assert set, "A cipher is required"
  end

  def test_crypto_secretbox_open_require_secret_key
    set = false
    begin
      TweetNaCl.crypto_secretbox_open("foo", "foo", nil)
    rescue ArgumentError => e
      set = true
    end
    assert set, "A secret key is required"
  end

  def test_crypto_secretbox_open_nonce_not_correct_length
    set = false
    begin
      TweetNaCl.crypto_secretbox_open("foo", "bar", "k")
    rescue ArgumentError => e
      set = true
    end
    assert set, "Incorrect nonce length should have raised ArgumentError"
  end
end
