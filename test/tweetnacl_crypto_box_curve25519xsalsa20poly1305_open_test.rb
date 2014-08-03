require 'test_helper'

class TweetNaClCryptoBoxCurve25519XSalsa20Poly1305OpenTest < MiniTest::Test
  def test_crypto_box_curve25519xsalsa20poly1305_open_require_cipher_to_decrypt
    set = false
    begin
      TweetNaCl.crypto_box_curve25519xsalsa20poly1305_open(nil, nil, nil, nil)
    rescue Exception => e
      set = true
    end
    assert set, "A cipher is required"
  end

  def test_crypto_box_curve25519xsalsa20poly1305_open_require_public_key
    set = false
    begin
      TweetNaCl.crypto_box_curve25519xsalsa20poly1305_open("foo", nil, "foo", nil)
    rescue ArgumentError => e
      set = true
    end
    assert set, "A public key is required"
  end

  def test_crypto_box_curve25519xsalsa20poly1305_open_require_secret_key
    set = false
    begin
      TweetNaCl.crypto_box_curve25519xsalsa20poly1305_open("foo", "foo", "foo", nil)
    rescue ArgumentError => e
      set = true
    end
    assert set, "A secret key is required"
  end

  def test_crypto_box_curve25519xsalsa20poly1305_open_nonce_not_correct_length
    set = false
    begin
      TweetNaCl.crypto_box_curve25519xsalsa20poly1305_open("foo", "bar", "pk", "sk")
    rescue ArgumentError => e
      set = true
    end
    assert set, "Incorrect nonce length should have raised ArgumentError"
  end
end
