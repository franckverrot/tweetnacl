require 'test_helper'

class TweetNaClCryptoSecretTest < MiniTest::Test
  def test_crypto_secretbox
    input = "hello world"
    nonce = "*" * 24
    expected_cipher = "00000000000000002A9612E32BCC4E836B3D46463B7C1546EA8BC752A1B6AE6DE"
    k = "\x60\xF0\x23\x07\xDF\xB6\x8B\xBB\x15\xE2\x92\x59\x05\x1B\x2D\xF8\xC8\x59\xDB\x5B\xDE\x97\xFA\xE8\x9B\x5F\xE5\x62\x63\x11\xD6\x56"

    cipher = TweetNaCl.crypto_secretbox(input, nonce, k)

    output = TweetNaCl.crypto_secretbox_open(cipher, nonce, k)

    assert_equal input, output
    assert_equal expected_cipher, cipher.hd
  end

  def test_crypto_secretbox_require_message_to_cipher
    set = false
    begin
      TweetNaCl.crypto_secretbox(nil, "bar", "k")
    rescue ArgumentError => e
      set = true
    end
    assert set, "A message is required"
  end

  def test_crypto_secretbox_require_secret_key
    set = false
    begin
      TweetNaCl.crypto_secretbox("foo", "bar", "k")
    rescue ArgumentError => e
      set = true
    end
    assert set, "A secret key is required"
  end

  def test_crypto_secretbox_nonce_not_correct_length
    set = false
    begin
      TweetNaCl.crypto_secretbox("foo", "bar", "k")
    rescue ArgumentError => e
      set = true
    end
    assert set, "Incorrect nonce length should have raised ArgumentError"
  end
end
