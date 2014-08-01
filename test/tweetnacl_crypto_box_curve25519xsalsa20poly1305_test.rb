require 'test_helper'

class TweetNaClCryptoBoxCurve25519XSalsa20Poly1305Test < MiniTest::Test
  def setup
    @t = TweetNaCl.new
  end

  def teardown; end

  def test_crypto_box_curve25519xsalsa20poly1305
    input = "hello world"
    nonce = "*" * 24
    expected_cipher = "0000000000000000FBC937C3F136E09FA8A45C58C15E801394F5BB74CE8D538FE3D726"
    pk = "\x60\xF0\x23\x07\xDF\xB6\x8B\xBB\x15\xE2\x92\x59\x05\x1B\x2D\xF8\xC8\x59\xDB\x5B\xDE\x97\xFA\xE8\x9B\x5F\xE5\x62\x63\x11\xD6\x56"
    sk = "\xBE\x38\x7C\x59\xD1\x81\x0B\xCC\x8E\xD8\x90\xDB\x3D\xF9\x80\x63\x9E\xD2\x54\x44\xFB\x4D\xD1\x92\xB6\xC6\x75\x53\xF9\x76\x9F\xCF"

    cipher = @t.crypto_box_curve25519xsalsa20poly1305(input, nonce, pk, sk)

    output = @t.crypto_box_curve25519xsalsa20poly1305_open(cipher, nonce, pk, sk)

    assert_equal input, output
    assert_equal expected_cipher, cipher.hd
  end

  def test_crypto_box_curve25519xsalsa20poly1305_require_message_to_cipher
    set = false
    begin
      @t.crypto_box_curve25519xsalsa20poly1305(nil, "bar", "pk", "sk")
    rescue ArgumentError => e
      set = true
    end
    assert set, "A message is required"
  end

  def test_crypto_box_curve25519xsalsa20poly1305_require_public_key
    set = false
    begin
      @t.crypto_box_curve25519xsalsa20poly1305("foo", "bar", nil, "sk")
    rescue ArgumentError => e
      set = true
    end
    assert set, "A public key is required"
  end

  def test_crypto_box_curve25519xsalsa20poly1305_require_secret_key
    set = false
    begin
      @t.crypto_box_curve25519xsalsa20poly1305("foo", "bar", "pk", nil)
    rescue ArgumentError => e
      set = true
    end
    assert set, "A secret key is required"
  end

  def test_crypto_box_curve25519xsalsa20poly1305_nonce_not_correct_length
    set = false
    begin
      @t.crypto_box_curve25519xsalsa20poly1305("foo", "bar", "pk", "sk")
    rescue ArgumentError => e
      set = true
    end
    assert set, "Incorrect nonce length should have raised ArgumentError"
  end
end
