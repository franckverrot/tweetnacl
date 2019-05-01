require 'test_helper'

class TweetNaClCryptoBoxTest < MiniTest::Test
  def test_crypto_box
    input = "hello world"
    nonce = "*" * 24
    expected_cipher = "FBC937C3F136E09FA8A45C58C15E801394F5BB74CE8D538FE3D726"
    pk = "\x60\xF0\x23\x07\xDF\xB6\x8B\xBB\x15\xE2\x92\x59\x05\x1B\x2D\xF8\xC8\x59\xDB\x5B\xDE\x97\xFA\xE8\x9B\x5F\xE5\x62\x63\x11\xD6\x56"
    sk = "\xBE\x38\x7C\x59\xD1\x81\x0B\xCC\x8E\xD8\x90\xDB\x3D\xF9\x80\x63\x9E\xD2\x54\x44\xFB\x4D\xD1\x92\xB6\xC6\x75\x53\xF9\x76\x9F\xCF"

    cipher = TweetNaCl.crypto_box(input, nonce, pk, sk)

    output = TweetNaCl.crypto_box_open(cipher, nonce, pk, sk)

    assert_equal input, output
    assert_equal expected_cipher, cipher.hd
  end

  def test_crypto_box_require_message_to_cipher
    assert_raises(ArgumentError) { TweetNaCl.crypto_box(nil, "bar", "pk", "sk") }
  end

  def test_crypto_box_require_public_key
    assert_raises(ArgumentError) { TweetNaCl.crypto_box("foo", "bar", nil, "sk") }
  end

  def test_crypto_box_require_secret_key
    assert_raises(ArgumentError) { TweetNaCl.crypto_box("foo", "bar", "pk", nil) }
  end

  def test_crypto_box_nonce_not_correct_length
    assert_raises(ArgumentError) { TweetNaCl.crypto_box("foo", "bar", "pk", "sk") }
  end

  def test_crypto_box_salsa_rounds_set_with_nil_argument
    assert_raises(ArgumentError) { TweetNaCl.salsa_rounds = nil }
  end

  def test_crypto_box_salsa_rounds_get_set
    assert_equal(TweetNaCl.salsa_rounds, TweetNaCl::DEFAULT_SALSA_ROUNDS)
    TweetNaCl.salsa_rounds = 42
    assert_equal(TweetNaCl.salsa_rounds, 42)
  ensure
    TweetNaCl.salsa_rounds = TweetNaCl::DEFAULT_SALSA_ROUNDS
  end

  def test_crypto_box_salsa_rounds_get
  end
end
