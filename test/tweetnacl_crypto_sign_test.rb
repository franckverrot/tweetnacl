require 'test_helper'

class TweetNaClCryptoSignTest < MiniTest::Test
  def test_crypto_sign
    input = "hello world"
    expected_cipher = "948CC9261D32D928AA3E5321F54EFE80B19AA8DE985A2FE5F0CDA0669FE253499051F8E54F0F4767646ECA13D75CCF49AD4802536331B3AB8BF427A5D43CA868656C6C6F20776F726C64"
    pk = "\x8B\x1B\xA8\xF3\xCB\xD6\x2C\x4F\x40\xAA\x96\x53\x06\x5B\x2F\x02\x52\x4B\x35\x34\x39\x32\xE2\x02\xC0\xA7\x5F\x9D\x4B\x5B\x07\xCF"
    sk = "\xC3\x51\x77\xB0\x8D\x93\xC3\x09\x37\x06\xCA\x65\x98\x9A\x53\x80\x92\xA4\x9C\x9B\x7A\x57\x19\x6D\xF8\x01\x5C\x0F\x81\x6E\xA3\xEF\x8B\x1B\xA8\xF3\xCB\xD6\x2C\x4F\x40\xAA\x96\x53\x06\x5B\x2F\x02\x52\x4B\x35\x34\x39\x32\xE2\x02\xC0\xA7\x5F\x9D\x4B\x5B\x07\xCF"

    cipher = TweetNaCl.crypto_sign(input, sk)

    output = TweetNaCl.crypto_sign_open(cipher, pk)

    assert_equal input, output
    assert_equal expected_cipher, cipher.hd
  end

  def test_crypto_sign_require_message_to_sign
    assert_raises(ArgumentError) { TweetNaCl.crypto_sign(nil, nil) }
  end

  def test_crypto_sign_require_public_key
    assert_raises(ArgumentError) { TweetNaCl.crypto_sign("foo", nil) }
    assert_raises(ArgumentError) { TweetNaCl.crypto_sign("foo", "too_short_public_key") }
  end
end
