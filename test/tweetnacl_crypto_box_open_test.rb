require 'test_helper'

class TweetNaClCryptoBoxOpenTest < MiniTest::Test
  def setup
    @t = TweetNaCl.new
  end

  def teardown; end

  def test_crypto_box_open_require_cipher_to_decrypt
    set = false
    begin
      @t.crypto_box_open(nil, nil, nil, nil)
    rescue Exception => e
      set = true
    end
    assert set, "A cipher is required"
  end

  def test_crypto_box_open_require_public_key
    set = false
    begin
      @t.crypto_box_open("foo", nil, "foo", nil)
    rescue ArgumentError => e
      set = true
    end
    assert set, "A public key is required"
  end

  def test_crypto_box_open_require_secret_key
    set = false
    begin
      @t.crypto_box_open("foo", "foo", "foo", nil)
    rescue ArgumentError => e
      set = true
    end
    assert set, "A secret key is required"
  end

  def test_crypto_box_open_nonce_not_correct_length
    set = false
    begin
      @t.crypto_box("foo", "bar", "pk", "sk")
    rescue ArgumentError => e
      set = true
    end
    assert set, "Incorrect nonce length should have raised ArgumentError"
  end
end
