require 'test_helper'

class TweetNaClConstantsTest < MiniTest::Test
  def _const(const_name)
    TweetNaCl.const_get(const_name)
  end

  def test_constants
    assert_instance_of String,  _const("CRYPTO_AUTH_PRIMITIVE")
    assert_instance_of Integer, _const("CRYPTO_AUTH_BYTES")
    assert_instance_of Integer, _const("CRYPTO_AUTH_KEYBYTES")
    assert_instance_of String,  _const("CRYPTO_AUTH_IMPLEMENTATION")
    assert_instance_of String,  _const("CRYPTO_AUTH_VERSION")
    assert_instance_of Integer, _const("CRYPTO_AUTH_HMACSHA512256_TWEET_BYTES")
    assert_instance_of Integer, _const("CRYPTO_AUTH_HMACSHA512256_TWEET_KEYBYTES")
    assert_instance_of String,  _const("CRYPTO_AUTH_HMACSHA512256_TWEET_VERSION")
    assert_instance_of Integer, _const("CRYPTO_AUTH_HMACSHA512256_BYTES")
    assert_instance_of Integer, _const("CRYPTO_AUTH_HMACSHA512256_KEYBYTES")
    assert_instance_of String,  _const("CRYPTO_AUTH_HMACSHA512256_VERSION")
    assert_instance_of String,  _const("CRYPTO_AUTH_HMACSHA512256_IMPLEMENTATION")
    assert_instance_of String,  _const("CRYPTO_BOX_PRIMITIVE")
    assert_instance_of Integer, _const("CRYPTO_BOX_PUBLICKEYBYTES")
    assert_instance_of Integer, _const("CRYPTO_BOX_SECRETKEYBYTES")
    assert_instance_of Integer, _const("CRYPTO_BOX_BEFORENMBYTES")
    assert_instance_of Integer, _const("CRYPTO_BOX_NONCEBYTES")
    assert_instance_of Integer, _const("CRYPTO_BOX_ZEROBYTES")
    assert_instance_of Integer, _const("CRYPTO_BOX_BOXZEROBYTES")
    assert_instance_of String,  _const("CRYPTO_BOX_IMPLEMENTATION")
    assert_instance_of String,  _const("CRYPTO_BOX_VERSION")
    assert_instance_of Integer, _const("CRYPTO_BOX_CURVE25519XSALSA20POLY1305_TWEET_PUBLICKEYBYTES")
    assert_instance_of Integer, _const("CRYPTO_BOX_CURVE25519XSALSA20POLY1305_TWEET_SECRETKEYBYTES")
    assert_instance_of Integer, _const("CRYPTO_BOX_CURVE25519XSALSA20POLY1305_TWEET_BEFORENMBYTES")
    assert_instance_of Integer, _const("CRYPTO_BOX_CURVE25519XSALSA20POLY1305_TWEET_NONCEBYTES")
    assert_instance_of Integer, _const("CRYPTO_BOX_CURVE25519XSALSA20POLY1305_TWEET_ZEROBYTES")
    assert_instance_of Integer, _const("CRYPTO_BOX_CURVE25519XSALSA20POLY1305_TWEET_BOXZEROBYTES")
    assert_instance_of String,  _const("CRYPTO_BOX_CURVE25519XSALSA20POLY1305_TWEET_VERSION")
    assert_instance_of Integer, _const("CRYPTO_BOX_CURVE25519XSALSA20POLY1305_PUBLICKEYBYTES")
    assert_instance_of Integer, _const("CRYPTO_BOX_CURVE25519XSALSA20POLY1305_SECRETKEYBYTES")
    assert_instance_of Integer, _const("CRYPTO_BOX_CURVE25519XSALSA20POLY1305_BEFORENMBYTES")
    assert_instance_of Integer, _const("CRYPTO_BOX_CURVE25519XSALSA20POLY1305_NONCEBYTES")
    assert_instance_of Integer, _const("CRYPTO_BOX_CURVE25519XSALSA20POLY1305_ZEROBYTES")
    assert_instance_of Integer, _const("CRYPTO_BOX_CURVE25519XSALSA20POLY1305_BOXZEROBYTES")
    assert_instance_of String,  _const("CRYPTO_BOX_CURVE25519XSALSA20POLY1305_VERSION")
    assert_instance_of String,  _const("CRYPTO_BOX_CURVE25519XSALSA20POLY1305_IMPLEMENTATION")
    assert_instance_of String,  _const("CRYPTO_CORE_PRIMITIVE")
    assert_instance_of Integer, _const("CRYPTO_CORE_OUTPUTBYTES")
    assert_instance_of Integer, _const("CRYPTO_CORE_INPUTBYTES")
    assert_instance_of Integer, _const("CRYPTO_CORE_KEYBYTES")
    assert_instance_of Integer, _const("CRYPTO_CORE_CONSTBYTES")
    assert_instance_of String,  _const("CRYPTO_CORE_IMPLEMENTATION")
    assert_instance_of String,  _const("CRYPTO_CORE_VERSION")
    assert_instance_of Integer, _const("CRYPTO_CORE_SALSA20_TWEET_OUTPUTBYTES")
    assert_instance_of Integer, _const("CRYPTO_CORE_SALSA20_TWEET_INPUTBYTES")
    assert_instance_of Integer, _const("CRYPTO_CORE_SALSA20_TWEET_KEYBYTES")
    assert_instance_of Integer, _const("CRYPTO_CORE_SALSA20_TWEET_CONSTBYTES")
    assert_instance_of String,  _const("CRYPTO_CORE_SALSA20_TWEET_VERSION")
    assert_instance_of Integer, _const("CRYPTO_CORE_SALSA20_OUTPUTBYTES")
    assert_instance_of Integer, _const("CRYPTO_CORE_SALSA20_INPUTBYTES")
    assert_instance_of Integer, _const("CRYPTO_CORE_SALSA20_KEYBYTES")
    assert_instance_of Integer, _const("CRYPTO_CORE_SALSA20_CONSTBYTES")
    assert_instance_of String,  _const("CRYPTO_CORE_SALSA20_VERSION")
    assert_instance_of String,  _const("CRYPTO_CORE_SALSA20_IMPLEMENTATION")
    assert_instance_of Integer, _const("CRYPTO_CORE_HSALSA20_TWEET_OUTPUTBYTES")
    assert_instance_of Integer, _const("CRYPTO_CORE_HSALSA20_TWEET_INPUTBYTES")
    assert_instance_of Integer, _const("CRYPTO_CORE_HSALSA20_TWEET_KEYBYTES")
    assert_instance_of Integer, _const("CRYPTO_CORE_HSALSA20_TWEET_CONSTBYTES")
    assert_instance_of String,  _const("CRYPTO_CORE_HSALSA20_TWEET_VERSION")
    assert_instance_of Integer, _const("CRYPTO_CORE_HSALSA20_OUTPUTBYTES")
    assert_instance_of Integer, _const("CRYPTO_CORE_HSALSA20_INPUTBYTES")
    assert_instance_of Integer, _const("CRYPTO_CORE_HSALSA20_KEYBYTES")
    assert_instance_of Integer, _const("CRYPTO_CORE_HSALSA20_CONSTBYTES")
    assert_instance_of String,  _const("CRYPTO_CORE_HSALSA20_VERSION")
    assert_instance_of String,  _const("CRYPTO_CORE_HSALSA20_IMPLEMENTATION")
    assert_instance_of String,  _const("CRYPTO_HASHBLOCKS_PRIMITIVE")
    assert_instance_of Integer, _const("CRYPTO_HASHBLOCKS_STATEBYTES")
    assert_instance_of Integer, _const("CRYPTO_HASHBLOCKS_BLOCKBYTES")
    assert_instance_of String,  _const("CRYPTO_HASHBLOCKS_IMPLEMENTATION")
    assert_instance_of String,  _const("CRYPTO_HASHBLOCKS_VERSION")
    assert_instance_of Integer, _const("CRYPTO_HASHBLOCKS_SHA512_TWEET_STATEBYTES")
    assert_instance_of Integer, _const("CRYPTO_HASHBLOCKS_SHA512_TWEET_BLOCKBYTES")
    assert_instance_of String,  _const("CRYPTO_HASHBLOCKS_SHA512_TWEET_VERSION")
    assert_instance_of Integer, _const("CRYPTO_HASHBLOCKS_SHA512_STATEBYTES")
    assert_instance_of Integer, _const("CRYPTO_HASHBLOCKS_SHA512_BLOCKBYTES")
    assert_instance_of String,  _const("CRYPTO_HASHBLOCKS_SHA512_VERSION")
    assert_instance_of String,  _const("CRYPTO_HASHBLOCKS_SHA512_IMPLEMENTATION")
    assert_instance_of Integer, _const("CRYPTO_HASHBLOCKS_SHA256_TWEET_STATEBYTES")
    assert_instance_of Integer, _const("CRYPTO_HASHBLOCKS_SHA256_TWEET_BLOCKBYTES")
    assert_instance_of String,  _const("CRYPTO_HASHBLOCKS_SHA256_TWEET_VERSION")
    assert_instance_of Integer, _const("CRYPTO_HASHBLOCKS_SHA256_STATEBYTES")
    assert_instance_of Integer, _const("CRYPTO_HASHBLOCKS_SHA256_BLOCKBYTES")
    assert_instance_of String,  _const("CRYPTO_HASHBLOCKS_SHA256_VERSION")
    assert_instance_of String,  _const("CRYPTO_HASHBLOCKS_SHA256_IMPLEMENTATION")
    assert_instance_of String,  _const("CRYPTO_HASH_PRIMITIVE")
    assert_instance_of Integer, _const("CRYPTO_HASH_BYTES")
    assert_instance_of String,  _const("CRYPTO_HASH_IMPLEMENTATION")
    assert_instance_of String,  _const("CRYPTO_HASH_VERSION")
    assert_instance_of Integer, _const("CRYPTO_HASH_SHA512_TWEET_BYTES")
    assert_instance_of String,  _const("CRYPTO_HASH_SHA512_TWEET_VERSION")
    assert_instance_of Integer, _const("CRYPTO_HASH_SHA512_BYTES")
    assert_instance_of String,  _const("CRYPTO_HASH_SHA512_VERSION")
    assert_instance_of String,  _const("CRYPTO_HASH_SHA512_IMPLEMENTATION")
    assert_instance_of Integer, _const("CRYPTO_HASH_SHA256_TWEET_BYTES")
    assert_instance_of String,  _const("CRYPTO_HASH_SHA256_TWEET_VERSION")
    assert_instance_of Integer, _const("CRYPTO_HASH_SHA256_BYTES")
    assert_instance_of String,  _const("CRYPTO_HASH_SHA256_VERSION")
    assert_instance_of String,  _const("CRYPTO_HASH_SHA256_IMPLEMENTATION")
    assert_instance_of String,  _const("CRYPTO_ONETIMEAUTH_PRIMITIVE")
    assert_instance_of Integer, _const("CRYPTO_ONETIMEAUTH_BYTES")
    assert_instance_of Integer, _const("CRYPTO_ONETIMEAUTH_KEYBYTES")
    assert_instance_of String,  _const("CRYPTO_ONETIMEAUTH_IMPLEMENTATION")
    assert_instance_of String,  _const("CRYPTO_ONETIMEAUTH_VERSION")
    assert_instance_of Integer, _const("CRYPTO_ONETIMEAUTH_POLY1305_TWEET_BYTES")
    assert_instance_of Integer, _const("CRYPTO_ONETIMEAUTH_POLY1305_TWEET_KEYBYTES")
    assert_instance_of String,  _const("CRYPTO_ONETIMEAUTH_POLY1305_TWEET_VERSION")
    assert_instance_of Integer, _const("CRYPTO_ONETIMEAUTH_POLY1305_BYTES")
    assert_instance_of Integer, _const("CRYPTO_ONETIMEAUTH_POLY1305_KEYBYTES")
    assert_instance_of String,  _const("CRYPTO_ONETIMEAUTH_POLY1305_VERSION")
    assert_instance_of String,  _const("CRYPTO_ONETIMEAUTH_POLY1305_IMPLEMENTATION")
    assert_instance_of String,  _const("CRYPTO_SCALARMULT_PRIMITIVE")
    assert_instance_of Integer, _const("CRYPTO_SCALARMULT_BYTES")
    assert_instance_of Integer, _const("CRYPTO_SCALARMULT_SCALARBYTES")
    assert_instance_of String,  _const("CRYPTO_SCALARMULT_IMPLEMENTATION")
    assert_instance_of String,  _const("CRYPTO_SCALARMULT_VERSION")
    assert_instance_of Integer, _const("CRYPTO_SCALARMULT_CURVE25519_TWEET_BYTES")
    assert_instance_of Integer, _const("CRYPTO_SCALARMULT_CURVE25519_TWEET_SCALARBYTES")
    assert_instance_of String,  _const("CRYPTO_SCALARMULT_CURVE25519_TWEET_VERSION")
    assert_instance_of Integer, _const("CRYPTO_SCALARMULT_CURVE25519_BYTES")
    assert_instance_of Integer, _const("CRYPTO_SCALARMULT_CURVE25519_SCALARBYTES")
    assert_instance_of String,  _const("CRYPTO_SCALARMULT_CURVE25519_VERSION")
    assert_instance_of String,  _const("CRYPTO_SCALARMULT_CURVE25519_IMPLEMENTATION")
    assert_instance_of String,  _const("CRYPTO_SECRETBOX_PRIMITIVE")
    assert_instance_of Integer, _const("CRYPTO_SECRETBOX_KEYBYTES")
    assert_instance_of Integer, _const("CRYPTO_SECRETBOX_NONCEBYTES")
    assert_instance_of Integer, _const("CRYPTO_SECRETBOX_ZEROBYTES")
    assert_instance_of Integer, _const("CRYPTO_SECRETBOX_BOXZEROBYTES")
    assert_instance_of String,  _const("CRYPTO_SECRETBOX_IMPLEMENTATION")
    assert_instance_of String,  _const("CRYPTO_SECRETBOX_VERSION")
    assert_instance_of Integer, _const("CRYPTO_SECRETBOX_XSALSA20POLY1305_TWEET_KEYBYTES")
    assert_instance_of Integer, _const("CRYPTO_SECRETBOX_XSALSA20POLY1305_TWEET_NONCEBYTES")
    assert_instance_of Integer, _const("CRYPTO_SECRETBOX_XSALSA20POLY1305_TWEET_ZEROBYTES")
    assert_instance_of Integer, _const("CRYPTO_SECRETBOX_XSALSA20POLY1305_TWEET_BOXZEROBYTES")
    assert_instance_of String,  _const("CRYPTO_SECRETBOX_XSALSA20POLY1305_TWEET_VERSION")
    assert_instance_of Integer, _const("CRYPTO_SECRETBOX_XSALSA20POLY1305_KEYBYTES")
    assert_instance_of Integer, _const("CRYPTO_SECRETBOX_XSALSA20POLY1305_NONCEBYTES")
    assert_instance_of Integer, _const("CRYPTO_SECRETBOX_XSALSA20POLY1305_ZEROBYTES")
    assert_instance_of Integer, _const("CRYPTO_SECRETBOX_XSALSA20POLY1305_BOXZEROBYTES")
    assert_instance_of String,  _const("CRYPTO_SECRETBOX_XSALSA20POLY1305_VERSION")
    assert_instance_of String,  _const("CRYPTO_SECRETBOX_XSALSA20POLY1305_IMPLEMENTATION")
    assert_instance_of String,  _const("CRYPTO_SIGN_PRIMITIVE")
    assert_instance_of Integer, _const("CRYPTO_SIGN_BYTES")
    assert_instance_of Integer, _const("CRYPTO_SIGN_PUBLICKEYBYTES")
    assert_instance_of Integer, _const("CRYPTO_SIGN_SECRETKEYBYTES")
    assert_instance_of String,  _const("CRYPTO_SIGN_IMPLEMENTATION")
    assert_instance_of String,  _const("CRYPTO_SIGN_VERSION")
    assert_instance_of Integer, _const("CRYPTO_SIGN_ED25519_TWEET_BYTES")
    assert_instance_of Integer, _const("CRYPTO_SIGN_ED25519_TWEET_PUBLICKEYBYTES")
    assert_instance_of Integer, _const("CRYPTO_SIGN_ED25519_TWEET_SECRETKEYBYTES")
    assert_instance_of String,  _const("CRYPTO_SIGN_ED25519_TWEET_VERSION")
    assert_instance_of Integer, _const("CRYPTO_SIGN_ED25519_BYTES")
    assert_instance_of Integer, _const("CRYPTO_SIGN_ED25519_PUBLICKEYBYTES")
    assert_instance_of Integer, _const("CRYPTO_SIGN_ED25519_SECRETKEYBYTES")
    assert_instance_of String,  _const("CRYPTO_SIGN_ED25519_VERSION")
    assert_instance_of String,  _const("CRYPTO_SIGN_ED25519_IMPLEMENTATION")
    assert_instance_of String,  _const("CRYPTO_STREAM_PRIMITIVE")
    assert_instance_of Integer, _const("CRYPTO_STREAM_KEYBYTES")
    assert_instance_of Integer, _const("CRYPTO_STREAM_NONCEBYTES")
    assert_instance_of String,  _const("CRYPTO_STREAM_IMPLEMENTATION")
    assert_instance_of String,  _const("CRYPTO_STREAM_VERSION")
    assert_instance_of Integer, _const("CRYPTO_STREAM_XSALSA20_TWEET_KEYBYTES")
    assert_instance_of Integer, _const("CRYPTO_STREAM_XSALSA20_TWEET_NONCEBYTES")
  end
end
