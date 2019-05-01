#include <ruby/ruby.h>
#include <ruby/encoding.h>
#include "tweetnacl.h"
#define PADDING_LEN 32

void hexdump(char * data, int len)
{
  int i;
  for (i = 0; i < len; i++) {
    printf("%02X", (unsigned char)data[i]);
  }
  printf("\n");
}

extern int salsa_rounds;

VALUE m_crypto_box_salsa_rounds_set(VALUE self, VALUE _n) {
  if(_n == Qnil) { rb_raise(rb_eArgError, "`TweetNaCl#salsa_round=` called with nil argument"); }
  salsa_rounds = NUM2INT(_n);
  return _n;
}

VALUE m_crypto_box_salsa_rounds_get(VALUE self) {
  return INT2NUM(salsa_rounds);
}

VALUE m_crypto_box_keypair(VALUE self) {
  VALUE ary = rb_ary_new2(2);
  unsigned char *pk = calloc(crypto_box_PUBLICKEYBYTES, sizeof(unsigned char));
  unsigned char *sk = calloc(crypto_box_SECRETKEYBYTES, sizeof(unsigned char));

  int res = crypto_box_keypair(pk, sk);
  // TODO: use an exception instead of exit()
  if (0 != res) { rb_raise(rb_eRuntimeError, "crypto_box_keypair did not work. error %d\n", res); }

  rb_ary_store(ary, 0, rb_str_new(pk, crypto_box_PUBLICKEYBYTES));
  rb_ary_store(ary, 1, rb_str_new(sk, crypto_box_SECRETKEYBYTES));
  return ary;
}

VALUE m_crypto_box(VALUE self, VALUE _m, VALUE _n, VALUE _pk, VALUE _sk) {
  if(_m == Qnil) { rb_raise(rb_eArgError, "A message should have been given"); }
  if(_n == Qnil) { rb_raise(rb_eArgError, "A nonce should have been given"); }
  if(_pk == Qnil) { rb_raise(rb_eArgError, "Public key should have been given"); }
  if(_sk == Qnil) { rb_raise(rb_eArgError, "Secret key should have been given"); }
  if (RSTRING_LEN(_n)  != 24) { rb_raise(rb_eArgError, "nonce should be 24-byte long"); }
  if (RSTRING_LEN(_pk) != 32) { rb_raise(rb_eArgError, "public key should be 24-byte long"); }
  if (RSTRING_LEN(_sk) != 32) { rb_raise(rb_eArgError, "secret key should be 24-byte long"); }

  char * message = RSTRING_PTR(_m);
  char * nonce = RSTRING_PTR(_n);
  char * pk = RSTRING_PTR(_pk);
  char * sk = RSTRING_PTR(_sk);
  int len = RSTRING_LEN(_m);
  char * padded_message = (char*)calloc(sizeof(char), len + PADDING_LEN);
  memcpy(padded_message + PADDING_LEN, message, len);
  char * c = malloc(len + PADDING_LEN);
  int res = crypto_box(c, padded_message, len + PADDING_LEN, nonce, pk, sk);
  // TODO: use an exception instead of exit()
  if (0 != res) { fprintf(stderr, "Something went wrong\n"); exit(res); }
  VALUE ret = rb_str_new(c + 16, len + 16);
  return ret;
}

VALUE m_crypto_box_open(VALUE self, VALUE _c, VALUE _n, VALUE _pk, VALUE _sk) {
  if(_c == Qnil) { rb_raise(rb_eArgError, "A cipher should have been given"); }
  if(_n == Qnil) { rb_raise(rb_eArgError, "A nonce should have been given"); }
  if(_pk == Qnil) { rb_raise(rb_eArgError, "Public key should have been given"); }
  if(_sk == Qnil) { rb_raise(rb_eArgError, "Secret key should have been given"); }
  if (RSTRING_LEN(_n)  != crypto_box_NONCEBYTES)     { rb_raise(rb_eArgError, "nonce should be %d-byte long", crypto_box_NONCEBYTES); }
  if (RSTRING_LEN(_pk) != crypto_box_PUBLICKEYBYTES) { rb_raise(rb_eArgError, "public key should be %d-byte long", crypto_box_PUBLICKEYBYTES); }
  if (RSTRING_LEN(_sk) != crypto_box_SECRETKEYBYTES) { rb_raise(rb_eArgError, "secret key should be %d-byte long", crypto_box_SECRETKEYBYTES); }

  unsigned char * c = RSTRING_PTR(_c);
  char * nonce = RSTRING_PTR(_n);
  char * pk = RSTRING_PTR(_pk);
  char * sk = RSTRING_PTR(_sk);
  int len = RSTRING_LEN(_c);
  unsigned char * ciphertext = (unsigned char*)calloc(sizeof(unsigned char), len + 16);
  memcpy(ciphertext + 16, c, len);

  unsigned char * message = (unsigned char*)calloc(len + PADDING_LEN, sizeof(unsigned char));

  int res = crypto_box_open(message, ciphertext, len + 16, nonce, pk, sk);
  if (0 != res) { rb_raise(rb_eRuntimeError, "crypto_box_open did not work. error %d", res); }

  VALUE ret = rb_str_new(message + PADDING_LEN, len - 16);
  return ret;
}

VALUE m_crypto_secretbox(VALUE self, VALUE _m, VALUE _n, VALUE _k) {
  if(_m == Qnil) { rb_raise(rb_eArgError, "A message should have been given"); }
  if(_k == Qnil) { rb_raise(rb_eArgError, "Secret key should have been given"); }
  if (RSTRING_LEN(_n)  != 24) { rb_raise(rb_eArgError, "nonce should be 24-byte long"); }
  if (RSTRING_LEN(_k) != 32) { rb_raise(rb_eArgError, "Secret key should be 32-byte long"); }

  char * message = RSTRING_PTR(_m);
  char * nonce = RSTRING_PTR(_n);
  char * k = RSTRING_PTR(_k);
  int len = RSTRING_LEN(_m);
  char * padded_message = (char*)calloc(sizeof(char), len + PADDING_LEN);
  memcpy(padded_message + PADDING_LEN, message, len);
  char * c = malloc(len + PADDING_LEN);
  int res = crypto_secretbox(c, padded_message, len + PADDING_LEN, nonce, k);
  // TODO: use an exception instead of exit()
  if (0 != res) { fprintf(stderr, "Something went wrong\n"); exit(res); }
  VALUE ret = rb_str_new(c + 16, len + 16);
  return ret;
}

VALUE m_crypto_secretbox_open(VALUE self, VALUE _c, VALUE _n, VALUE _k) {
  if(_c == Qnil) { rb_raise(rb_eArgError, "A cipher should have been given"); }
  if(_k == Qnil) { rb_raise(rb_eArgError, "Secret key should have been given"); }
  if (RSTRING_LEN(_n)  != 24) { rb_raise(rb_eArgError, "nonce should be 24-byte long"); }
  if (RSTRING_LEN(_k) != 32) { rb_raise(rb_eArgError, "secret key should be 24-byte long"); }

  unsigned char * c = RSTRING_PTR(_c);
  char * nonce = RSTRING_PTR(_n);
  char * k = RSTRING_PTR(_k);
  int len = RSTRING_LEN(_c);

  unsigned char * ciphertext = (unsigned char*)calloc(sizeof(unsigned char), len + 16);
  memcpy(ciphertext + 16, c, len);

  char * message = calloc(len + PADDING_LEN, sizeof(char));

  int res = crypto_secretbox_open(message, ciphertext, len + 16, nonce, k);
  if (0 != res) { rb_raise(rb_eRuntimeError, "crypto_secretbox_open did not work"); }

  return rb_str_new(message + PADDING_LEN, len - 16);
}

VALUE m_crypto_sign_keypair(VALUE self) {
  VALUE ary = rb_ary_new2(2);
  unsigned char *pk = (unsigned char*)calloc(crypto_sign_PUBLICKEYBYTES, sizeof(unsigned char));
  unsigned char *sk = (unsigned char*)calloc(crypto_sign_SECRETKEYBYTES, sizeof(unsigned char));
  int res = crypto_sign_keypair(pk, sk);
  pk[crypto_sign_PUBLICKEYBYTES] = 0;
  sk[crypto_sign_SECRETKEYBYTES] = 0;
  rb_ary_store(ary, 0, rb_str_new(pk, crypto_sign_PUBLICKEYBYTES));
  rb_ary_store(ary, 1, rb_str_new(sk, crypto_sign_SECRETKEYBYTES));
  return ary;
}

VALUE m_crypto_sign(VALUE self, VALUE _m, VALUE _k) {
  if(_m == Qnil) { rb_raise(rb_eArgError, "A message should have been given"); }
  if(_k == Qnil) { rb_raise(rb_eArgError, "Secret key should have been given"); }
  if (RSTRING_LEN(_k) != crypto_sign_SECRETKEYBYTES) { rb_raise(rb_eArgError, "Secret key should be %d-byte long", crypto_sign_SECRETKEYBYTES); }

  unsigned char * message = RSTRING_PTR(_m);
  int len = rb_str_strlen(_m);
  unsigned char * c = (unsigned char*)calloc(sizeof(unsigned char), len + crypto_sign_BYTES);
  char * k = RSTRING_PTR(_k);
  unsigned long long int smlen = 0;

  int res = crypto_sign(c, &smlen, message, len, k);
  // TODO: use an exception instead of exit()
  if (0 != res) { fprintf(stderr, "crypto_sign did not work\n"); exit(res); }
  VALUE ret = rb_str_new(c, smlen);
  return ret;
}

VALUE m_crypto_sign_open(VALUE self, VALUE _c, VALUE _k) {
  if(_c == Qnil) { rb_raise(rb_eArgError, "A message should have been given"); }
  if(_k == Qnil) { rb_raise(rb_eArgError, "Public key should have been given"); }
  if (RSTRING_LEN(_k) != crypto_sign_PUBLICKEYBYTES) { rb_raise(rb_eArgError, "public key should be %d-byte long", crypto_sign_PUBLICKEYBYTES); }

  unsigned char * cipher = RSTRING_PTR(_c);
  int len = rb_str_strlen(_c);
  unsigned char * message = (unsigned char*)calloc(sizeof(unsigned char), len + 1);
  char * k = RSTRING_PTR(_k);
  unsigned long long int mlen = 0;

  int res = crypto_sign_open(message, &mlen, cipher, len, k);
  message[len] = 0;
  if (0 != res) { rb_raise(rb_eRuntimeError, "crypto_sign_open did not work. error %d\n", res); }
  VALUE ret = rb_str_new(message, mlen);
  return ret;
}


void Init_tweetnacl() {
  VALUE c = rb_define_module("TweetNaCl");

  rb_define_module_function(c , "salsa_rounds="                              , RUBY_METHOD_FUNC(m_crypto_box_salsa_rounds_set), 1);
  rb_define_module_function(c , "salsa_rounds"                               , RUBY_METHOD_FUNC(m_crypto_box_salsa_rounds_get), 0);

  rb_define_module_function(c , "crypto_box_keypair"                         , RUBY_METHOD_FUNC(m_crypto_box_keypair)    , 0);

  rb_define_module_function(c , "crypto_box"                                 , RUBY_METHOD_FUNC(m_crypto_box)            , 4);
  rb_define_module_function(c , "crypto_box_open"                            , RUBY_METHOD_FUNC(m_crypto_box_open)       , 4);
  rb_define_module_function(c , "crypto_box_curve25519xsalsa20poly1305"      , RUBY_METHOD_FUNC(m_crypto_box)            , 4);
  rb_define_module_function(c , "crypto_box_curve25519xsalsa20poly1305_open" , RUBY_METHOD_FUNC(m_crypto_box_open)       , 4);

  rb_define_module_function(c , "crypto_secretbox"                           , RUBY_METHOD_FUNC(m_crypto_secretbox)      , 3);
  rb_define_module_function(c , "crypto_secretbox_open"                      , RUBY_METHOD_FUNC(m_crypto_secretbox_open) , 3);
  rb_define_module_function(c , "crypto_secretbox_xsalsa20poly1305"          , RUBY_METHOD_FUNC(m_crypto_secretbox)      , 3);
  rb_define_module_function(c , "crypto_secretbox_xsalsa20poly1305_open"     , RUBY_METHOD_FUNC(m_crypto_secretbox_open) , 3);

  rb_define_module_function(c , "crypto_sign_keypair"                        , RUBY_METHOD_FUNC(m_crypto_sign_keypair)   , 0);

  rb_define_module_function(c , "crypto_sign"                                , RUBY_METHOD_FUNC(m_crypto_sign)           , 2);
  rb_define_module_function(c , "crypto_sign_ed25519"                        , RUBY_METHOD_FUNC(m_crypto_sign)           , 2);
  rb_define_module_function(c , "crypto_sign_open"                           , RUBY_METHOD_FUNC(m_crypto_sign_open)      , 2);
  rb_define_module_function(c , "crypto_sign_ed25519_open"                   , RUBY_METHOD_FUNC(m_crypto_sign_open)      , 2);

  rb_define_const(c , "CRYPTO_AUTH_PRIMITIVE"                                      , rb_str_new2("hmacsha512256"));
  rb_define_const(c , "CRYPTO_AUTH_BYTES"                                          , INT2NUM(crypto_auth_hmacsha512256_BYTES));
  rb_define_const(c , "CRYPTO_AUTH_KEYBYTES"                                       , INT2NUM(crypto_auth_hmacsha512256_KEYBYTES));
  rb_define_const(c , "CRYPTO_AUTH_IMPLEMENTATION"                                 , rb_str_new2(crypto_auth_hmacsha512256_IMPLEMENTATION));
  rb_define_const(c , "CRYPTO_AUTH_VERSION"                                        , rb_str_new2(crypto_auth_hmacsha512256_VERSION));
  rb_define_const(c , "CRYPTO_AUTH_HMACSHA512256_TWEET_BYTES"                      , INT2NUM(32));
  rb_define_const(c , "CRYPTO_AUTH_HMACSHA512256_TWEET_KEYBYTES"                   , INT2NUM(32));
  rb_define_const(c , "CRYPTO_AUTH_HMACSHA512256_TWEET_VERSION"                    , rb_str_new2("-"));
  rb_define_const(c , "CRYPTO_AUTH_HMACSHA512256_BYTES"                            , INT2NUM(crypto_auth_hmacsha512256_tweet_BYTES));
  rb_define_const(c , "CRYPTO_AUTH_HMACSHA512256_KEYBYTES"                         , INT2NUM(crypto_auth_hmacsha512256_tweet_KEYBYTES));
  rb_define_const(c , "CRYPTO_AUTH_HMACSHA512256_VERSION"                          , rb_str_new2(crypto_auth_hmacsha512256_tweet_VERSION));
  rb_define_const(c , "CRYPTO_AUTH_HMACSHA512256_IMPLEMENTATION"                   , rb_str_new2("crypto_auth/hmacsha512256/tweet"));
  rb_define_const(c , "CRYPTO_BOX_PRIMITIVE"                                       , rb_str_new2("curve25519xsalsa20poly1305"));
  rb_define_const(c , "CRYPTO_BOX_PUBLICKEYBYTES"                                  , INT2NUM(crypto_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES));
  rb_define_const(c , "CRYPTO_BOX_SECRETKEYBYTES"                                  , INT2NUM(crypto_box_curve25519xsalsa20poly1305_SECRETKEYBYTES));
  rb_define_const(c , "CRYPTO_BOX_BEFORENMBYTES"                                   , INT2NUM(crypto_box_curve25519xsalsa20poly1305_BEFORENMBYTES));
  rb_define_const(c , "CRYPTO_BOX_NONCEBYTES"                                      , INT2NUM(crypto_box_curve25519xsalsa20poly1305_NONCEBYTES));
  rb_define_const(c , "CRYPTO_BOX_ZEROBYTES"                                       , INT2NUM(crypto_box_curve25519xsalsa20poly1305_ZEROBYTES));
  rb_define_const(c , "CRYPTO_BOX_BOXZEROBYTES"                                    , INT2NUM(crypto_box_curve25519xsalsa20poly1305_BOXZEROBYTES));
  rb_define_const(c , "CRYPTO_BOX_IMPLEMENTATION"                                  , rb_str_new2(crypto_box_curve25519xsalsa20poly1305_IMPLEMENTATION));
  rb_define_const(c , "CRYPTO_BOX_VERSION"                                         , rb_str_new2(crypto_box_curve25519xsalsa20poly1305_VERSION));
  rb_define_const(c , "CRYPTO_BOX_CURVE25519XSALSA20POLY1305_TWEET_PUBLICKEYBYTES" , INT2NUM(32));
  rb_define_const(c , "CRYPTO_BOX_CURVE25519XSALSA20POLY1305_TWEET_SECRETKEYBYTES" , INT2NUM(32));
  rb_define_const(c , "CRYPTO_BOX_CURVE25519XSALSA20POLY1305_TWEET_BEFORENMBYTES"  , INT2NUM(32));
  rb_define_const(c , "CRYPTO_BOX_CURVE25519XSALSA20POLY1305_TWEET_NONCEBYTES"     , INT2NUM(24));
  rb_define_const(c , "CRYPTO_BOX_CURVE25519XSALSA20POLY1305_TWEET_ZEROBYTES"      , INT2NUM(32));
  rb_define_const(c , "CRYPTO_BOX_CURVE25519XSALSA20POLY1305_TWEET_BOXZEROBYTES"   , INT2NUM(16));
  rb_define_const(c , "CRYPTO_BOX_CURVE25519XSALSA20POLY1305_TWEET_VERSION"        , rb_str_new2("-"));
  rb_define_const(c , "CRYPTO_BOX_CURVE25519XSALSA20POLY1305_PUBLICKEYBYTES"       , INT2NUM(crypto_box_curve25519xsalsa20poly1305_tweet_PUBLICKEYBYTES));
  rb_define_const(c , "CRYPTO_BOX_CURVE25519XSALSA20POLY1305_SECRETKEYBYTES"       , INT2NUM(crypto_box_curve25519xsalsa20poly1305_tweet_SECRETKEYBYTES));
  rb_define_const(c , "CRYPTO_BOX_CURVE25519XSALSA20POLY1305_BEFORENMBYTES"        , INT2NUM(crypto_box_curve25519xsalsa20poly1305_tweet_BEFORENMBYTES));
  rb_define_const(c , "CRYPTO_BOX_CURVE25519XSALSA20POLY1305_NONCEBYTES"           , INT2NUM(crypto_box_curve25519xsalsa20poly1305_tweet_NONCEBYTES));
  rb_define_const(c , "CRYPTO_BOX_CURVE25519XSALSA20POLY1305_ZEROBYTES"            , INT2NUM(crypto_box_curve25519xsalsa20poly1305_tweet_ZEROBYTES));
  rb_define_const(c , "CRYPTO_BOX_CURVE25519XSALSA20POLY1305_BOXZEROBYTES"         , INT2NUM(crypto_box_curve25519xsalsa20poly1305_tweet_BOXZEROBYTES));
  rb_define_const(c , "CRYPTO_BOX_CURVE25519XSALSA20POLY1305_VERSION"              , rb_str_new2(crypto_box_curve25519xsalsa20poly1305_tweet_VERSION));
  rb_define_const(c , "CRYPTO_BOX_CURVE25519XSALSA20POLY1305_IMPLEMENTATION"       , rb_str_new2("crypto_box/curve25519xsalsa20poly1305/tweet"));
  rb_define_const(c , "CRYPTO_CORE_PRIMITIVE"                                      , rb_str_new2("salsa20"));
  rb_define_const(c , "CRYPTO_CORE_OUTPUTBYTES"                                    , INT2NUM(crypto_core_salsa20_OUTPUTBYTES));
  rb_define_const(c , "CRYPTO_CORE_INPUTBYTES"                                     , INT2NUM(crypto_core_salsa20_INPUTBYTES));
  rb_define_const(c , "CRYPTO_CORE_KEYBYTES"                                       , INT2NUM(crypto_core_salsa20_KEYBYTES));
  rb_define_const(c , "CRYPTO_CORE_CONSTBYTES"                                     , INT2NUM(crypto_core_salsa20_CONSTBYTES));
  rb_define_const(c , "CRYPTO_CORE_IMPLEMENTATION"                                 , rb_str_new2(crypto_core_salsa20_IMPLEMENTATION));
  rb_define_const(c , "CRYPTO_CORE_VERSION"                                        , rb_str_new2(crypto_core_salsa20_VERSION));
  rb_define_const(c , "CRYPTO_CORE_SALSA20_TWEET_OUTPUTBYTES"                      , INT2NUM(64));
  rb_define_const(c , "CRYPTO_CORE_SALSA20_TWEET_INPUTBYTES"                       , INT2NUM(16));
  rb_define_const(c , "CRYPTO_CORE_SALSA20_TWEET_KEYBYTES"                         , INT2NUM(32));
  rb_define_const(c , "CRYPTO_CORE_SALSA20_TWEET_CONSTBYTES"                       , INT2NUM(16));
  rb_define_const(c , "CRYPTO_CORE_SALSA20_TWEET_VERSION"                          , rb_str_new2("-"));
  rb_define_const(c , "CRYPTO_CORE_SALSA20_OUTPUTBYTES"                            , INT2NUM(crypto_core_salsa20_tweet_OUTPUTBYTES));
  rb_define_const(c , "CRYPTO_CORE_SALSA20_INPUTBYTES"                             , INT2NUM(crypto_core_salsa20_tweet_INPUTBYTES));
  rb_define_const(c , "CRYPTO_CORE_SALSA20_KEYBYTES"                               , INT2NUM(crypto_core_salsa20_tweet_KEYBYTES));
  rb_define_const(c , "CRYPTO_CORE_SALSA20_CONSTBYTES"                             , INT2NUM(crypto_core_salsa20_tweet_CONSTBYTES));
  rb_define_const(c , "CRYPTO_CORE_SALSA20_VERSION"                                , rb_str_new2(crypto_core_salsa20_tweet_VERSION));
  rb_define_const(c , "CRYPTO_CORE_SALSA20_IMPLEMENTATION"                         , rb_str_new2("crypto_core/salsa20/tweet"));
  rb_define_const(c , "CRYPTO_CORE_HSALSA20_TWEET_OUTPUTBYTES"                     , INT2NUM(32));
  rb_define_const(c , "CRYPTO_CORE_HSALSA20_TWEET_INPUTBYTES"                      , INT2NUM(16));
  rb_define_const(c , "CRYPTO_CORE_HSALSA20_TWEET_KEYBYTES"                        , INT2NUM(32));
  rb_define_const(c , "CRYPTO_CORE_HSALSA20_TWEET_CONSTBYTES"                      , INT2NUM(16));
  rb_define_const(c , "CRYPTO_CORE_HSALSA20_TWEET_VERSION"                         , rb_str_new2("-"));
  rb_define_const(c , "CRYPTO_CORE_HSALSA20_OUTPUTBYTES"                           , INT2NUM(crypto_core_hsalsa20_tweet_OUTPUTBYTES));
  rb_define_const(c , "CRYPTO_CORE_HSALSA20_INPUTBYTES"                            , INT2NUM(crypto_core_hsalsa20_tweet_INPUTBYTES));
  rb_define_const(c , "CRYPTO_CORE_HSALSA20_KEYBYTES"                              , INT2NUM(crypto_core_hsalsa20_tweet_KEYBYTES));
  rb_define_const(c , "CRYPTO_CORE_HSALSA20_CONSTBYTES"                            , INT2NUM(crypto_core_hsalsa20_tweet_CONSTBYTES));
  rb_define_const(c , "CRYPTO_CORE_HSALSA20_VERSION"                               , rb_str_new2(crypto_core_hsalsa20_tweet_VERSION));
  rb_define_const(c , "CRYPTO_CORE_HSALSA20_IMPLEMENTATION"                        , rb_str_new2("crypto_core/hsalsa20/tweet"));
  rb_define_const(c , "CRYPTO_HASHBLOCKS_PRIMITIVE"                                , rb_str_new2("sha512"));
  rb_define_const(c , "CRYPTO_HASHBLOCKS_STATEBYTES"                               , INT2NUM(crypto_hashblocks_sha512_STATEBYTES));
  rb_define_const(c , "CRYPTO_HASHBLOCKS_BLOCKBYTES"                               , INT2NUM(crypto_hashblocks_sha512_BLOCKBYTES));
  rb_define_const(c , "CRYPTO_HASHBLOCKS_IMPLEMENTATION"                           , rb_str_new2(crypto_hashblocks_sha512_IMPLEMENTATION));
  rb_define_const(c , "CRYPTO_HASHBLOCKS_VERSION"                                  , rb_str_new2(crypto_hashblocks_sha512_VERSION));
  rb_define_const(c , "CRYPTO_HASHBLOCKS_SHA512_TWEET_STATEBYTES"                  , INT2NUM(64));
  rb_define_const(c , "CRYPTO_HASHBLOCKS_SHA512_TWEET_BLOCKBYTES"                  , INT2NUM(128));
  rb_define_const(c , "CRYPTO_HASHBLOCKS_SHA512_TWEET_VERSION"                     , rb_str_new2("-"));
  rb_define_const(c , "CRYPTO_HASHBLOCKS_SHA512_STATEBYTES"                        , INT2NUM(crypto_hashblocks_sha512_tweet_STATEBYTES));
  rb_define_const(c , "CRYPTO_HASHBLOCKS_SHA512_BLOCKBYTES"                        , INT2NUM(crypto_hashblocks_sha512_tweet_BLOCKBYTES));
  rb_define_const(c , "CRYPTO_HASHBLOCKS_SHA512_VERSION"                           , rb_str_new2(crypto_hashblocks_sha512_tweet_VERSION));
  rb_define_const(c , "CRYPTO_HASHBLOCKS_SHA512_IMPLEMENTATION"                    , rb_str_new2("crypto_hashblocks/sha512/tweet"));
  rb_define_const(c , "CRYPTO_HASHBLOCKS_SHA256_TWEET_STATEBYTES"                  , INT2NUM(32));
  rb_define_const(c , "CRYPTO_HASHBLOCKS_SHA256_TWEET_BLOCKBYTES"                  , INT2NUM(64));
  rb_define_const(c , "CRYPTO_HASHBLOCKS_SHA256_TWEET_VERSION"                     , rb_str_new2("-"));
  rb_define_const(c , "CRYPTO_HASHBLOCKS_SHA256_STATEBYTES"                        , INT2NUM(crypto_hashblocks_sha256_tweet_STATEBYTES));
  rb_define_const(c , "CRYPTO_HASHBLOCKS_SHA256_BLOCKBYTES"                        , INT2NUM(crypto_hashblocks_sha256_tweet_BLOCKBYTES));
  rb_define_const(c , "CRYPTO_HASHBLOCKS_SHA256_VERSION"                           , rb_str_new2(crypto_hashblocks_sha256_tweet_VERSION));
  rb_define_const(c , "CRYPTO_HASHBLOCKS_SHA256_IMPLEMENTATION"                    , rb_str_new2("crypto_hashblocks/sha256/tweet"));
  rb_define_const(c , "CRYPTO_HASH_PRIMITIVE"                                      , rb_str_new2("sha512"));
  rb_define_const(c , "CRYPTO_HASH_BYTES"                                          , INT2NUM(crypto_hash_sha512_BYTES));
  rb_define_const(c , "CRYPTO_HASH_IMPLEMENTATION"                                 , rb_str_new2(crypto_hash_sha512_IMPLEMENTATION));
  rb_define_const(c , "CRYPTO_HASH_VERSION"                                        , rb_str_new2(crypto_hash_sha512_VERSION));
  rb_define_const(c , "CRYPTO_HASH_SHA512_TWEET_BYTES"                             , INT2NUM(64));
  rb_define_const(c , "CRYPTO_HASH_SHA512_TWEET_VERSION"                           , rb_str_new2("-"));
  rb_define_const(c , "CRYPTO_HASH_SHA512_BYTES"                                   , INT2NUM(crypto_hash_sha512_tweet_BYTES));
  rb_define_const(c , "CRYPTO_HASH_SHA512_VERSION"                                 , rb_str_new2(crypto_hash_sha512_tweet_VERSION));
  rb_define_const(c , "CRYPTO_HASH_SHA512_IMPLEMENTATION"                          , rb_str_new2("crypto_hash/sha512/tweet"));
  rb_define_const(c , "CRYPTO_HASH_SHA256_TWEET_BYTES"                             , INT2NUM(32));
  rb_define_const(c , "CRYPTO_HASH_SHA256_TWEET_VERSION"                           , rb_str_new2("-"));
  rb_define_const(c , "CRYPTO_HASH_SHA256_BYTES"                                   , INT2NUM(crypto_hash_sha256_tweet_BYTES));
  rb_define_const(c , "CRYPTO_HASH_SHA256_VERSION"                                 , rb_str_new2(crypto_hash_sha256_tweet_VERSION));
  rb_define_const(c , "CRYPTO_HASH_SHA256_IMPLEMENTATION"                          , rb_str_new2("crypto_hash/sha256/tweet"));
  rb_define_const(c , "CRYPTO_ONETIMEAUTH_PRIMITIVE"                               , rb_str_new2("poly1305"));
  rb_define_const(c , "CRYPTO_ONETIMEAUTH_BYTES"                                   , INT2NUM(crypto_onetimeauth_poly1305_BYTES));
  rb_define_const(c , "CRYPTO_ONETIMEAUTH_KEYBYTES"                                , INT2NUM(crypto_onetimeauth_poly1305_KEYBYTES));
  rb_define_const(c , "CRYPTO_ONETIMEAUTH_IMPLEMENTATION"                          , rb_str_new2(crypto_onetimeauth_poly1305_IMPLEMENTATION));
  rb_define_const(c , "CRYPTO_ONETIMEAUTH_VERSION"                                 , rb_str_new2(crypto_onetimeauth_poly1305_VERSION));
  rb_define_const(c , "CRYPTO_ONETIMEAUTH_POLY1305_TWEET_BYTES"                    , INT2NUM(16));
  rb_define_const(c , "CRYPTO_ONETIMEAUTH_POLY1305_TWEET_KEYBYTES"                 , INT2NUM(32));
  rb_define_const(c , "CRYPTO_ONETIMEAUTH_POLY1305_TWEET_VERSION"                  , rb_str_new2("-"));
  rb_define_const(c , "CRYPTO_ONETIMEAUTH_POLY1305_BYTES"                          , INT2NUM(crypto_onetimeauth_poly1305_tweet_BYTES));
  rb_define_const(c , "CRYPTO_ONETIMEAUTH_POLY1305_KEYBYTES"                       , INT2NUM(crypto_onetimeauth_poly1305_tweet_KEYBYTES));
  rb_define_const(c , "CRYPTO_ONETIMEAUTH_POLY1305_VERSION"                        , rb_str_new2(crypto_onetimeauth_poly1305_tweet_VERSION));
  rb_define_const(c , "CRYPTO_ONETIMEAUTH_POLY1305_IMPLEMENTATION"                 , rb_str_new2("crypto_onetimeauth/poly1305/tweet"));
  rb_define_const(c , "CRYPTO_SCALARMULT_PRIMITIVE"                                , rb_str_new2("curve25519"));
  rb_define_const(c , "CRYPTO_SCALARMULT_BYTES"                                    , INT2NUM(crypto_scalarmult_curve25519_BYTES));
  rb_define_const(c , "CRYPTO_SCALARMULT_SCALARBYTES"                              , INT2NUM(crypto_scalarmult_curve25519_SCALARBYTES));
  rb_define_const(c , "CRYPTO_SCALARMULT_IMPLEMENTATION"                           , rb_str_new2(crypto_scalarmult_curve25519_IMPLEMENTATION));
  rb_define_const(c , "CRYPTO_SCALARMULT_VERSION"                                  , rb_str_new2(crypto_scalarmult_curve25519_VERSION));
  rb_define_const(c , "CRYPTO_SCALARMULT_CURVE25519_TWEET_BYTES"                   , INT2NUM(32));
  rb_define_const(c , "CRYPTO_SCALARMULT_CURVE25519_TWEET_SCALARBYTES"             , INT2NUM(32));
  rb_define_const(c , "CRYPTO_SCALARMULT_CURVE25519_TWEET_VERSION"                 , rb_str_new2("-"));
  rb_define_const(c , "CRYPTO_SCALARMULT_CURVE25519_BYTES"                         , INT2NUM(crypto_scalarmult_curve25519_tweet_BYTES));
  rb_define_const(c , "CRYPTO_SCALARMULT_CURVE25519_SCALARBYTES"                   , INT2NUM(crypto_scalarmult_curve25519_tweet_SCALARBYTES));
  rb_define_const(c , "CRYPTO_SCALARMULT_CURVE25519_VERSION"                       , rb_str_new2(crypto_scalarmult_curve25519_tweet_VERSION));
  rb_define_const(c , "CRYPTO_SCALARMULT_CURVE25519_IMPLEMENTATION"                , rb_str_new2("crypto_scalarmult/curve25519/tweet"));
  rb_define_const(c , "CRYPTO_SECRETBOX_PRIMITIVE"                                 , rb_str_new2("xsalsa20poly1305"));
  rb_define_const(c , "CRYPTO_SECRETBOX_KEYBYTES"                                  , INT2NUM(crypto_secretbox_xsalsa20poly1305_KEYBYTES));
  rb_define_const(c , "CRYPTO_SECRETBOX_NONCEBYTES"                                , INT2NUM(crypto_secretbox_xsalsa20poly1305_NONCEBYTES));
  rb_define_const(c , "CRYPTO_SECRETBOX_ZEROBYTES"                                 , INT2NUM(crypto_secretbox_xsalsa20poly1305_ZEROBYTES));
  rb_define_const(c , "CRYPTO_SECRETBOX_BOXZEROBYTES"                              , INT2NUM(crypto_secretbox_xsalsa20poly1305_BOXZEROBYTES));
  rb_define_const(c , "CRYPTO_SECRETBOX_IMPLEMENTATION"                            , rb_str_new2(crypto_secretbox_xsalsa20poly1305_IMPLEMENTATION));
  rb_define_const(c , "CRYPTO_SECRETBOX_VERSION"                                   , rb_str_new2(crypto_secretbox_xsalsa20poly1305_VERSION));
  rb_define_const(c , "CRYPTO_SECRETBOX_XSALSA20POLY1305_TWEET_KEYBYTES"           , INT2NUM(32));
  rb_define_const(c , "CRYPTO_SECRETBOX_XSALSA20POLY1305_TWEET_NONCEBYTES"         , INT2NUM(24));
  rb_define_const(c , "CRYPTO_SECRETBOX_XSALSA20POLY1305_TWEET_ZEROBYTES"          , INT2NUM(32));
  rb_define_const(c , "CRYPTO_SECRETBOX_XSALSA20POLY1305_TWEET_BOXZEROBYTES"       , INT2NUM(16));
  rb_define_const(c , "CRYPTO_SECRETBOX_XSALSA20POLY1305_TWEET_VERSION"            , rb_str_new2("-"));
  rb_define_const(c , "CRYPTO_SECRETBOX_XSALSA20POLY1305_KEYBYTES"                 , INT2NUM(crypto_secretbox_xsalsa20poly1305_tweet_KEYBYTES));
  rb_define_const(c , "CRYPTO_SECRETBOX_XSALSA20POLY1305_NONCEBYTES"               , INT2NUM(crypto_secretbox_xsalsa20poly1305_tweet_NONCEBYTES));
  rb_define_const(c , "CRYPTO_SECRETBOX_XSALSA20POLY1305_ZEROBYTES"                , INT2NUM(crypto_secretbox_xsalsa20poly1305_tweet_ZEROBYTES));
  rb_define_const(c , "CRYPTO_SECRETBOX_XSALSA20POLY1305_BOXZEROBYTES"             , INT2NUM(crypto_secretbox_xsalsa20poly1305_tweet_BOXZEROBYTES));
  rb_define_const(c , "CRYPTO_SECRETBOX_XSALSA20POLY1305_VERSION"                  , rb_str_new2(crypto_secretbox_xsalsa20poly1305_tweet_VERSION));
  rb_define_const(c , "CRYPTO_SECRETBOX_XSALSA20POLY1305_IMPLEMENTATION"           , rb_str_new2("crypto_secretbox/xsalsa20poly1305/tweet"));
  rb_define_const(c , "CRYPTO_SIGN_PRIMITIVE"                                      , rb_str_new2("ed25519"));
  rb_define_const(c , "CRYPTO_SIGN_BYTES"                                          , INT2NUM(crypto_sign_ed25519_BYTES));
  rb_define_const(c , "CRYPTO_SIGN_PUBLICKEYBYTES"                                 , INT2NUM(crypto_sign_ed25519_PUBLICKEYBYTES));
  rb_define_const(c , "CRYPTO_SIGN_SECRETKEYBYTES"                                 , INT2NUM(crypto_sign_ed25519_SECRETKEYBYTES));
  rb_define_const(c , "CRYPTO_SIGN_IMPLEMENTATION"                                 , rb_str_new2(crypto_sign_ed25519_IMPLEMENTATION));
  rb_define_const(c , "CRYPTO_SIGN_VERSION"                                        , rb_str_new2(crypto_sign_ed25519_VERSION));
  rb_define_const(c , "CRYPTO_SIGN_ED25519_TWEET_BYTES"                            , INT2NUM(64));
  rb_define_const(c , "CRYPTO_SIGN_ED25519_TWEET_PUBLICKEYBYTES"                   , INT2NUM(32));
  rb_define_const(c , "CRYPTO_SIGN_ED25519_TWEET_SECRETKEYBYTES"                   , INT2NUM(64));
  rb_define_const(c , "CRYPTO_SIGN_ED25519_TWEET_VERSION"                          , rb_str_new2("-"));
  rb_define_const(c , "CRYPTO_SIGN_ED25519_BYTES"                                  , INT2NUM(crypto_sign_ed25519_tweet_BYTES));
  rb_define_const(c , "CRYPTO_SIGN_ED25519_PUBLICKEYBYTES"                         , INT2NUM(crypto_sign_ed25519_tweet_PUBLICKEYBYTES));
  rb_define_const(c , "CRYPTO_SIGN_ED25519_SECRETKEYBYTES"                         , INT2NUM(crypto_sign_ed25519_tweet_SECRETKEYBYTES));
  rb_define_const(c , "CRYPTO_SIGN_ED25519_VERSION"                                , rb_str_new2(crypto_sign_ed25519_tweet_VERSION));
  rb_define_const(c , "CRYPTO_SIGN_ED25519_IMPLEMENTATION"                         , rb_str_new2("crypto_sign/ed25519/tweet"));
  rb_define_const(c , "CRYPTO_STREAM_PRIMITIVE"                                    , rb_str_new2("xsalsa20"));
  rb_define_const(c , "CRYPTO_STREAM_KEYBYTES"                                     , INT2NUM(crypto_stream_xsalsa20_KEYBYTES));
  rb_define_const(c , "CRYPTO_STREAM_NONCEBYTES"                                   , INT2NUM(crypto_stream_xsalsa20_NONCEBYTES));
  rb_define_const(c , "CRYPTO_STREAM_IMPLEMENTATION"                               , rb_str_new2(crypto_stream_xsalsa20_IMPLEMENTATION));
  rb_define_const(c , "CRYPTO_STREAM_VERSION"                                      , rb_str_new2(crypto_stream_xsalsa20_VERSION));
  rb_define_const(c , "CRYPTO_STREAM_XSALSA20_TWEET_KEYBYTES"                      , INT2NUM(32));
  rb_define_const(c , "CRYPTO_STREAM_XSALSA20_TWEET_NONCEBYTES"                    , INT2NUM(24));
}
