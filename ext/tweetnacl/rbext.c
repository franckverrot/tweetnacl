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

VALUE m_crypto_box_keypair(VALUE self) {
  VALUE ary = rb_ary_new2(2);
  char *pk = calloc(crypto_box_PUBLICKEYBYTES, sizeof(unsigned char));
  char *sk = calloc(crypto_box_SECRETKEYBYTES, sizeof(unsigned char));
  int res = crypto_box_keypair(pk, sk);
  pk[crypto_box_PUBLICKEYBYTES] = 0;
  sk[crypto_box_SECRETKEYBYTES] = 0;
  rb_ary_store(ary, 0, rb_str_new(pk, crypto_box_PUBLICKEYBYTES));
  rb_ary_store(ary, 1, rb_str_new(sk, crypto_box_SECRETKEYBYTES));
  return ary;
}

VALUE m_crypto_box(VALUE self, VALUE _m, VALUE _n, VALUE _pk, VALUE _sk) {
  if(_m == Qnil) { rb_raise(rb_eArgError, "A message should have been given"); }
  if(_pk == Qnil) { rb_raise(rb_eArgError, "Public key should have been given"); }
  if(_sk == Qnil) { rb_raise(rb_eArgError, "Secret key should have been given"); }
  if (RSTRING_LEN(_n)  != 24) { rb_raise(rb_eArgError, "nonce should be 24-byte long"); }
  if (RSTRING_LEN(_pk) != 32) { rb_raise(rb_eArgError, "public key should be 24-byte long"); }
  if (RSTRING_LEN(_sk) != 32) { rb_raise(rb_eArgError, "secret key should be 24-byte long"); }

  char * message = RSTRING_PTR(_m);
  char * nonce = RSTRING_PTR(_n);
  char * pk = RSTRING_PTR(_pk);
  char * sk = RSTRING_PTR(_sk);
  int len = strlen(message);
  char * padded_message = (char*)calloc(sizeof(char), len + PADDING_LEN);
  memcpy(padded_message + PADDING_LEN, message, strlen(message));
  char * c = malloc(strlen(message) + PADDING_LEN);
  int res = crypto_box(c, padded_message, len + PADDING_LEN, nonce, pk, sk);
  if (0 != res) { fprintf(stderr, "Something went wrong\n"); exit(res); }
  VALUE ret = rb_str_new(c, len + PADDING_LEN);
  return ret;
}

VALUE m_crypto_box_open(VALUE self, VALUE _c, VALUE _n, VALUE _pk, VALUE _sk) {
  if(_c == Qnil) { rb_raise(rb_eArgError, "A cipher should have been given"); }
  if(_pk == Qnil) { rb_raise(rb_eArgError, "Public key should have been given"); }
  if(_sk == Qnil) { rb_raise(rb_eArgError, "Secret key should have been given"); }
  if (RSTRING_LEN(_n)  != 24) { rb_raise(rb_eArgError, "nonce should be 24-byte long"); }
  if (RSTRING_LEN(_pk) != 32) { rb_raise(rb_eArgError, "public key should be 24-byte long"); }
  if (RSTRING_LEN(_sk) != 32) { rb_raise(rb_eArgError, "secret key should be 24-byte long"); }

  unsigned char * c = RSTRING_PTR(_c);
  char * nonce = RSTRING_PTR(_n);
  char * pk = RSTRING_PTR(_pk);
  char * sk = RSTRING_PTR(_sk);
  int padded_mlen = rb_str_strlen(_c);
  char * message = calloc(padded_mlen, sizeof(char));

  int res = crypto_box_open(message, c, padded_mlen, nonce, pk, sk);
  if (0 != res) { rb_raise(rb_eRuntimeError, "crypto_box_open did not work"); }

  return rb_str_new2(message + PADDING_LEN);
}

VALUE m_crypto_secretbox(VALUE self, VALUE _m, VALUE _n, VALUE _k) {
  if(_m == Qnil) { rb_raise(rb_eArgError, "A message should have been given"); }
  if(_k == Qnil) { rb_raise(rb_eArgError, "Secret key should have been given"); }
  if (RSTRING_LEN(_n)  != 24) { rb_raise(rb_eArgError, "nonce should be 24-byte long"); }
  if (RSTRING_LEN(_k) != 32) { rb_raise(rb_eArgError, "Secret key should be 24-byte long"); }

  char * message = RSTRING_PTR(_m);
  char * nonce = RSTRING_PTR(_n);
  char * k = RSTRING_PTR(_k);
  int len = strlen(message);
  char * padded_message = (char*)calloc(sizeof(char), len + PADDING_LEN);
  memcpy(padded_message + PADDING_LEN, message, strlen(message));
  char * c = malloc(strlen(message) + PADDING_LEN);
  int res = crypto_secretbox(c, padded_message, len + PADDING_LEN, nonce, k);
  if (0 != res) { fprintf(stderr, "Something went wrong\n"); exit(res); }
  VALUE ret = rb_str_new(c, len + PADDING_LEN);
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
  int padded_mlen = rb_str_strlen(_c);
  char * message = calloc(padded_mlen, sizeof(char));

  int res = crypto_secretbox_open(message, c, padded_mlen, nonce, k);
  if (0 != res) { rb_raise(rb_eRuntimeError, "crypto_secretbox_open did not work"); }

  return rb_str_new2(message + PADDING_LEN);
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
  if (0 != res) { fprintf(stderr, "crypto_sign did not work\n"); exit(res); }
  VALUE ret = rb_str_new(c, smlen);
  return ret;
}

VALUE m_crypto_sign_open(VALUE self, VALUE _c, VALUE _k) {
  if(_c == Qnil) { rb_raise(rb_eArgError, "A cipher should have been given"); }
  if(_k == Qnil) { rb_raise(rb_eArgError, "Public key should have been given"); }
  if (RSTRING_LEN(_k) != crypto_sign_PUBLICKEYBYTES) { rb_raise(rb_eArgError, "public key should be %d-byte long", crypto_sign_PUBLICKEYBYTES); }

  unsigned char * cipher = RSTRING_PTR(_c);
  int len = rb_str_strlen(_c);
  unsigned char * message = (unsigned char*)calloc(sizeof(unsigned char), len + 1);
  char * k = RSTRING_PTR(_k);
  unsigned long long int mlen = 0;

  int res = crypto_sign_open(message, &mlen, cipher, len, k);
  message[len] = 0;
  if (0 != res) { fprintf(stderr, "crypto_sign_open did not work. error %d\n", res); exit(res); }
  VALUE ret = rb_str_new(message, mlen);
  return ret;
}


void Init_tweetnacl() {
  VALUE c = rb_define_module("TweetNaCl");

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
}
