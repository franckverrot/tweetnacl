#include <ruby.h>
#include <ruby/encoding.h>
#include "tweetnacl.h"
#define PADDING_LEN 32

typedef struct {
} TweetNaCl;

static void tweetnacl_free() {
}

static VALUE tweetnacl_alloc(VALUE klass) {
  return Data_Wrap_Struct(klass, NULL, tweetnacl_free, ruby_xmalloc(sizeof(TweetNaCl)));
}

static VALUE tweetnacl_init(VALUE self) {
  return Qnil;
}

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
  if (0 != res) { rb_raise(rb_eRuntimeError, "la putain"); }

  return rb_str_new2(message + PADDING_LEN);
}

void Init_tweetnacl() {
  VALUE c = rb_define_class("TweetNaCl", rb_cObject);

  rb_define_alloc_func(c, tweetnacl_alloc);
  rb_define_private_method(c, "initialize", RUBY_METHOD_FUNC(tweetnacl_init), 0);
  rb_define_method(c, "crypto_box_keypair", RUBY_METHOD_FUNC(m_crypto_box_keypair), 0);
  rb_define_method(c, "crypto_box", RUBY_METHOD_FUNC(m_crypto_box), 4);
  rb_define_method(c, "crypto_box_open", RUBY_METHOD_FUNC(m_crypto_box_open), 4);
}
