# TweetNaCl for Ruby

## SUMMARY

TweetNaCl is a C-extension for Ruby built on top of the official TweetNacl
distribution. It exposes the basic functions using Ruby objects.

For a detailed explanation of TweetNaCl, [here's the research paper associated with it][paper]

## INSTALL

    gem install tweetnacl

## USAGE

    input = "<text to cipher>"
    nonce = "<a 24-char string>"

    pk, sk = TweetNaCl.crypto_box_keypair # This generates a pair of public and secret keys

    cipher = TweetNaCl.crypto_box(input, nonce, pk, sk) # Encrypt !

    output = TweetNaCl.crypto_box_open(cipher, nonce, pk, sk) # Decrypt!

    assert_equal input, output # They're the same !

## RUBY API

### KeyPair

A KeyPair object represents a pair of public and secret keys. They are created
with the `crypto_box_keypair` function call.

    keypair = KeyPair.new

One can also create a keypair with an existing tuple of keys like this:

    keypair = KeyPair.new(["<public_key>","<private_key>"])


### CryptoBox

#### initialize / new
A Cryptobox object contains all the methods required to sign, encrypt and verify
messages. It is instantiated like so:

    cb = CryptoBox.new(<Optional: KeyPair object>)

if no KeyPair is given, `CryptoBox` will create a new one by calling `KeyPair.new`

## FUNCTIONS

### crypto_box_keypair

Generate a pair of public and secret keys.

### crypto_box(input, nonce, public_key, secret_key)

Encrypt and sign the input given the other parameters.

### crypto_box_open(ciphered_message, nonce, public_key, secret_key)

Decrypt and verify the signature of the ciphered message given the other parameters.

### crypto_secretbox(input, nonce, public_key)

Encrypt the input given the other parameters.

### crypto_secretbox_open(ciphered_message, nonce, public_key)

Decrypt the ciphered message given the other parameters.

### crypto_sign_keypair

Generate a pair of public and secret keys.


## TODO

### Raw C-API
* [x] crypto_box (aliased crypto_box_curve25519xsalsa20poly1305)
* [x] crypto_box_open (aliased crypto_box_curve25519xsalsa20poly1305_open)
* [x] crypto_box_keypair
* [ ] crypto_box_beforenm
* [ ] crypto_box_afternm
* [ ] crypto_box_open_afternm
* [ ] crypto_core_salsa20
* [ ] crypto_core_hsalsa20
* [ ] crypto_hashblocks = crypto_hashblocks_sha512
* [ ] crypto_hash = crypto_hash_sha512
* [ ] crypto_onetimeauth = crypto_onetimeauth_poly1305
* [ ] crypto_onetimeauth_verify
* [ ] crypto_scalarmult = crypto_scalarmult_curve25519
* [ ] crypto_scalarmult_base
* [x] crypto_secretbox (aliased crypto_secretbox_xsalsa20poly1305)
* [x] crypto_secretbox_open (aliased crypto_secretbox_xsalsa20poly1305_open)
* [ ] crypto_sign = crypto_sign_ed25519
* [ ] crypto_sign_open
* [x] crypto_sign_keypair
* [ ] crypto_stream = crypto_stream_xsalsa20
* [ ] crypto_stream_xor
* [ ] crypto_stream_salsa20
* [ ] crypto_stream_salsa20_xor
* [ ] crypto_verify_16
* [ ] crypto_verify_32

### Ruby API

* [ ] Cryptobox object
* [ ] Secretbox object

## Is it PRODUCTION-READY?

No. And it never will.

## Is it secure?

No. Until proven otherwise.

## CONTRIBUTE

1. Fork it ( https://github.com/franckverrot/tweetnacl/fork )
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create new Pull Request

## LICENSE

Franck Verrot, Copyright 2014. See LICENSE.txt.


[paper] : http://tweetnacl.cr.yp.to/tweetnacl-20131229.pdf
