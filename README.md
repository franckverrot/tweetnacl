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


## TODO

* [x] crypto_box_keypair
* [x] crypto_box
* [x] crypto_box_open
* [x] crypto_secretbox
* [x] crypto_secretbox_open
* [ ] All the other functions !
* [ ] Use high-level objects

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
