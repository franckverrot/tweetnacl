# Releases

## UNRELEASED

## 1.0.0 – Apr 30th 2019

### BREAKING CHANGES

* Drop leading 0s from encrypted boxes!

  A breaking change has been introduced to `crypto_box` and `crypto_secretbox`
  that makes ciphers differ.  The first 64 bits are always empty and have been
  dropped from the cipher output.

  This causes differences like:

```
  -    expected_cipher = "0000000000000000FBC937C3F136E09FA8A45C58C15E801394F5BB74CE8D538FE3D726"
  +    expected_cipher =                 "FBC937C3F136E09FA8A45C58C15E801394F5BB74CE8D538FE3D726"
```

  You might need to go through all persisted ciphers and change these values.

  If you have more questions, please file a ticket!  Thanks!

## 0.3.0 - Aug 19th 2014

* Added crypto\_sign\_key\_pair
* Added crypto\_sign
* Added crypto\_sign\_open
* Added a CryptoBox class to the Ruby API
* Added the C #define's to the Ruby API as constants under the TweetNacl module

## 0.2.0 

* Implemented the crypto\_box\_curve25519xsalsa20poly1305 functions
* Added a CHANGELOG file

## 0.0.1

* Initial release
* Implemented the crypto\_box functions
