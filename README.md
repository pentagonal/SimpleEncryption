# Pentagonal Simple Encryption
Another Encryption Helper

[![Build Status](https://travis-ci.org/pentagonal/SimpleEncryption.svg?branch=master)](https://travis-ci.org/pentagonal/SimpleEncryption)

Encrypt string or another type of value to encryption.
by default encryption use `openssl` with default `AES-256-CBC`
and another encryption using alternative of `str_rot13` and encoded by `base64_encode`

## Encryption

```php
/**
 * Using default encryption mcrypt
 */
Pentagonal\SimpleEncryption\Encryption::encrypt('string to encrypt', 'saltkey');

/**
 * Using alternative type
 */
Pentagonal\SimpleEncryption\Encryption::altEncrypt('string to encrypt', 'saltkey');
```

## Decryption

```php
/**
 * Decrypt encrypted string with auto detect encryption use
 */
Pentagonal\SimpleEncryption\Encryption::decrypt('string to decrypt', 'saltkey');

// or can use
Pentagonal\SimpleEncryption\Encryption::altDecrypt('string to decrypt', 'saltkey');
```

## Install Using Composer

[Composer](https://getcomposer.org) is handy tool for adding library easily from packagist and another resource to your application.
Get Install on here : [https://getcomposer.org](https://getcomposer.org) and install on your OS.

```json
{
  "require": {
        "pentagonal/simple-encryption" : "~1.0"
  }
}
```

## Requirements

This library require php 5.3.2 or later. Suggest to enable `openssl` on your php configuration.

## License

MIT License [https://opensource.org/licenses/MIT](https://opensource.org/licenses/MIT)
