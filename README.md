dart_pbkdf2
===========

License: MIT

Dart implementation of the [PBKDF2](http://en.wikipedia.org/wiki/PBKDF2) key derivation function


__This current version only implements PBKDF2 HMAC-SHA256. I'll be adding in support for user-defined hashes soon.__

## Usage:

```
var pbkdf2 = new Pbkdf2();

var key = pbkdf2.generate(Password, Salt, iterations, derived_key_length);
```


## Tests:

```
dart test/pbkdf2_test.dart
```




