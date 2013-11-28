dart_pbkdf2
===========

License: MIT

Dart implementation of the [PBKDF2](http://en.wikipedia.org/wiki/PBKDF2) key derivation function


## Usage:

```
// default is to use SHA256
var pbkdf2 = new Pbkdf2();

// to use SHA1
var pbkdf2 = new Pbkdf2(new SHA1());

var key = pbkdf2.generate(Password, Salt, iterations, derived_key_length);
```


## Tests:

```
dart test/pbkdf2_test.dart
```




