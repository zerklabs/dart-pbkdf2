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

var keyFromString = pbkdf2.generateFromString(Password, Salt, iterations, derived_key_length);

OR 

List<int> password   = encodeUtf8("password");
List<int> salt       = encodeUtf8("salt");

var keyFromBytes = pbkdf2.generate(password, salt, iterations, derived_key_length);
```


## Tests:

```
make test
```




