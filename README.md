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

// [Password] and [Salt] can be List<int> or Strings
var key = pbkdf2.generate(Password, Salt, iterations, derived_key_length);
```


## Tests:

```
# run only the util tests
make testutil

# run only the SHA1 tests (excluding the longest running)
make testsha1

# run only the SHA256 tests (excluding the longest running)
make testsha256

# run the SHA1 longest running tests
make testsha1long

# run the SHA256 longest running tests
make testsha256long

# or run all of the tests, except the longest running
make test
```




