UTILTESTS=test/pbkdf2_util_test.dart
SHA1TESTS=test/sha1_test.dart
SHA256TESTS=test/sha256_test.dart
SHA1LONGTESTS=test/sha1_long_test.dart
SHA256LONGTESTS=test/sha256_long_test.dart

testutil:
	@dart $(UTILTESTS)

testsha1:
	@dart $(SHA1TESTS)

testsha256:
	@dart $(SHA256TESTS)

testsha1long:
	@dart $(SHA1LONGTESTS)

testsha256long:
	@dart $(SHA256LONGTESTS)

test:
	@make testutil
	@make testsha1
	@make testsha256

.PHONY: testutil testsha1 testsha256 testsha1long testsha256long test
