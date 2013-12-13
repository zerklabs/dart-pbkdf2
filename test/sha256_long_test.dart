// Test vectors from http://tools.ietf.org/html/draft-josefsson-pbkdf2-test-vectors-06#page-3
// utilizing SHA256
//
// validation test results from http://stackoverflow.com/a/5136918/507231

//
// Quad-core i7 @ 2.80Ghz
//
// SHA256
// generate took 569.227 seconds (569227 ms) (c = 16777216)

library pbkdf2_sha256_long_test;

import '../lib/pbkdf2.dart';
import 'package:crypto/crypto.dart';
import 'package:unittest/vm_config.dart';
import 'package:unittest/unittest.dart';
import 'package:utf/utf.dart';

const TEST_VECTOR_SHA256_HASHES = const {
  'c=16777216': 'cf81c66fe8cfc04d1f31ecb65dab4089f7f179e89b3b0bcb17ad10e3ac6eba46'
};

void testLongRunningSHA256Vectors() {
  test("16,777,216 Iterations with Strings", () {
    var pbkdf2 = new Pbkdf2();
    // pbkdf2.enableDebugging = true;

    String P = 'password';
    String S = 'salt';
    String c = 16777216;
    String dkLen = 32;
    var key = pbkdf2.generate(P, S, c, dkLen);

    expect(key, TEST_VECTOR_SHA256_HASHES['c=16777216']);
  });

  test("16,777,216 Iterations with Bytes", () {
    var pbkdf2 = new Pbkdf2();
    // pbkdf2.enableDebugging = true;

    List<int> P = encodeUtf8('password');
    List<int> S = encodeUtf8('salt');
    String c = 16777216;
    String dkLen = 32;
    var key = pbkdf2.generate(P, S, c, dkLen);

    expect(key, TEST_VECTOR_SHA256_HASHES['c=16777216']);
  });
}

void main() {
  useVMConfiguration();
  unittestConfiguration.useColor = true;

  group("PBKDF2-HMAC-SHA256 long-running test vectors:", () {
    testLongRunningSHA256Vectors();
  });
}
