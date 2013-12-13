// Test vectors from http://tools.ietf.org/html/draft-josefsson-pbkdf2-test-vectors-06#page-3
// utilizing SHA256
//
// validation test results from http://stackoverflow.com/a/5136918/507231

//
// Quad-core i7 @ 2.80Ghz
//
// SHA1
// generate took 0.004 seconds (4 ms) (c = 1)
// generate took 0.002 seconds (2 ms) (c = 2)
// generate took 0.573 seconds (573 ms) (c = 4096, dkLen = 25)
// generate took 0.162 seconds (162 ms) (c = 4096)
// generate took 0.078 seconds (78 ms) (c = 4096, dkLen = 16)
// generate took 333.583 seconds (333583 ms) (c = 16777216)

library pbkdf2_sha1_test;

import '../lib/pbkdf2.dart';
import 'package:crypto/crypto.dart';
import 'package:unittest/vm_config.dart';
import 'package:unittest/unittest.dart';
import 'package:utf/utf.dart';

const TEST_VECTOR_SHA1_HASHES = const {
  'c=16777216': 'eefe3d61cd4da4e4e9945b3d6ba2158c2634e984'
};


void testLongRunningSHA1Vectors() {
  test("16,777,216 Iterations with Strings", () {
    var pbkdf2 = new Pbkdf2(new SHA1());
    // pbkdf2.enableDebugging = true;
    String P = 'password';
    String S = 'salt';
    String c = 16777216;
    String dkLen = 20;
    var key = pbkdf2.generate(P, S, c, dkLen);

    expect(key, TEST_VECTOR_SHA1_HASHES['c=16777216']);
  });

  test("16,777,216 Iterations with Bytes", () {
    var pbkdf2 = new Pbkdf2(new SHA1());
    // pbkdf2.enableDebugging = true;
    List<int> P = encodeUtf8('password');
    List<int> S = encodeUtf8('salt');
    String c = 16777216;
    String dkLen = 20;
    var key = pbkdf2.generate(P, S, c, dkLen);

    expect(key, TEST_VECTOR_SHA1_HASHES['c=16777216']);
  });
}

void main() {
  useVMConfiguration();
  unittestConfiguration.useColor = true;

  group("PBKDF2-HMAC-SHA1 long-running test vectors:", () {
    testLongRunningSHA1Vectors();
  });
}
