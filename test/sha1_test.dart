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
  'c=1': '0c60c80f961f0e71f3a9b524af6012062fe037a6',
  'c=2': 'ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957',
  'c=4096': '4b007901b765489abead49d926f721d065a429c1',
  'c=4096dkLen=25': '3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038',
  'c=4096dkLen=16': '56fa6aa75548099dcc37d7f03425e0c3'
};


void testStandardSHA1Vectors() {
  test("1 Iteration with Strings", () {
    var pbkdf2 = new Pbkdf2(new SHA1());
    // pbkdf2.enableDebugging = true;
    String P = 'password';
    String S = 'salt';
    String c = 1;
    String dkLen = 20;
    var key = pbkdf2.generate(P, S, c, dkLen);

    expect(key, TEST_VECTOR_SHA1_HASHES['c=1']);
  });

  test("1 Iteration with Bytes", () {
    var pbkdf2 = new Pbkdf2(new SHA1());
    // pbkdf2.enableDebugging = true;
    List<int> P = encodeUtf8('password');
    List<int> S = encodeUtf8('salt');
    String c = 1;
    String dkLen = 20;
    var key = pbkdf2.generate(P, S, c, dkLen);

    expect(key, TEST_VECTOR_SHA1_HASHES['c=1']);
  });

  test("2 Iterations with Strings", () {
    var pbkdf2 = new Pbkdf2(new SHA1());
    // pbkdf2.enableDebugging = true;
    String P = 'password';
    String S = 'salt';
    String c = 2;
    String dkLen = 20;
    var key = pbkdf2.generate(P, S, c, dkLen);

    expect(key, TEST_VECTOR_SHA1_HASHES['c=2']);
  });

  test("2 Iterations with Bytes", () {
    var pbkdf2 = new Pbkdf2(new SHA1());
    // pbkdf2.enableDebugging = true;
    String P = encodeUtf8('password');
    String S = encodeUtf8('salt');
    String c = 2;
    String dkLen = 20;
    var key = pbkdf2.generate(P, S, c, dkLen);

    expect(key, TEST_VECTOR_SHA1_HASHES['c=2']);
  });

  test("4096 Iterations with Strings", () {
    var pbkdf2 = new Pbkdf2(new SHA1());
    // pbkdf2.enableDebugging = true;
    String P = 'password';
    String S = 'salt';
    String c = 4096;
    String dkLen = 20;
    var key = pbkdf2.generate(P, S, c, dkLen);

    expect(key, TEST_VECTOR_SHA1_HASHES['c=4096']);
  });

  test("4096 Iterations with Bytes", () {
    var pbkdf2 = new Pbkdf2(new SHA1());
    // pbkdf2.enableDebugging = true;
    String P = encodeUtf8('password');
    String S = encodeUtf8('salt');
    String c = 4096;
    String dkLen = 20;
    var key = pbkdf2.generate(P, S, c, dkLen);

    expect(key, TEST_VECTOR_SHA1_HASHES['c=4096']);
  });

  test("4096 Iterations, dkLen = 25 with Strings", () {
    var pbkdf2 = new Pbkdf2(new SHA1());
    // pbkdf2.enableDebugging = true;
    String P = 'passwordPASSWORDpassword';
    String S = 'saltSALTsaltSALTsaltSALTsaltSALTsalt';
    String c = 4096;
    String dkLen = 25;
    var key = pbkdf2.generate(P, S, c, dkLen);

    expect(key, TEST_VECTOR_SHA1_HASHES['c=4096dkLen=25']);
  });

  test("4096 Iterations, dkLen = 25 with Bytes", () {
    var pbkdf2 = new Pbkdf2(new SHA1());
    // pbkdf2.enableDebugging = true;
    String P = encodeUtf8('passwordPASSWORDpassword');
    String S = encodeUtf8('saltSALTsaltSALTsaltSALTsaltSALTsalt');
    String c = 4096;
    String dkLen = 25;
    var key = pbkdf2.generate(P, S, c, dkLen);

    expect(key, TEST_VECTOR_SHA1_HASHES['c=4096dkLen=25']);
  });

    test("4096 Iterations, dkLen = 16 with Strings", () {
      var pbkdf2 = new Pbkdf2(new SHA1());
      // pbkdf2.enableDebugging = true;

      String P = r'pass\0word';
      String S = r'sa\0lt';
      String c = 4096;
      String dkLen = 16;
      var key = pbkdf2.generate(P, S, c, dkLen);

      expect(key, TEST_VECTOR_SHA1_HASHES['c=4096dkLen=16']);
    });

    test("4096 Iterations, dkLen = 16 with Bytes", () {
      var pbkdf2 = new Pbkdf2(new SHA1());
      // pbkdf2.enableDebugging = true;

      List<int> P = encodeUtf8(r'pass\0word');
      List<int> S = encodeUtf8(r'sa\0lt');
      String c = 4096;
      String dkLen = 16;
      var key = pbkdf2.generate(P, S, c, dkLen);

      expect(key, TEST_VECTOR_SHA1_HASHES['c=4096dkLen=16']);
    });
}

void main() {
  useVMConfiguration();
  unittestConfiguration.useColor = true;

  group("PBKDF2-HMAC-SHA1 test vectors:", () {
    testStandardSHA1Vectors();
  });
}
