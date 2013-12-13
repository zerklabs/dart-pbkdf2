// Test vectors from http://tools.ietf.org/html/draft-josefsson-pbkdf2-test-vectors-06#page-3
// utilizing SHA256
//
// validation test results from http://stackoverflow.com/a/5136918/507231

//
// Quad-core i7 @ 2.80Ghz
//
// SHA256
// generate took 0.006 seconds (6 ms) (c = 1)
// generate took 0.006 seconds (6 ms) (c = 2)
// generate took 0.184 seconds (184 ms) (c = 4096)
// generate took 0.265 seconds (265 ms) (c = 4096, dkLen = 40)
// generate took 0.133 seconds (133 ms) (c = 4096, dkLen = 16)
// generate took 569.227 seconds (569227 ms) (c = 16777216)

library pbkdf2_sha256_test;

import '../lib/pbkdf2.dart';
import 'package:crypto/crypto.dart';
import 'package:unittest/vm_config.dart';
import 'package:unittest/unittest.dart';
import 'package:utf/utf.dart';

const TEST_VECTOR_SHA256_HASHES = const {
  'c=1': '120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b',
  'c=2': 'ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43',
  'c=4096': 'c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a',
  'c=4096dkLen=40': '348c89dbcbd32b2f32d814b8116e84cf2b17347ebc1800181c4e2a1fb8dd53e1c635518c7dac47e9',
  'c=4096dkLen=16': '89b69d0516f829893c696226650a8687'
};

void testStandardSHA256Vectors() {
  test("1 Iteration with Strings", () {
    var pbkdf2 = new Pbkdf2();
    // pbkdf2.enableDebugging = true;
    String P = 'password';
    String S = 'salt';
    String c = 1;
    String dkLen = 32;

    var key = pbkdf2.generate(P, S, c, dkLen);

    expect(key, TEST_VECTOR_SHA256_HASHES['c=1']);
  });

  test("1 Iteration with Bytes", () {
    var pbkdf2 = new Pbkdf2();
    // pbkdf2.enableDebugging = true;
    String P = encodeUtf8('password');
    String S = encodeUtf8('salt');
    String c = 1;
    String dkLen = 32;

    var key = pbkdf2.generate(P, S, c, dkLen);

    expect(key, TEST_VECTOR_SHA256_HASHES['c=1']);
  });

  test("2 Iterations with Strings", () {
    var pbkdf2 = new Pbkdf2();
    // pbkdf2.enableDebugging = true;
    String P = 'password';
    String S = 'salt';
    String c = 2;
    String dkLen = 32;
    var key = pbkdf2.generate(P, S, c, dkLen);

    expect(key, TEST_VECTOR_SHA256_HASHES['c=2']);
  });

  test("2 Iterations with Bytes", () {
    var pbkdf2 = new Pbkdf2();
    // pbkdf2.enableDebugging = true;
    List<int> P = encodeUtf8('password');
    List<int> S = encodeUtf8('salt');
    String c = 2;
    String dkLen = 32;
    var key = pbkdf2.generate(P, S, c, dkLen);

    expect(key, TEST_VECTOR_SHA256_HASHES['c=2']);
  });

  test("4096 Iterations with Strings", () {
    var pbkdf2 = new Pbkdf2();
    // pbkdf2.enableDebugging = true;
    String P = 'password';
    String S = 'salt';
    String c = 4096;
    String dkLen = 32;
    var key = pbkdf2.generate(P, S, c, dkLen);

    expect(key, TEST_VECTOR_SHA256_HASHES['c=4096']);
  });

  test("4096 Iterations with Bytes", () {
    var pbkdf2 = new Pbkdf2();
    // pbkdf2.enableDebugging = true;
    List<int> P = encodeUtf8('password');
    List<int> S = encodeUtf8('salt');
    String c = 4096;
    String dkLen = 32;
    var key = pbkdf2.generate(P, S, c, dkLen);

    expect(key, TEST_VECTOR_SHA256_HASHES['c=4096']);
  });

  test("4096 Iterations, dkLen = 40 with Strings", () {
    var pbkdf2 = new Pbkdf2();
    // pbkdf2.enableDebugging = true;
    String P = 'passwordPASSWORDpassword';
    String S = 'saltSALTsaltSALTsaltSALTsaltSALTsalt';
    String c = 4096;
    String dkLen = 40;
    var key = pbkdf2.generate(P, S, c, dkLen);

    expect(key, TEST_VECTOR_SHA256_HASHES['c=4096dkLen=40']);
    });

  test("4096 Iterations, dkLen = 40 with Bytes", () {
    var pbkdf2 = new Pbkdf2();
    // pbkdf2.enableDebugging = true;
    List<int> P = encodeUtf8('passwordPASSWORDpassword');
    List<int> S = encodeUtf8('saltSALTsaltSALTsaltSALTsaltSALTsalt');
    String c = 4096;
    String dkLen = 40;
    var key = pbkdf2.generate(P, S, c, dkLen);

    expect(key, TEST_VECTOR_SHA256_HASHES['c=4096dkLen=40']);
  });

  test("4096 Iterations, dkLen = 16 with Strings", () {
    var pbkdf2 = new Pbkdf2();
    // pbkdf2.enableDebugging = true;
    String P = r'pass\0word';
    String S = r'sa\0lt';
    String c = 4096;
    String dkLen = 16;
    var key = pbkdf2.generate(P, S, c, dkLen);

    expect(key, TEST_VECTOR_SHA256_HASHES['c=4096dkLen=16']);
  });

  test("4096 Iterations, dkLen = 16 with Bytes", () {
    var pbkdf2 = new Pbkdf2();
    // pbkdf2.enableDebugging = true;
    List<int> P = encodeUtf8(r'pass\0word');
    List<int> S = encodeUtf8(r'sa\0lt');
    String c = 4096;
    String dkLen = 16;
    var key = pbkdf2.generate(P, S, c, dkLen);

    expect(key, TEST_VECTOR_SHA256_HASHES['c=4096dkLen=16']);
  });
}

void main() {
  useVMConfiguration();
  unittestConfiguration.useColor = true;

  group("PBKDF2-HMAC-SHA256 test vectors:", () {
    testStandardSHA256Vectors();
  });
}
