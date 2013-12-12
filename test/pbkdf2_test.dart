// Test vectors from http://tools.ietf.org/html/draft-josefsson-pbkdf2-test-vectors-06#page-3
// utilizing SHA256
//
// validation test results from http://stackoverflow.com/a/5136918/507231

library pbkdf2test;

import '../lib/pbkdf2.dart';
import 'package:crypto/crypto.dart';
import 'package:unittest/vm_config.dart';
import 'package:unittest/unittest.dart';

const TEST_VECTOR_SHA256_HASHES = const {
  'c=1': '120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b',
  'c=2': 'ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43',
  'c=4096': 'c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a',
  'c=16777216': 'cf81c66fe8cfc04d1f31ecb65dab4089f7f179e89b3b0bcb17ad10e3ac6eba46',
  'c=4096dkLen=40': '348c89dbcbd32b2f32d814b8116e84cf2b17347ebc1800181c4e2a1fb8dd53e1c635518c7dac47e9',
  'c=4096dkLen=16': '89b69d0516f829893c696226650a8687'
};

const TEST_VECTOR_SHA1_HASHES = const {
  'c=1': '0c60c80f961f0e71f3a9b524af6012062fe037a6',
  'c=2': 'ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957',
  'c=4096': '4b007901b765489abead49d926f721d065a429c1',
  'c=16777216': 'eefe3d61cd4da4e4e9945b3d6ba2158c2634e984',
  'c=4096dkLen=25': '3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038',
  'c=4096dkLen=16': '56fa6aa75548099dcc37d7f03425e0c3'
};

void testLongRunningSHA256Vectors() {
  test("16,777,216 Iterations", () {
    var pbkdf2 = new Pbkdf2();
    // pbkdf2.enableDebugging = true;

    String P = 'password';
    String S = 'salt';
    String c = 16777216;
    String dkLen = 32;
    var key = pbkdf2.generate(P, S, c, dkLen);

    // logMessage('Input');
    // logMessage('\tPassword = ${P}');
    // logMessage('\tSalt = ${S}');
    // logMessage('\tc = ${c}');
    // logMessage('\tdkLen = ${dkLen}');
    // logMessage('Output');
    // logMessage('\tDK = ${key}');

    expect(key, TEST_VECTOR_SHA256_HASHES['c=16777216']);
  });
}

void testStandardSHA256Vectors() {
  test("1 Iteration", () {
    var pbkdf2 = new Pbkdf2();
    // pbkdf2.enableDebugging = true;
    String P = 'password';
    String S = 'salt';
    String c = 1;
    String dkLen = 32;

    // logMessage('Input');
    // logMessage('\tPassword = ${P}');
    // logMessage('\tSalt = ${S}');
    // logMessage('\tc = ${c}');
    // logMessage('\tdkLen = ${dkLen}');

    var key = pbkdf2.generate(P, S, c, dkLen);
    // logMessage('Output');
    // logMessage('\tDK = ${key}');

    expect(key, TEST_VECTOR_SHA256_HASHES['c=1']);
  });

  test("2 Iterations", () {
    var pbkdf2 = new Pbkdf2();
    // pbkdf2.enableDebugging = true;
    String P = 'password';
    String S = 'salt';
    String c = 2;
    String dkLen = 32;

    // logMessage('Input');
    // logMessage('\tPassword = ${P}');
    // logMessage('\tSalt = ${S}');
    // logMessage('\tc = ${c}');
    // logMessage('\tdkLen = ${dkLen}');

    var key = pbkdf2.generate(P, S, c, dkLen);
    // logMessage('Output');
    // logMessage('\tDK = ${key}');

    expect(key, TEST_VECTOR_SHA256_HASHES['c=2']);
  });

  test("4096 Iterations", () {
    var pbkdf2 = new Pbkdf2();
    // pbkdf2.enableDebugging = true;
    String P = 'password';
    String S = 'salt';
    String c = 4096;
    String dkLen = 32;
    var key = pbkdf2.generate(P, S, c, dkLen);

    // logMessage('Input');
    // logMessage('\tPassword = ${P}');
    // logMessage('\tSalt = ${S}');
    // logMessage('\tc = ${c}');
    // logMessage('\tdkLen = ${dkLen}');
    // logMessage('Output');
    // logMessage('\tDK = ${key}');


    expect(key, TEST_VECTOR_SHA256_HASHES['c=4096']);
  });

  test("4096 Iterations, Derived Key Length = 40", () {
    var pbkdf2 = new Pbkdf2();
    // pbkdf2.enableDebugging = true;
    String P = 'passwordPASSWORDpassword';
    String S = 'saltSALTsaltSALTsaltSALTsaltSALTsalt';
    String c = 4096;
    String dkLen = 40;
    var key = pbkdf2.generate(P, S, c, dkLen);

    // logMessage('Input');
    // logMessage('\tPassword = ${P}');
    // logMessage('\tSalt = ${S}');
    // logMessage('\tc = ${c}');
    // logMessage('\tdkLen = ${dkLen}');
    // logMessage('Output');
    // logMessage('\tDK = ${key}');

    expect(key, TEST_VECTOR_SHA256_HASHES['c=4096dkLen=40']);
  });

    /**
     *  Currently lacking support for these kinds of edge cases. Will implement support soon
     */
    test("4096 Iterations, Derived Key Length = 16", () {
      var pbkdf2 = new Pbkdf2();
    // pbkdf2.enableDebugging = true;
      String P = 'pass\u{0000}word';
      String S = 'sa\u{0000}lt';
      String c = 4096;
      String dkLen = 16;
      var key = pbkdf2.generate(P, S, c, dkLen);

      // logMessage('Input');
      // logMessage('\tPassword = ${P}');
      // logMessage('\tSalt = ${S}');
      // logMessage('\tc = ${c}');
      // logMessage('\tdkLen = ${dkLen}');
      // logMessage('Output');
      // logMessage('\tDK = ${key}');

      expect(key, TEST_VECTOR_SHA256_HASHES['c=4096dkLen=16']);
    });
}

void testLongRunningSHA1Vectors() {
  test("16,777,216 Iterations", () {
    var pbkdf2 = new Pbkdf2(new SHA1());
    // pbkdf2.enableDebugging = true;

    String P = 'password';
    String S = 'salt';
    String c = 16777216;
    String dkLen = 20;
    var key = pbkdf2.generate(P, S, c, dkLen);

    // logMessage('Input');
    // logMessage('\tPassword = ${P}');
    // logMessage('\tSalt = ${S}');
    // logMessage('\tc = ${c}');
    // logMessage('\tdkLen = ${dkLen}');
    // logMessage('Output');
    // logMessage('\tDK = ${key}');

    expect(key, TEST_VECTOR_SHA1_HASHES['c=16777216']);
  });
}

void testStandardSHA1Vectors() {
  test("1 Iteration", () {
    var pbkdf2 = new Pbkdf2(new SHA1());
    // pbkdf2.enableDebugging = true;
    String P = 'password';
    String S = 'salt';
    String c = 1;
    String dkLen = 20;
    var key = pbkdf2.generate(P, S, c, dkLen);

    // logMessage('Input');
    // logMessage('\tPassword = ${P}');
    // logMessage('\tSalt = ${S}');
    // logMessage('\tc = ${c}');
    // logMessage('\tdkLen = ${dkLen}');
    // logMessage('Output');
    // logMessage('\tDK = ${key}');

    expect(key, TEST_VECTOR_SHA1_HASHES['c=1']);
  });

  test("2 Iterations", () {
    var pbkdf2 = new Pbkdf2(new SHA1());
    // pbkdf2.enableDebugging = true;
    String P = 'password';
    String S = 'salt';
    String c = 2;
    String dkLen = 20;
    var key = pbkdf2.generate(P, S, c, dkLen);

    // logMessage('Input');
    // logMessage('\tPassword = ${P}');
    // logMessage('\tSalt = ${S}');
    // logMessage('\tc = ${c}');
    // logMessage('\tdkLen = ${dkLen}');
    // logMessage('Output');
    // logMessage('\tDK = ${key}');

    expect(key, TEST_VECTOR_SHA1_HASHES['c=2']);
  });

  test("4096 Iterations", () {
    var pbkdf2 = new Pbkdf2(new SHA1());
    // pbkdf2.enableDebugging = true;
    String P = 'password';
    String S = 'salt';
    String c = 4096;
    String dkLen = 20;
    var key = pbkdf2.generate(P, S, c, dkLen);

    // logMessage('Input');
    // logMessage('\tPassword = ${P}');
    // logMessage('\tSalt = ${S}');
    // logMessage('\tc = ${c}');
    // logMessage('\tdkLen = ${dkLen}');
    // logMessage('Output');
    // logMessage('\tDK = ${key}');

    expect(key, TEST_VECTOR_SHA1_HASHES['c=4096']);
  });

  test("4096 Iterations, Derived Key Length = 25", () {
    var pbkdf2 = new Pbkdf2(new SHA1());
    // pbkdf2.enableDebugging = true;
    String P = 'passwordPASSWORDpassword';
    String S = 'saltSALTsaltSALTsaltSALTsaltSALTsalt';
    String c = 4096;
    String dkLen = 25;
    var key = pbkdf2.generate(P, S, c, dkLen);

    // logMessage('Input');
    // logMessage('\tPassword = ${P}');
    // logMessage('\tSalt = ${S}');
    // logMessage('\tc = ${c}');
    // logMessage('\tdkLen = ${dkLen}');
    // logMessage('Output');
    // logMessage('\tDK = ${key}');

    expect(key, TEST_VECTOR_SHA1_HASHES['c=4096dkLen=25']);
  });

    /**
     *  Currently lacking support for these kinds of edge cases. Will implement support soon
     */
    test("4096 Iterations, Derived Key Length = 16", () {
      var pbkdf2 = new Pbkdf2(new SHA1());

      // pbkdf2.enableDebugging = true;

      String P = 'pass\u{0000}word';
      String S = 'sa\u{0000}lt';
      String c = 4096;
      String dkLen = 16;
      var key = pbkdf2.generate(P, S, c, dkLen);

      // logMessage('Input');
      // logMessage('\tPassword = ${P}');
      // logMessage('\tSalt = ${S}');
      // logMessage('\tc = ${c}');
      // logMessage('\tdkLen = ${dkLen}');
      // logMessage('Output');
      // logMessage('\tDK = ${key}');

      expect(key, TEST_VECTOR_SHA1_HASHES['c=4096dkLen=16']);
    });
}

void testUtils() {
  test("toInt32Be", () {
    expect(toInt32Be(1), [00, 00, 00, 01]);
  });

  test("toBytes", () {
    expect(toBytes('salt'), ['73', '61', '6c', '74']);
  });

}


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
//
// SHA1
// generate took 0.004 seconds (4 ms) (c = 1)
// generate took 0.002 seconds (2 ms) (c = 2)
// generate took 0.573 seconds (573 ms) (c = 4096, dkLen = 25)
// generate took 0.162 seconds (162 ms) (c = 4096)
// generate took 0.078 seconds (78 ms) (c = 4096, dkLen = 16)
// generate took 333.583 seconds (333583 ms) (c = 16777216)

void main() {
  useVMConfiguration();
  unittestConfiguration.useColor = true;

  group("dart_pbkdf2 utils tests", () {
    testUtils();
  });

  group("PBKDF2-HMAC-SHA256 Test Vectors:", () {
    testStandardSHA256Vectors();
    // print('Long running tests for SHA256 are disabled');
    testLongRunningSHA256Vectors();
  });

  group("PBKDF2-HMAC-SHA1 Test Vectors:", () {
    testStandardSHA1Vectors();
    // print('Long running tests for SHA1 are disabled');
    testLongRunningSHA1Vectors();
  });
}
