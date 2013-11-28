// Copyright (c) 2013, Robin "cabrel" Harper.  Please see the AUTHORS file
// for details. All rights reserved. Use of this source code is governed by a
// MIT-style license that can be found in the LICENSE file.

// Test vectors from http://tools.ietf.org/html/draft-josefsson-pbkdf2-test-vectors-06#page-3
// utilizing SHA256
//
// validation test results from http://stackoverflow.com/a/5136918/507231

library pbkdf2test;
import '../lib/pbkdf2.dart';
import 'package:utf/utf.dart';
import 'package:unittest/unittest.dart';

void main() {
  group("PBKDF2-HMAC-SHA256 Test Vectors:", () {
    var pbkdf2 = new Pbkdf2();
    String P = 'password';
    String S = 'salt';
    String c = 1;
    String dkLen = 32;

    test("Password = 'password' / Salt = 'salt' / Iterations = 1 / Derived Key Length = 32", () {
      expect(pbkdf2.generate(P, S, c, dkLen), '120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b');
    });

    test("Password = 'password' / Salt = 'salt' / Iterations = 2 / Derived Key Length = 32", () {
      c = 2;
      expect(pbkdf2.generate(P, S, c, dkLen), 'ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43');
    });

    test("Password = 'password' / Salt = 'salt' / Iterations = 8 / Derived Key Length = 32", () {
      c = 8;
      expect(pbkdf2.generate(P, S, c, dkLen), '1f9955fb8ad6bcfa119b911d41f540bfc153dbe244e41158e7fa5311c91cb1b7');
    });

    test("Password = 'password' / Salt = 'salt' / Iterations = 4096 / Derived Key Length = 32", () {
      c = 4096;
      expect(pbkdf2.generate(P, S, c, dkLen), 'c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a');
    });

    test("Password = 'password' / Salt = 'salt' / Iterations = 16777216 / Derived Key Length = 32", () {
      c = 16777216;
      expect(pbkdf2.generate(P, S, c, dkLen), 'cf81c66fe8cfc04d1f31ecb65dab4089f7f179e89b3b0bcb17ad10e3ac6eba46');
    });

    test("Password = 'passwordPASSWORDpassword' / Salt = 'saltSALTsaltSALTsaltSALTsaltSALTsalt' / Iterations = 4096 / Derived Key Length = 40", () {
      c = 4096;
      dkLen = 40;
      P = 'passwordPASSWORDpassword';
      S = 'saltSALTsaltSALTsaltSALTsaltSALTsalt';
      expect(pbkdf2.generate(P, S, c, dkLen),
        '348c89dbcbd32b2f32d814b8116e84cf2b17347ebc1800181c4e2a1fb8dd53e1c635518c7dac47e9');
    });

    /**
     *  Currently lacking support for these kinds of edge cases. Will implement support soon
     */
    test("Password = 'pass\\0word' / Salt = 'sa\\0lt' / Iterations = 4096 / Derived Key Length = 16", () {
      c = 4096;
      dkLen = 16;
      P = 'pass\\0word';
      S = 'sa\\0lt';
      expect(pbkdf2.generate(P, S, c, dkLen), '89b69d0516f829893c696226650a8687');
    });
  });
}
