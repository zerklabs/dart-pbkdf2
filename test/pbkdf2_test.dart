// Copyright (c) 2013, Robin "cabrel" Harper.  Please see the AUTHORS file
// for details. All rights reserved. Use of this source code is governed by a
// MIT-style license that can be found in the LICENSE file.

// Test vectors from http://stackoverflow.com/a/5136918/507231

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

    test("Password = 'password' / Salt = 'salt' / Iterations = 4096 / Derived Key Length = 32", () {
      c = 4096;
      expect(pbkdf2.generate(P, S, c, dkLen), 'c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a');
    });
  });

  group("pbkdf2 utility functions", () {
    var pbkdf2 = new Pbkdf2();

    test("INT", () {
      expect(pbkdf2.INT(1), [00, 00, 00, 01]);
    });

    test("toBytes", () {
     expect(pbkdf2.toBytes('salt'), ['73', '61', '6c', '74']);
    });

  });
}
