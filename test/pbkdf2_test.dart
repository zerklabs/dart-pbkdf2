// Copyright (c) 2013, Robin "cabrel" Harper.  Please see the AUTHORS file
// for details. All rights reserved. Use of this source code is governed by a
// MIT-style license that can be found in the LICENSE file.

// Test vectors from http://stackoverflow.com/a/5136918/507231

library pbkdf2test;
import '../lib/pbkdf2.dart';
import 'package:unittest/unittest.dart';

void main() {
  group("PBKDF2-HMAC-SHA256 Test Vectors", () {
    test("P=password/S=salt/c=1/dkLen=32", () {
      var pbkdf2 = new Pbkdf2();
      var dk = pbkdf2.generate('password', 'salt', 1, 32);
      expect(dk, '120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b');
    });
  });

  group("pbkdf2 utility functions", () {
    test("_INT", () {
      var pbkdf2 = new Pbkdf2();
      var _int = pbkdf2.INT(1);
      expect(_int, [00, 00, 00, 01]);
    });
  });
}
