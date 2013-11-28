// Copyright (c) 2013, Robin "cabrel" Harper.  Please see the AUTHORS file
// for details. All rights reserved. Use of this source code is governed by a
// MIT-style license that can be found in the LICENSE file.

// Test vectors from http://stackoverflow.com/a/5136918/507231

library pbkdf2_utils_test;
import '../lib/pbkdf2.dart';
import 'package:utf/utf.dart';
import 'package:unittest/unittest.dart';

void main() {
  group("pbkdf2 utility functions", () {
    test("toInt32Be", () {
      expect(toInt32Be(1), [00, 00, 00, 01]);
    });

    test("toBytes", () {
     expect(toBytes('salt'), ['73', '61', '6c', '74']);
    });

  });
}
