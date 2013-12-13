library pbkdf2_util_test;

import '../lib/pbkdf2.dart';
import 'package:unittest/vm_config.dart';
import 'package:unittest/unittest.dart';

void testUtils() {
  test("toInt32Be", () {
    expect(toInt32Be(1), [00, 00, 00, 01]);
  });

  test("toBytes", () {
    expect(toBytes('salt'), ['73', '61', '6c', '74']);
  });

  test("replace should return the appropriate string with a null value in it", () {
    expect(replace(r'sa\0lt'), 'sa\u{0000}lt');
  });

  test("replace doesn't modify value if no matching characters found", () {
    expect(replace(r'salt'), 'salt');
  });

}

void main() {
  useVMConfiguration();
  unittestConfiguration.useColor = true;

  group("dart_pbkdf2 utils tests", () {
    testUtils();
  });
}
