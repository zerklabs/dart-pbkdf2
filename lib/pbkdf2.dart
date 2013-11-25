/**
 *  Port of pbkdf2 from SJCL.
 *
 *  See https://github.com/bitwiseshiftleft/sjcl/tree/master/README for licensing information. Original source is
 *  included verbatim below
 */


/// /** @fileOverview Password-based key-derivation function, version 2.0.
/// *
/// * @author Emily Stark
/// * @author Mike Hamburg
/// * @author Dan Boneh
/// */
///
/// /** Password-Based Key-Derivation Function, version 2.0.
/// *
/// * Generate keys from passwords using PBKDF2-HMAC-SHA256.
/// *
/// * This is the method specified by RSA's PKCS #5 standard.
/// *
/// * @param {bitArray|String} password  The password.
/// * @param {bitArray|String} salt The salt.  Should have lots of entropy.
/// * @param {Number} [count=1000] The number of iterations.  Higher numbers make the function slower but more secure.
/// * @param {Number} [length] The length of the derived key.  Defaults to the
///                            output size of the hash function.
/// * @param {Object} [Prff=sjcl.misc.hmac] The pseudorandom function family.
/// * @return {bitArray} the derived key.
/// */
/// sjcl.misc.pbkdf2 = function (password, salt, count, length, Prff) {
///   count = count || 1000;
///
///   if (length < 0 || count < 0) {
///     throw sjcl.exception.invalid("invalid params to pbkdf2");
///   }
///
///   if (typeof password === "string") {
///     password = sjcl.codec.utf8String.toBits(password);
///   }
///
///   if (typeof salt === "string") {
///     salt = sjcl.codec.utf8String.toBits(salt);
///   }
///
///   Prff = Prff || sjcl.misc.hmac;
///
///   var prf = new Prff(password),
///       u, ui, i, j, k, out = [], b = sjcl.bitArray;
///
///   for (k = 1; 32 * out.length < (length || 1); k++) {
///     u = ui = prf.encrypt(b.concat(salt,[k]));
///
///     for (i=1; i<count; i++) {
///       ui = prf.encrypt(ui);
///       for (j=0; j<ui.length; j++) {
///         u[j] ^= ui[j];
///       }
///     }
///
///     out = out.concat(u);
///   }
///
///   if (length) { out = b.clamp(out, length); }
///
///   return out;
/// };


library pbkdf2;
import "package:utf/utf.dart";

Future<String> pbkdf2(String password, String salt, int count, int length) {
  var completer = new Completer();

  List<int> passwordBits;
  List<int> saltBits;
  List<int> out = new List<int>();

  if(count == null || count == 0) {
    count = 1000; // default to some iteration
  }

  if(length < 0 || count < 0) {
    throw("invalid params to pbkdf2");
  }

  passwordBits = utf.encodeUtf8(password);
  saltBits = utf.encodeUtf8(salt);

  // the SJCL implementation defaults to SHA256 for the HMAC hash if not explicitly defined
  var sha256 = new SHA256();
  var hmac = new HMAC(sha256, passwordBits);

  for(var k = 1; 32 * out.length < (length || 1); k++) {
    var temp = new List<int>();
    temp.addAll(saltBits);
    temp.addAll([k]);

    var u = ui = hmac.add(temp).digest;

    for(var i = 1; i < count; i++) {
      ui = hmac.add(ui).digest;

      for(var j = 0; j < ui.length; j++) {
        u[j] ^= ui[j];
      }
    }

    out.addAll(u);
  }

  if(length) {
    out.removeRange(length, out.length);
  }

  completer.complete(utf.decodeUtf8(out));

  return completer.future;
}
