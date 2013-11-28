part of pbkdf2;

class Pbkdf2 {

  // default hash function
  SHA256 hash = new SHA256();
  HMAC hmac;

  /**
   *  Our pseudo-random function, taking in two byte arrays
   *  and returning the HMAC processed result
   */
  List<int> PRF(var password, var salt) {
    hmac = new HMAC(hash, password);
    hmac.add(salt);

    var res = hmac.close();
    // print('Digest: ${CryptoUtils.bytesToHex(toBytes(res))}');

    return res;
  }

  String generate(String password, String salt, int count, int length) {
    if(count == null || count == 0) {
      count = 1000; // default to some iteration
    }

    if(count <= 0) {
      throw ArgumentError("Iterations must be greater than or equal to 1");
    }

    if(length <= 0) {
      throw ArgumentError("Derived key length must be greater than or equal to 1");
    }

    // print(((pow(2, 32) - 1) * hash.newInstance().blockSize) ~/ 2);

    if(length > ((pow(2, 32) - 1) * hash.blockSize) ~/ 2) {
      throw('derived key too long');
    }

    var passwordBits = new List<int>();
    var saltBits = new List<int>();

    password.codeUnits.forEach((i) {
      passwordBits.add(i);
    });

    salt.codeUnits.forEach((i) {
      saltBits.add(i);
    });

    // iterator
    int l = -((-length / hash.blockSize).floor());
    int c = 1;
    int k = 1;

    var digest = new List<int>();
    var dk = new List<int>();
    var lastDigest = new List<int>();

    for(k = 1; k < l + 1; k++) {
      // concat the iterator value
      dk.addAll(saltBits);
      dk.addAll(toInt32Be(k));

      dk = PRF(passwordBits, dk);
      lastDigest = new List<int>.from(dk);

      // iterations - 1 since the
      // first round was done above
      for(c = 1; c < count; c++) {
        dk = new List<int>.from(PRF(passwordBits, dk));
        lastDigest = XOR(lastDigest, dk);
      }

      dk = lastDigest;
    }

    return CryptoUtils.bytesToHex(dk);
  }
}
