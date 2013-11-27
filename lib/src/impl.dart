part of pbkdf2;

class Pbkdf2 {

  // default hash function
  SHA256 hash = new SHA256();

  List<int> toBytes(var input) {
    var bytes = new List<int>();

    for(var i = 0; i < input.length; i++) {
      int x;

      if(input[i] is int) {
        x = input[i].toRadixString(16);
      } else if(input[i] is String) {
        x = input.codeUnitAt(i).toRadixString(16);
      }

      bytes.add(x);
    }

    return bytes;
  }

  List<int> XOR(var a1, var a2) {
    var result = new List<int>();
    var comb = new IterableZip([a1, a2]);

    comb.forEach((i) {
      result.add(i[0] ^ i[1]);
    });

    return result;
  }

  /**
   *  Our pseudo-random function, taking in two byte arrays
   *  and returning the HMAC processed result
   */
  List<int> PRF(var password, var salt) {
    var hmac = new HMAC(hash, password);
    hmac.add(salt);

    return hmac.close();
  }

  /**
   *  Convert an int to a 32-bit big-endian representation
   */
  List<int> INT(int input) {
    var buffer = new List<int>();
    buffer.add((input >> 24) & 0xFF);
    buffer.add((input >> 16) & 0xFF);
    buffer.add((input >> 8) & 0xFF);
    buffer.add(input & 0xFF);

    return buffer;
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

    for(k = 1; k < l + 1; k++) {
      // round 1 derived key storage
      var dk = new List<int>();

      // concat the iterator value
      dk.addAll(saltBits);
      dk.addAll(INT(k));

      digest = PRF(passwordBits, dk);
      var previous = new List<int>();

      // iterations - 1 since the
      // first round was done above
      for(c = 1; c < count; c++) {
        previous = digest;
        digest = PRF(passwordBits, digest);
        digest = XOR(digest, previous);
      }
    }

    return CryptoUtils.bytesToHex(digest);
  }
}
