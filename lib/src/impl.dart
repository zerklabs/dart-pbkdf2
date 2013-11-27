part of pbkdf2;

class Pbkdf2 {
// def INT(i):
//     assert i > 0
//     return struct.pack('>I', i)

// def xor(A, B):
//     return ''.join([chr(ord(a) ^ ord(b)) for a, b in zip(A, B)])

  // def pbkdf2(P, S, c, dkLen, PRF):
  //   hLen = PRF.digest_size

  //   if dkLen > (2**32 - 1) * hLen:
  //       raise Exception('derived key too long')

  //   l = -(-dkLen // hLen)
  //   r = dkLen - (l - 1) * hLen

  //   def F(i):
  //       def U():
  //           U = S + INT(i)
  //           for j in range(c):
  //               U = PRF(P, U)
  //               yield U

  //       return reduce(xor, U())

  //   T = map(F, range(1, l+1))

  //   DK = ''.join(T[:-1]) + T[-1][:r]
  //   return DK

  List<num> toBytes(var input) {
    var bytes = new List<num>();

    for(var i = 0; i < input.length; i++) {
      if(input[i] is num) {
        bytes.add(input[i].toRadixString(16));
      } else if(input[i] is String) {
        bytes.add(input.codeUnitAt(i).toRadixString(16));
      }
    }

    return bytes;
  }

  List<int> PRF(List<int> password, List<int> salt) {
    // default to SHA256
    var hash = new SHA256();
    var hmac = new HMAC(hash, password);

    hmac.add(salt);

    var result = hmac.close();

    return result;
  }

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

    if(count < 0 || length < 0) {
      throw("invalid params to pbkdf2");
    }

    if(length > (pow(2, 32) - 1) * 64) {
      throw('derived key too long');
    }

    // var passwordBits = toBytes(password);
    // var saltBits = toBytes(salt);
    var passwordBits = new List<int>();
    var saltBits = new List<int>();

    password.codeUnits.forEach((i) {
      passwordBits.add(i);
    });

    salt.codeUnits.forEach((i) {
      saltBits.add(i);
    });

    // digest key
    List<int> dk = new List<int>();

    // iterator
    int l = -((-length / 64).floor());
    int c = 0;
    int k = 1;

    for(k = 1; k < l + 1; k++) {
      // a new collection to host salt + iterator
      var salt_k_concat = new List<int>();

      // concat the iterator value
      dk.addAll(saltBits);
      dk.addAll(INT(k));

      for(c = 0; c < count; c++) {
        dk = PRF(passwordBits, dk);
      }
    }

    return CryptoUtils.bytesToHex(dk);
  }
}
