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

  List<int> PRF(List<int> password, List<int> salt) {
    // default to SHA256
    var hash = new SHA256();
    var hmac = new HMAC(hash, password);
    var hmac1 = new HMAC(hash, password);

    hmac.add(salt);

    var digest = hmac.close();

    for(var j = 0; j < salt.length; j++) {
      digest[j] ^= salt[j];
    }

    return digest;
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

    var passwordBits = new List<int>();
    encodeUtf8(password).forEach((i) {
      // passwordBits.addAll(INT(i));
      passwordBits.add(i);
    });

    var saltBits = new List<int>();

    encodeUtf8(salt).forEach((i) {
      // saltBits.addAll(INT(i));
      saltBits.add(i);
    });

    // digest key
    List<int> dk = new List<int>();

    // iterator
    int k = 1;

    while(dk.length < length) {
      // a new collection to host salt + iterator
      var salt_k_concat = new List<int>();

      // concat the iterator value
      dk.addAll(saltBits);
      dk.addAll(INT(k));

      for(var i = 0; i < count; i++) {
        dk = PRF(passwordBits, dk);
      }

      k = k + 1;
    }

    if(dk.length > length) {
      throw("digest key too large");
    }

    return CryptoUtils.bytesToHex(dk);
  }
}

main() {
  var password = 'password';
  var salt = 'salt';
  var pbkdf2 = new Pbkdf2();

  var hash = new SHA256();

  var sha256_result_1_iter = pbkdf2.generate(password, salt, 1, 32);

  print('SHA256 Hash (1 iteration): ${sha256_result_1_iter}, length: ${sha256_result_1_iter.length}');
}
