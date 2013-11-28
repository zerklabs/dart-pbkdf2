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

     var l = -(-length / (hash.blockSize ~/ 2)).floor();
     var r = length - (l - 1) * (hash.blockSize ~/ 2);
     // print('length: ${length}, l: ${l}, r: ${r}');

     List<int> process(int i) {
       var dk = new List<int>();
       var lastDigest = new List<int>();

       // concat the iterator value
       dk.addAll(saltBits);
       dk.addAll(toInt32Be(i));

       dk = PRF(passwordBits, dk);
       lastDigest = new List<int>.from(dk);

       // iterations - 1 since the
       // first round was done above
       for(var c = 1; c < count; c++) {
         dk = new List<int>.from(PRF(passwordBits, dk));
         lastDigest = XOR(lastDigest, dk);
       }

       return lastDigest;
     }

     // based on the number of cycles expected, defined by `l`
     // generate a list the size of `l` and populate it with [1, 2, ...]
     var result = new List.generate(l, (int index) => index += 1).map(process);
     var key = '';

     if(result.length == 1) {
       key = CryptoUtils.bytesToHex(result.first).substring(0, length * 2);
     } else {
       var part1 = CryptoUtils.bytesToHex(result.first);
       var part2 = CryptoUtils.bytesToHex(result.last).substring(0, r * l);
       key = part1 + part2;
     }

       return key;
     }
   }
