part of pbkdf2;

class Pbkdf2 {

  // flag to control print statements
  bool enableDebugging = false;

  Hash hash;
  HMAC hmac;

  // Constructor
  //
  // Hash can be any hash defined in the Crypto
  // package (SHA1, SHA256, ...)
  //
  // If one is not explicitly given, then we default to SHA256
  Pbkdf2([Hash hash]) {
    if(hash != null) {
      this.hash = hash;
    } else {
      this.hash = new SHA256();
    }
  }

  // XOR's each value in the first list (A) with the value in the same
  // position in the second list (B)
  List<int> XOR(var A, var B) {
    Stopwatch stopwatch = new Stopwatch()..start();

    var result = new List<int>(A.length);
    var comb = new IterableZip([A, B]);

    for(var x = 0; x < result.length; x++) {
      var e = comb.elementAt(x);
      result[x] = toBytes(e[0] ^ e[1])[0];
    }

     stopwatch.stop();

     if(enableDebugging) {
       if(stopwatch.elapsedMilliseconds > 0.01) {
         print('XOR took ${stopwatch.elapsedMilliseconds / 1000} seconds (${stopwatch.elapsedMilliseconds} ms)');
       }
     }

    return result;
  }

   /// Our pseudo-random function, taking in two byte arrays
   /// and returning the HMAC processed result
   List<int> PRF(var password, var salt) {
     Stopwatch stopwatch = new Stopwatch()..start();

     hmac = new HMAC(hash.newInstance(), password);
     hmac.add(salt);

     var res = hmac.close();

     stopwatch.stop();

     if(enableDebugging) {
       if(stopwatch.elapsedMilliseconds > 0.01) {
         print('PRF took ${stopwatch.elapsedMilliseconds / 1000} seconds (${stopwatch.elapsedMilliseconds} ms)');
       }
     }

     return res;
   }


    /// The [password] and [salt] can be either Strings or Lists<int> (of bytes)
    ///
    /// If no count is given, we default to 1000
   String generate(var password, var salt, int count, int length) {
     Stopwatch stopwatch = new Stopwatch()..start();
     var hashLength = hash.newInstance().close().length;

     List<int> passwordBits;
     List<int> saltBits;

     if(count == null || count == 0) {
       count = 1000; // default to some iteration
     }

     if(count <= 0) {
       throw new ArgumentError("Iterations must be greater than or equal to 1");
     }

     if(length <= 0) {
       throw new ArgumentError("Derived key length must be greater than or equal to 1");
     }

     if(length > ((pow(2, 32) - 1) * hashLength)) {
       throw('derived key too long');
     }

     if(password is List<int>) {
       passwordBits = encodeUtf8(replace(decodeUtf8(password)));
     } else if(password is String) {
       passwordBits = encodeUtf8(replace(password));
     } else {
       throw new ArgumentError("Invalid type for [password]");
     }

     if(salt is List<int>) {
       saltBits = encodeUtf8(replace(decodeUtf8(salt)));
     } else if(salt is String) {
       saltBits = encodeUtf8(replace(salt));
     } else {
       throw new ArgumentError("Invalid type for [salt]");
     }

     int l = -(-(length ~/ hashLength));
     int r = length - (l - 1) * hashLength;

     if(enableDebugging) {
       print('r: ${r}, l: ${l}, length: ${length}, hash length: ${hashLength}');
     }

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
     var result = new List.generate(l + 1, (int index) => index += 1).map(process);

     var key = CryptoUtils.bytesToHex(result.first);

     if(key.length < length * 2) {
       if(result.length > 1) {
         key += CryptoUtils.bytesToHex(result.last).substring(0, (r - hashLength) * 2);
       }
     } else if (key.length > length) {
       if(result.length == 1) {
         key = key.substring(0, length * 2);
       }
     }

     stopwatch.stop();
     if(enableDebugging) {
       print('generate(${count}, ${length}) took ${stopwatch.elapsedMilliseconds / 1000} seconds (${stopwatch.elapsedMilliseconds} ms)');
     }
     return key;
   }
 }
