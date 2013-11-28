part of pbkdf2;

List<int> toBytes(var input) {
  var bytes = new List<int>();

  if(input is int) {
    bytes.add(input & 0xff);
  } else {
    for(var i = 0; i < input.length; i++) {
      int x;

      if(input[i] is int) {
        bytes.add(input[i] & 0xff);
      } else if(input[i] is String) {
        bytes.add(input.codeUnitAt(i).toRadixString(16));
      }
    }
  }

  return bytes;
}

List<int> XOR(var A, var B) {
  // print('A: ${CryptoUtils.bytesToHex(A)}');
  // print('B: ${CryptoUtils.bytesToHex(B)}');
  var result = new List<int>(A.length);
  var comb = new IterableZip([A, B]);

  for(var x = 0; x < result.length; x++) {
    var e = comb.elementAt(x);
    result[x] = toBytes(e[0] ^ e[1])[0];
  }

  return result;
}

/**
 *  Convert an int to a 32-bit big-endian representation
 */
List<int> toInt32Be(int input) {
  var buffer = new List<int>();
  buffer.add((input >> 24) & 0xff);
  buffer.add((input >> 16) & 0xff);
  buffer.add((input >> 8) & 0xff);
  buffer.add(input & 0xff);

  return buffer;
}

