part of pbkdf2;

/**
 *
 */
List<int> toRadixBytes(var input) {
  var bytes = new List<int>();

  if(input is int) {
    bytes.add(input.toRadixString(16));
  } else {
    for(var i = 0; i < input.length; i++) {
      int x;

      if(input[i] is int) {
        bytes.add(input[i].toRadixString(16));
      } else if(input[i] is String) {
        bytes.add(input.codeUnitAt(i).toRadixString(16));
      }
    }
  }

  return bytes;
}

/**
 *
 */
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

/**
 *
 */
String replace(String input) {
  print('Input before: ${input}');

  if(input.contains(r'\0')) {
    var index = input.indexOf(r'\0');
    var replacement = '';
    if(index == 0) {
      replacement = r'\u0000' + input.substring(1, input.length - 1);
    } else {
      replacement = input.substring(0, index) + r'\u{0000}' + input.substring(index + 2, input.length);
    }

    print('Input after: ${replacement}');
    print(encodeUtf8(replacement));

    return replacement;
  }

  return input;
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

