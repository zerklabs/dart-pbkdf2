/**
 *  From nigori
 *
 *  Need to document license and location
 */




part of pbkdf2;

ByteData toByteArray(List<int> ints){
  Uint8List list = new Uint8List(ints.length);
  int i = 0;
  ints.forEach((byte) { list[i] = byte; ++i;});
  return new ByteData.view(list.buffer);
}

ByteData toBytes(String string){
  List<int> byteList = encodeUtf8(string);
  ByteData ba = new ByteData.view(new Uint8List(byteList.length).buffer);
  int offset = 0;
  byteList.forEach((byte) { ba.setInt8(offset, byte); offset++;});
  return ba;
}

String fromBytes(ByteData array){
  List<int> byteList = byteArrayToByteList(array);
  return decodeUtf8(byteList);
}

List<int> byteArrayToByteList(ByteData array){
  int length = array.lengthInBytes;
  List<int> byteList = new List(length);
  for (int i = 0; i < length; ++i){
    byteList[i] = array.getUint8(i);
  }
  return byteList;
}

String byteArrayToString(ByteData array){
  int length = array.lengthInBytes;
  String answer = "[";
  for (int i = 0; i < length; ++i){
    answer = "$answer${i>0 ? ', ':''}${array.getInt8(i)}";
  }
  answer = "$answer]";
  return answer;
}
ByteData bigIntegerToByteArray(BigInteger integer){
  return toByteArray(integer.toByteArray());
}
BigInteger byteArrayToBigInteger(ByteData array){
  return new BigInteger(byteArrayToInt(array));
}

int byteArrayToInt(ByteData array){
  return int.parse("0x${CryptoUtils.bytesToHex(byteArrayToByteList(array))}");
}

int byteListToInt(List<int> byteList) {
  return int.parse("0x${CryptoUtils.bytesToHex(byteList)}");
}

ByteData intToByteArray(int integer){
  ByteData toflip = new ByteData.view(new Uint32List(1).buffer);
  ByteData target = new ByteData.view(new Uint8List(4).buffer);
  toflip.setInt32(0, integer);
  int offset = 0;
  target.setInt8(offset,toflip.getInt8(3));++offset;//Reverse byte order
  target.setInt8(offset,toflip.getInt8(2));++offset;
  target.setInt8(offset,toflip.getInt8(1));++offset;
  target.setInt8(offset,toflip.getInt8(0));
  return target;
}

List<int> _convertTypesToListInt(dynamic item){
  List<int> itemBytes;
  if (item is String)
    itemBytes = encodeUtf8(item);
  else if (item is List<int>)
    itemBytes = item;
  else if (item is BigInteger)
    itemBytes = item.toByteArray();
  else if (item is int)
    itemBytes = byteArrayToByteList(intToByteArray(item));
  else if (item is ByteData)
    itemBytes = byteArrayToByteList(item);
  else
    throw new ArgumentError("Invalid type of item '${item}'");
  return itemBytes;
}
/**
 * Implement || from the nigori spec
 * items can be Strings or List<int>s (of bytes) or BigIntegers, types can be mixed
 * TODO(drt24) unit test
 * */
ByteData byteconcat(List<dynamic> items) {
  const intLength = 4;
  List<List<int>> byteArrays = new List(items.length);
  int index = 0;
  items.forEach((item){ byteArrays[index] = _convertTypesToListInt(item); ++index;});
  int length = 0;
  byteArrays.forEach((array) => length += intLength + array.length);

  ByteData ba = new ByteData.view(new Uint8List(length).buffer);

  int offset = 0;
  byteArrays.forEach((array) {
    offset = _byteconcatInteger(offset,array.length,ba);
    array.forEach((byte) { ba.setInt8(offset,byte);++offset;});
    });
  return ba;
}

List<int> byteconcatList(List<dynamic> items){
  return byteArrayToByteList(byteconcat(items));
}

/**
 * Write an int of the length into the target array
 */
int _byteconcatInteger(int offset, int integer, ByteData target){
  ByteData length = new ByteData.view(new Uint32List(1).buffer);
  length.setInt32(0, integer);
  target.setInt8(offset,length.getInt8(3));++offset;//Reverse byte order
  target.setInt8(offset,length.getInt8(2));++offset;
  target.setInt8(offset,length.getInt8(1));++offset;
  target.setInt8(offset,length.getInt8(0));++offset;
  return offset;
}

String base64Encode(ByteData array){
  return CryptoUtils.bytesToBase64(byteArrayToByteList(array));
}
List<String> base64EncodeList(List<ByteData> listArray){
  List<String> listString = new List(listArray.length);
  int index = 0;
  listArray.forEach((item) { listString[index] = base64Encode(item); ++index;});
  return listString;
}

ByteData base64Decode(String encoded){
  if (null == encoded){
    throw new ArgumentError("Null string cannot be decoded");
  }
  return toByteArray(_base64ToBytes(encoded));
}

// Copied out of a dart CL https://codereview.chromium.org/12321078/ which I have submitted
int _getBase64Val(String s, int pos) {
  int code = s.codeUnitAt(pos);
  if (code >= 65 && code < (65+26)) { // 'A'..'Z'
    return code - 65;
  } else if (code >= 97 && code < (97+26)) { // 'a'..'z'
    return code - 97 + 26;
  } else if (code >= 48 && code < (48+10)) { // '0'..'9'
    return code - 48 + 52;
  } else if (code == 43) { // '+'
    return 62;
  } else if (code == 47) { // '/'
    return 63;
  } else {
    throw 'Invalid character "$s" at $pos';
  }
}

List<int> _base64ToBytes(String s) {
  // Remove line breaks so that we can treat all base64 strings the same
  s = s.replaceAll('\r\n', '');
  var rtn = new List<int>();
  var pos = 0;
  while (pos < s.length) {
    if (s[pos+2] =='=') { // Single byte as two chars.
      int v = (_getBase64Val(s, pos) << 18 ) | (_getBase64Val(s, pos+1) << 12 );
      rtn.add((v >> 16) & 0xff);
      break;
    } else if (s[pos+3] == '=') { // Two bytes as 3 chars.
      int v = (_getBase64Val(s, pos) << 18 ) | (_getBase64Val(s, pos+1) << 12 ) |
          (_getBase64Val(s, pos + 2) << 6);
      rtn.add((v >> 16) & 0xff);
      rtn.add((v >> 8) & 0xff);
      break;
    } else { // Three bytes as 4 chars.
      int v = (_getBase64Val(s, pos) << 18 ) | (_getBase64Val(s, pos+1) << 12 ) |
          (_getBase64Val(s, pos + 2) << 6) | _getBase64Val(s, pos+3);
      pos += 4;
      rtn.add((v >> 16 ) & 0xff);
      rtn.add((v >> 8) & 0xff);
      rtn.add(v & 0xff);
    }
  }
  return rtn;
}
