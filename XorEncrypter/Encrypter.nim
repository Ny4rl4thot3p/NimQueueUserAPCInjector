proc charSeqToByteSeq(chars: seq[char]): seq[byte] =
  result = @[]
  for c in chars:
    result.add(cast[byte](ord(c)))

proc xorEncryptDecrypt(data: seq[byte], key: seq[byte]): seq[byte] =
  result = @[]
  var keyIndex = 0
  for b in data:
    result.add(b xor key[keyIndex])
    inc(keyIndex)
    if keyIndex == key.len:
      keyIndex = 0

proc encodeShellcode(shellcode: seq[byte], key: seq[byte]): seq[byte] =
  result = xorEncryptDecrypt(shellcode, key)

let originalShellcode: seq[byte] = @[#shellcode
                                    ] 

let encryptionKeyChars: seq[char] = @['w', 'q', 'e', 'w', 'q', 't', 'f', 'a', '1', '2', '3', '1', '5', 'r', '1']
let encryptionKey: seq[byte] = charSeqToByteSeq(encryptionKeyChars)  # key "wqewqtfa12315r1"

let encryptedShellcode = encodeShellcode(originalShellcode, encryptionKey)
echo "Original Shellcode:", originalShellcode
echo "Encrypted Shellcode:", encryptedShellcode

let outputFile = "encrypted_shellcode.bin"
writeFile(outputFile, encryptedShellcode)
echo "Encrypted shellcode successfully written to file:", outputFile