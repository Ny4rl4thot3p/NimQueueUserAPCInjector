# Nim QueueUserAPC Shellcode Injector

This Nim programming language repository demonstrates a Windows shellcode injection technique using the `QueueUserAPC` function. The code includes functionalities for downloading encrypted shellcode from a specified URL, decrypting it using a XOR encryption algorithm, and injecting the decrypted shellcode into a remote process.

## Key Features

- Shellcode download from a remote server.
- XOR encryption and decryption of shellcode.
- Injection of shellcode into a target process using `QueueUserAPC`.
- Demonstrates Windows API usage for process manipulation.

## Usage

1. Clone the repository.
2. Modify the `encryptionKeyChars` with your encryption key.
3. Encrypt your shellcode with encryper.nim
4. Customize the `url` variable in the `downloadFile` procedure with the desired shellcode URL.
5. Compile and run the Nim code on a Windows system (nim c -d:release .\Filename.nim). 
