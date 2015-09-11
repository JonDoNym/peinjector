#!/usr/bin/env python3

# import lib
import argparse
import ssl
import http.server
import configparser
from platform import python_version
# import file
import ServerHandler


# constants
CONFIG_FILE = 'config.ini'
CONFIG_SECTION_WEB = 'WEBSERVER'
CONFIG_SECTION_INJ = 'INJECTOR'
CONFIG_KEY_IP = 'ip'
CONFIG_KEY_PORT = 'port'
CONFIG_KEY_LOCAL = 'localhostonly'
CONFIG_KEY_CERT = 'cert'
CONFIG_KEY_SSL = 'usessl'
CONFIG_KEY_AUTH = 'basicauth'
CONFIG_KEY_PASSHASH = 'passhash'
CONFIG_KEY_TOKEN = 'token'


"""
Create and run the HTTPS-server

self-signed certificate: openssl req -new -x509 -keyout server.pem -out server.pem -days 365 -nodes
ssl-doc: https://docs.python.org/3/library/ssl.html#ssl-contexts
"""
def run_https_server(cert="server.pem", ip='0.0.0.0', port=443, usessl=True):

    # build server
    server_address = (ip, port)                                           # listen to all interfaces
    handler = ServerHandler.SimplePostHTTPRequestHandler                  # create handler
    httpd = http.server.HTTPServer(server_address, handler)               # create HTTP-Server
    if usessl:
        # config SSLContext
        context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)      # create SSLContext with only TLS 1.2
        context.options |= ssl.OP_CIPHER_SERVER_PREFERENCE  # use the server cipher ordering preference
        context.options |= ssl.OP_SINGLE_DH_USE             # prevents re-use of the same DH key for distinct SSL sessions (requires more computational resources)
        context.options |= ssl.OP_SINGLE_ECDH_USE           # prevents re-use of the same ECDH key for distinct SSL sessions (requires more computational resources)
        context.load_cert_chain(cert)                       # load a private key and the corresponding certificate (all in one file)
        context.set_ciphers('HIGH:!aNULL:!eNULL:!LOW:!ADH:!RC4:!3DES:!MD5:!EXP:!PSK:!SRP:!DSS')  # set the ciphers (OpenSSL cipher list format)
        # install SSL-Socket
        httpd.socket = context.wrap_socket(httpd.socket, server_side=True)

    # print infos
    print("Python", python_version())
    sa = httpd.socket.getsockname()
    if usessl:
        print("Serving HTTPS on", sa[0], "port", sa[1], "(cert:", cert, ") ...")
    else:
        print("Serving HTTP on", sa[0], "port", sa[1], "...")

    # run
    httpd.serve_forever()  # Handle requests, FOREVER!


"""
MAIN
"""
if __name__ == '__main__':

    # default vars
    default_ip = '0.0.0.0'
    default_port = 443
    default_cert="server.pem"
    default_usessl=True

    # read/write config
    config = configparser.ConfigParser()
    config.read(CONFIG_FILE)

    if CONFIG_SECTION_WEB in config:
        web = config[CONFIG_SECTION_WEB]
        # ip
        if web.getboolean(CONFIG_KEY_LOCAL, fallback=True):
            default_ip = '127.0.0.1'
        else:
            default_ip = '0.0.0.0'
        # port
        default_port = web.get(CONFIG_KEY_PORT, fallback=default_port)
        # cert
        default_cert = web.get(CONFIG_KEY_CERT, fallback=default_cert)
        # ssl
        default_usessl = web.getboolean(CONFIG_KEY_SSL, fallback=default_usessl)

    # parser for command-line options, arguments and sub-commands
    help_text = "create a self-signed certificate: 'openssl req -new -x509 -keyout server.pem -out server.pem -days 365 -nodes'"
    parser = argparse.ArgumentParser(description=help_text)
    parser.add_argument('-i', '--ip', help='listen ip [default: 0.0.0.0]', default=default_ip)
    parser.add_argument('-p', '--port', type=int, help='listen on TCP port [default: 443]', default=default_port)
    parser.add_argument('-c', '--cert', help='listen on TCP port [default: server.pem]', default=default_cert)
    parser.add_argument('-s', '--ssl', help='use ssl [default: true]', default=default_usessl)
    args = parser.parse_args()

    # run run_http(s)_server
    run_https_server(cert=args.cert, ip=args.ip, port=args.port, usessl=args.ssl)
