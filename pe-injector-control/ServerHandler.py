#!/usr/bin/env python3

# import lib
from http.server import SimpleHTTPRequestHandler
import cgi
import configparser
import hashlib
import base64
import random
import ipaddress
import string
import os
# import file
from LibPeProtocol import LibPeProtocol
from ShellCodeBuilder import ShellCodeBuilder
from peinjector_control import CONFIG_FILE
from peinjector_control import CONFIG_SECTION_INJ
from peinjector_control import CONFIG_SECTION_WEB
from peinjector_control import CONFIG_KEY_IP
from peinjector_control import CONFIG_KEY_PORT
from peinjector_control import CONFIG_KEY_AUTH
from peinjector_control import CONFIG_KEY_PASSHASH
from peinjector_control import CONFIG_KEY_TOKEN


class SimplePostHTTPRequestHandler(SimpleHTTPRequestHandler):

    # generate hash: sha256( sha256(salt) + sha256(base64_basic_auth) )
    def generatePassHash(self, config_salt, base64_basic_auth):
        # prepare user input
        if 'Basic' in base64_basic_auth:
            base64_basic_auth = base64_basic_auth[6:] # remove 'Basic ' from string like: 'Basic o27435n7o2qo7=='
        # hash, hash, hash, ...
        salt_hash = hashlib.sha256(config_salt.encode("Ascii"))                  # sha256(salt)
        salt_hash = salt_hash.hexdigest()                                        #    convert to hexString
        basic_auth_hash = hashlib.sha256(base64_basic_auth.encode("Ascii"))      # sha256(base64_basic_auth)
        basic_auth_hash = basic_auth_hash.hexdigest()                            #    convert to hexString
        final_hash = hashlib.sha256((salt_hash+basic_auth_hash).encode("Ascii")) # sha256( sha256(salt) + sha256(base64_basic_auth) )
        final_hash = final_hash.hexdigest()                                      #    convert byte to hexString
        return final_hash

    # set user hash
    def setPassHash(self, username, password):
        # create base64_basic_auth String
        base64_basic_auth = base64.b64encode((username +':'+ password).encode("Ascii")) # base64(USER:PASS)
        base64_basic_auth = base64_basic_auth.decode("UTF-8")                           #    convert to String
        # generate salt
        salt = str(random.getrandbits(256))                                             # random string
        salt = hashlib.sha256(salt.encode("Ascii")).hexdigest()                         #    hash the string
        # use generatePassHash()
        final_hash = self.generatePassHash(config_salt=salt, base64_basic_auth=base64_basic_auth)
        # write to config
        config = configparser.ConfigParser()
        config.read(CONFIG_FILE)
        config.set(CONFIG_SECTION_WEB, CONFIG_KEY_PASSHASH, salt+':'+final_hash)
        with open(CONFIG_FILE, 'w') as configfile:
            config.write(configfile)

    # catch GET requests and redirected to the super class (after base_authenticate)
    def do_GET(self):
        if self.base_authenticate():
            self.path = "/html" + self.path         # set DocumentRoot to /html
            SimpleHTTPRequestHandler.do_GET(self)

    # catch POST requests and redirected to post_api() (after base_authenticate)
    def do_POST(self):
        if self.base_authenticate():
            # get vars
            form = cgi.FieldStorage(
                fp=self.rfile,
                headers=self.headers,
                environ={'REQUEST_METHOD':'POST','CONTENT_TYPE':self.headers['Content-Type'],})
            post_key = form.getfirst('key',None)
            post_value = form.getfirst('value',"")
            post_shellselect = form.getfirst('shellselect',None)

            # select API
            if(post_key is not None and post_value is not None):
                # 'key' and 'value' must exist
                self.post_api_keyvalue(key=post_key, value=post_value)
            elif(post_shellselect is not None):
                # 'shellselect' exist
                post_name = form.getfirst('name',"")
                post_host = form.getfirst('host',None)
                post_port = form.getfirst('port',None)
                post_xor = form.getfirst('xor',None)
                post_textarea = form.getfirst('textarea',None)
                post_system = form.getfirst('system',None)
                self.post_api_shellcode(shellselect=post_shellselect, system=post_system, name=post_name, shellhost=post_host, shellport=post_port, xor=post_xor, textarea=post_textarea)
            else:
                # no API found
                print("post request error: no api selected")
                self.wfile.write(b"post request error: no api selected")

    # check user and pass and return TRUE
    def base_authenticate(self):
        # read config
        config = configparser.ConfigParser()
        config.read(CONFIG_FILE)
        config_auth_enable = False
        config_salt = "None"
        config_hash = "None"
        if CONFIG_SECTION_WEB in config:
            config_auth_enable = config[CONFIG_SECTION_WEB].getboolean(CONFIG_KEY_AUTH, fallback=False)
            conf_salt_pass_hash = config[CONFIG_SECTION_WEB].get(CONFIG_KEY_PASSHASH, fallback="None:None")
            if ':' in conf_salt_pass_hash:
                config_salt = conf_salt_pass_hash.split(':')[0]
                config_hash = conf_salt_pass_hash.split(':')[1]

        # do your thing
        if not config_auth_enable:
            # authentication disabled
            return True
        elif self.headers.get('Authorization') == None:
            # send Header
            self.send_response(401)
            self.send_header('WWW-Authenticate', 'Basic realm=\"peinjector-control\"')
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            # send body
            self.wfile.write(b"no auth header received")
            self.wfile.flush()
            return False
        else:
            # check hash
            user_hash = self.generatePassHash(config_salt, self.headers.get('Authorization'))
            if config_hash == user_hash:
                # authentication success
                return True
            else:
                # send Header
                self.send_response(401)
                self.send_header('WWW-Authenticate', 'Basic realm=\"peinjector-control\"')
                self.send_header('Content-type', 'text/plain')
                self.end_headers()
                # send body
                self.wfile.write(b"not authenticated")
                self.wfile.flush()
                return False

    # send a command
    def simply_command_send(self, command, data, host, port, token):
        # connect
        con = LibPeProtocol(token=token, host=host, port=port)
        con.send_command(command=command, data=data)
        last_error = con.get_last_error()
        # result
        if last_error is not None:
            # ERROR
            print(last_error)
            self.wfile.write(last_error.encode("Ascii"))  # send the error and the GUI will display it
            return False
        else:
            # OK
            self.wfile.write(b"OK") # send "OK" and the GUI will not do anything
            return True

    # POST handling (API 1)
    def post_api_keyvalue(self, key, value):

        # read injector ip and port from config
        config = configparser.ConfigParser()
        config.read(CONFIG_FILE)
        token="AAAA000000000000000000000000000000"
        host="127.0.0.1"
        port=31338
        if CONFIG_SECTION_INJ in config:
            token = config[CONFIG_SECTION_INJ].get(CONFIG_KEY_TOKEN, fallback=token)
            host = config[CONFIG_SECTION_INJ].get(CONFIG_KEY_IP, fallback=host)
            port = int(config[CONFIG_SECTION_INJ].get(CONFIG_KEY_PORT, fallback=port))
        else:
            config.add_section(CONFIG_SECTION_INJ)  # importend for 'controlport' and 'controlip'

        # send header
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain')
        self.end_headers()

        # send body
        print("post request: set", key, "to", value)
        # ---------------------------------------------------
        if("injrestart" == key):
            # restart is a void command (value=None)
            value = None
            # simply command send
            self.simply_command_send(command=LibPeProtocol.CMD_SEND_RESTART, data=value, host=host, port=port, token=token)

        elif("sectionname" == key):
            # set STRING
            value = value # 'value' is already a string
            # simply command send
            self.simply_command_send(command=LibPeProtocol.CMD_SEND_SET_SECTION_NAME, data=value, host=host, port=port, token=token)

        elif("changeflags" == key):
            # cast value to boolean
            value = (True if (value == "true") else False)
            # simply command send
            self.simply_command_send(command=LibPeProtocol.CMD_SEND_SET_METHOD_CHANGE_FLAGS, data=value, host=host, port=port, token=token)

        elif("newsection" == key):
            # cast value to boolean
            value = (True if (value == "true") else False)
            # simply command send
            self.simply_command_send(command=LibPeProtocol.CMD_SEND_SET_METHOD_NEW_SECTION, data=value, host=host, port=port, token=token)

        elif("alignmentresize" == key):
            # cast value to boolean
            value = (True if (value == "true") else False)
            # simply command send
            self.simply_command_send(command=LibPeProtocol.CMD_SEND_SET_METHOD_ALIGNMENT_RESIZE, data=value, host=host, port=port, token=token)

        elif("alignment" == key):
            # cast value to boolean
            value = (True if (value == "true") else False)
            # simply command send
            self.simply_command_send(command=LibPeProtocol.CMD_SEND_SET_METHOD_ALIGNMENT, data=value, host=host, port=port, token=token)

        elif("crosssectionjump" == key):
            # cast value to boolean
            value = (True if (value == "true") else False)
            # simply command send
            self.simply_command_send(command=LibPeProtocol.CMD_SEND_SET_METHOD_CROSS_SECTION_JUMP, data=value, host=host, port=port, token=token)

        elif("removeintegity" == key):
            # cast value to boolean
            value = (True if (value == "true") else False)
            # simply command send
            self.simply_command_send(command=LibPeProtocol.CMD_SEND_SET_REMOVE_INTEGRITY_CHECK, data=value, host=host, port=port, token=token)

        elif("dataport" == key):
            # cast value to int
            value = int(value)
            # simply command send
            self.simply_command_send(command=LibPeProtocol.CMD_SEND_SET_DATA_PORT, data=value, host=host, port=port, token=token)

        elif("encryptiterations" == key):
            # cast value to int
            value = int(value)
            # simply command send
            self.simply_command_send(command=LibPeProtocol.CMD_SEND_SET_ENCRYPT_ITERATIONS, data=value, host=host, port=port, token=token)

        elif("crosssectionjumpiterations" == key):
            # cast value to int
            value = int(value)
            # simply command send
            self.simply_command_send(command=LibPeProtocol.CMD_SEND_SET_METHOD_CROSS_SECTION_JUMP_ITERATIONS, data=value, host=host, port=port, token=token)

        elif("token" == key):
            # cast value to byte
            try:
                he3x = bytes.fromhex(value)
            except Exception:
                he3x = None
            # simply command send
            isok = self.simply_command_send(command=LibPeProtocol.CMD_SEND_SET_TOKEN, data=he3x, host=host, port=port, token=token)
            # save local
            if(isok):
                # write token in local config
                config.set(CONFIG_SECTION_INJ, CONFIG_KEY_TOKEN, value)
                with open(CONFIG_FILE, 'w') as configfile:
                    config.write(configfile)

        elif("token_write" == key):
            try:
                # test for hex
                bytes.fromhex(value)
                # write token in local config
                config.set(CONFIG_SECTION_INJ, CONFIG_KEY_TOKEN, value)
                with open(CONFIG_FILE, 'w') as configfile:
                    config.write(configfile)
                # return OK
                self.wfile.write(b"OK")
            except Exception:
                self.wfile.write(b"post request error: invalid hex")

        elif("datainterface" == key):
            # cast value to boolean
            value = (True if (value == "true") else False)
            # simply command send
            self.simply_command_send(command=LibPeProtocol.CMD_SEND_SET_DATA_INTERFACE, data=value, host=host, port=port, token=token)

        elif("controlport" == key):
            # cast value to int
            port_new = int(value)
            # simply command send
            self.simply_command_send(command=LibPeProtocol.CMD_SEND_SET_CONTROL_PORT, data=port_new, host=host, port=port, token=token)

        elif("controlport_write" == key):
            # cast value to int
            port_new = int(value)
            # write port in local config
            config.set(CONFIG_SECTION_INJ, CONFIG_KEY_PORT, str(port_new))
            with open(CONFIG_FILE, 'w') as configfile:
                config.write(configfile)
            # return OK
            self.wfile.write(b"OK")

        elif("controlip" == key):
            # validate
            if len(value) <= 255:
                # write ip in local config
                config.set(CONFIG_SECTION_INJ, CONFIG_KEY_IP, value)
                with open(CONFIG_FILE, 'w') as configfile:
                    config.write(configfile)
                # return OK
                self.wfile.write(b"OK")
            else:
                self.wfile.write(b"post request error: invalid ip or hostname address")

        elif("controlinterface" == key):
            # cast value to boolean
            value = (True if (value == "true") else False)
            # simply command send
            self.simply_command_send(command=LibPeProtocol.CMD_SEND_SET_CONTROL_INTERFACE, data=value, host=host, port=port, token=token)

        elif("enableencrypt" == key):
            # cast value to boolean
            value = (True if (value == "true") else False)
            # simply command send
            self.simply_command_send(command=LibPeProtocol.CMD_SEND_SET_ENCRYPT, data=value, host=host, port=port, token=token)

        elif("randomsectionname" == key):
            # cast value to boolean
            value = (True if (value == "true") else False)
            # simply command send
            self.simply_command_send(command=LibPeProtocol.CMD_SEND_SET_RANDOM_SECTION_NAME, data=value, host=host, port=port, token=token)

        elif("trystaystealth" == key):
            # cast value to boolean
            value = (True if (value == "true") else False)
            # simply command send
            self.simply_command_send(command=LibPeProtocol.CMD_SEND_SET_TRY_STAY_STEALTH, data=value, host=host, port=port, token=token)

        elif("enable" == key):
            # cast value to boolean
            value = (True if (value == "true") else False)
            # simply command send
            self.simply_command_send(command=LibPeProtocol.CMD_SEND_SET_ENABLE, data=value, host=host, port=port, token=token)

        elif("adminpass" == key):
            # set STRING
            value = value # 'value' is already a string
            # set admin password
            self.setPassHash('admin', value)
            # return OK
            self.wfile.write(b"OK")

        elif("enableauth" == key):
            # cast value to boolean
            value = (True if (value == "true") else False)
            # write config
            config.set(CONFIG_SECTION_WEB, CONFIG_KEY_AUTH, str(value))
            with open(CONFIG_FILE, 'w') as configfile:
                config.write(configfile)
            # return OK
            self.wfile.write(b"OK")

        elif("getconfig" == key):
            # return web-ini
            config = configparser.ConfigParser()
            config.read(CONFIG_FILE)
            for section in config.sections():
                for key in config[section]:
                    writestr = section+'_'+key+"{|~|}"+config[section][key]+'\n'
                    if not key == CONFIG_KEY_PASSHASH:
                        # alles ausser PASSHASH ausgeben
                        self.wfile.write(writestr.encode("Ascii"))
            # get config is a void command (value=None)
            value = None
            # send command
            con = LibPeProtocol(token=token, host=host, port=port)
            result = con.send_command(command=LibPeProtocol.CMD_SEND_GET_CONFIG, data=value)
            last_error = con.get_last_error()
            # result
            if last_error is not None:
                # ERROR
                print(last_error)
                last_error = 'ERROR: '+last_error
                self.wfile.write(last_error.encode("Ascii"))  # send the error and the GUI will display it
            else:
                # OK:  return server-ini
                config = configparser.ConfigParser()
                config.read_string(result.decode("UTF-8"))
                for section in config.sections():
                    for key in config[section]:
                        writestr = section+'_'+key+"{|~|}"+config[section][key]+'\n'
                        self.wfile.write(writestr.encode("Ascii"))

        elif("exportconfig" == key):
            # get config is a void command (value=None)
            value = None
            # send command
            con = LibPeProtocol(token=token, host=host, port=port)
            result = con.send_command(command=LibPeProtocol.CMD_SEND_GET_CONFIG, data=value)
            last_error = con.get_last_error()
            # result
            if last_error is not None:
                # ERROR
                print(last_error)
                last_error = 'ERROR: '+last_error
                self.wfile.write(last_error.encode("Ascii"))  # send the error and the GUI will display it
            else:
                # OK:  return server-ini
                self.wfile.write(result)

        # bad command
        else:
            self.wfile.write(b"post request error: command not found")
        # ---------------------------------------------------
        self.wfile.flush()

    # POST handling (API 2)
    def post_api_shellcode(self, shellselect, system, name, shellhost, shellport, xor, textarea=None):
        print("post request: shellchode:", shellselect, "system:", system, "name:", name, "host:", shellhost, "port:", shellport, "xor:", xor, "textarea:", textarea)

        # read injector ip and port from config
        config = configparser.ConfigParser()
        config.read(CONFIG_FILE)
        token="AAAA000000000000000000000000000000"
        injhost="127.0.0.1"
        injport=31338
        if CONFIG_SECTION_INJ in config:
            token = config[CONFIG_SECTION_INJ].get(CONFIG_KEY_TOKEN, fallback=token)
            injhost = config[CONFIG_SECTION_INJ].get(CONFIG_KEY_IP, fallback=injhost)
            injport = int(config[CONFIG_SECTION_INJ].get(CONFIG_KEY_PORT, fallback=injport))
        else:
            config.add_section(CONFIG_SECTION_INJ)  # importend for 'controlport' and 'controlip'

        # send header
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain')
        self.end_headers()

        # clear name
        valid_chars = "-_.() %s%s" % (string.ascii_letters, string.digits)
        name = ''.join(c for c in name if c in valid_chars)

        # clear textarea
        if textarea is not None:
            textarea = textarea.replace(' ','').replace(':','').replace('-','').replace('.','')

        # check user input
        if shellport is None or not shellport.isdigit():
            print("post request error: port must be a number")
            self.wfile.write(b"port must be a number")
        elif not self.is_valide_ip(shellhost):
            print("post request error: host must be a ip")
            self.wfile.write(b"host must be a ip")
        else:
            # convert shellcode (textarea) from HEX-String to Bytes
            try:
                textarea = bytes.fromhex(textarea)
            except Exception:
                textarea = None
                print("no valid textarea")
            # ShellCodeBuilder
            scb = ShellCodeBuilder()
            scb.set_params(host=shellhost, port=int(shellport), shellcode=textarea)
            if scb.select_shellcode(shellselect):
                if xor == "true" or xor == "True" or xor == "TRUE" or xor == "1":
                    xor = True
                else:
                    xor = False
                code = scb.get_shellcode_x86(encode=xor)
                code2 = scb.get_shellcode_x64(encode=xor)
                if code is not None:
                    if "x86" in system:
                        print("Code (x86):", len(code))
                        lasterror = self.simply_shellcode_send(command=LibPeProtocol.CMD_SEND_SET_PAYLOAD_X86, data=code, host=injhost, port=injport, token=token)
                        if lasterror is None:
                            self.simply_shellcode_send(command=LibPeProtocol.CMD_SEND_SET_PAYLOAD_NAME_X86, data=name, host=injhost, port=injport, token=token)
                        else:
                            self.wfile.write(("x86: "+lasterror+"\n").encode("Ascii"))
                    if "x64" in system:
                        print("Code (x64):", len(code2))
                        lasterror = self.simply_shellcode_send(command=LibPeProtocol.CMD_SEND_SET_PAYLOAD_X64, data=code2, host=injhost, port=injport, token=token)
                        if lasterror is None:
                            self.simply_shellcode_send(command=LibPeProtocol.CMD_SEND_SET_PAYLOAD_NAME_X64, data=name, host=injhost, port=injport, token=token)
                        else:
                            self.wfile.write(("x64: "+lasterror+"\n").encode("Ascii"))
                    self.wfile.write(b"OK")
                else:
                    print(scb.get_last_error())
                    self.wfile.write(scb.get_last_error().encode("Ascii"))
            else:
                print(scb.get_last_error())
                self.wfile.write(scb.get_last_error().encode("Ascii"))
            # fin
            self.wfile.flush()

    # check IPv4
    def is_valide_ip(self,ip):
        try:
            ipaddress.ip_address(ip)
            return True
        except Exception:
            return False

    # send a shellcode
    def simply_shellcode_send(self, command, data, host, port, token):
        # connect
        con = LibPeProtocol(token=token, host=host, port=port)
        con.send_command(command=command, data=data)
        return con.get_last_error()
