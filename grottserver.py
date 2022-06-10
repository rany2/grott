import codecs
import http.server
import json
import queue
import select
import socket
import textwrap
import threading
import time
from collections import defaultdict
from datetime import datetime
from itertools import cycle
from urllib.parse import parse_qs, urlparse

import libscrc
import pytz

from grottdata import procdata as grottdata
from grottproxy import Forward

# grottserver.py emulates the server.growatt.com website and is
# initially developed for debugging and testing grott.
# Updated: 2022-06-02
# Version:
verrel = "0.0.8a"


# Formats multi-line data
def format_multi_line(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = "".join(rf"\x{byte:02x}" for byte in string)
        if size % 2:
            size -= 1
    return "\n".join([prefix + line for line in textwrap.wrap(string, size)])


# encrypt / decrypt data.
def decrypt(decdata):

    ndecdata = len(decdata)

    # Create mask and convert to hexadecimal
    mask = "Growatt"
    hex_mask = [f"{ord(x):02x}" for x in mask]
    nmask = len(hex_mask)

    # start decrypt routine
    unscrambled = list(decdata[0:8])  # take unscramble header

    for i, j in zip(range(0, ndecdata - 8), cycle(range(0, nmask))):
        unscrambled = unscrambled + [decdata[i + 8] ^ int(hex_mask[j], 16)]

    result_string = "".join(f"{n:02x}" for n in unscrambled)

    print("\t - " + "Grott - data decrypted V2")
    return result_string


def htmlsendresp(self, responserc, responseheader, responsetxt):
    # send response
    self.send_response(responserc)
    self.send_header("Content-type", responseheader)
    self.end_headers()
    self.wfile.write(responsetxt)
    if self.verbose:
        print(
            "\t - Grotthttpserver - http response send: ",
            responserc,
            responseheader,
            responsetxt,
        )


def getcurrenttime(conf):
    try:
        local = pytz.timezone(conf.tmzone)
    except Exception:
        if conf.verbose:
            if conf.tmzone == "local":
                print("\t - " + "Timezone local specified default timezone used")
            else:
                print(
                    "\t - " + "Grott unknown timezone : ",
                    conf.tmzone,
                    ", default timezone used",
                )
        conf.tmzone = "local"

    if conf.tmzone == "local":
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    return datetime.now(local).strftime("%Y-%m-%d %H:%M:%S")


def createtimecommand(conf, protocol, loggerid, sequenceno, commandresponse):
    bodybytes = loggerid.encode("utf-8")
    body = bodybytes.hex()
    if protocol == "06":
        body = body + "0000000000000000000000000000000000000000"
    register = 31
    body = body + f"{int(register):04x}"
    currenttime = getcurrenttime(conf)
    timex = currenttime.encode("utf-8").hex()
    timel = f"{int(len(timex) / 2):04x}"
    body = body + timel + timex
    # calculate length of payload = body/2 (str => bytes) + 2 bytes invertid + command.
    bodylen = int(len(body) / 2 + 2)

    # create header
    header = "0001" + "00" + protocol + f"{bodylen:04x}" + "0118"
    # print(header)
    body = header + body
    body = bytes.fromhex(body)
    if conf.verbose:
        print("\t - Grottserver - Time plain body : ")
        print(format_multi_line("\t\t ", body))

    if protocol != "02":
        # encrypt message
        body = decrypt(body)
        crc16 = libscrc.modbus(bytes.fromhex(body))
        body = bytes.fromhex(body) + crc16.to_bytes(2, "big")

    if conf.verbose:
        print("\t - Grottserver - Time command created :")
        print(format_multi_line("\t\t ", body))

    # just to be sure delete register info
    try:
        del commandresponse["18"]["001f"]
    except Exception:
        pass

    return body


class GrottHttpRequestHandler(http.server.BaseHTTPRequestHandler):
    def __init__(self, send_queuereg, conf, loggerreg, commandresponse, *args):
        self.send_queuereg = send_queuereg
        self.conf = conf
        self.verbose = conf.verbose
        self.loggerreg = loggerreg
        self.commandresponse = commandresponse
        super().__init__(*args)

    def do_GET(self):
        try:
            if self.verbose:
                print("\t - Grotthttpserver - Get received ")
            # parse url
            url = urlparse(self.path)
            urlquery = parse_qs(url.query)

            if self.path == "/":
                self.path = "grott.html"

            # only allow files from current directory
            if self.path[0] == "/":
                self.path = self.path[1 : len(self.path)]

            # if self.path.endswith(".html") or self.path.endswith(".ico"):
            if self.path in ("grott.html", "favicon.ico"):
                try:
                    f = open(self.path, "rb")
                    self.send_response(200)
                    if self.path.endswith(".ico"):
                        self.send_header("Content-type", "image/x-icon")
                    else:
                        self.send_header("Content-type", "text/html")
                    self.end_headers()
                    self.wfile.write(f.read())
                    f.close()
                    return
                except IOError:
                    responsetxt = (
                        b"<h2>Welcome to Grott the growatt inverter monitor</h2>\r\n"
                    )
                    responsetxt += b"<br><h3>Made by Ledidobe, Johan Meijer</h3>\r\n"
                    responserc = 200
                    responseheader = "text/html"
                    htmlsendresp(self, responserc, responseheader, responsetxt)
                    return

            elif self.path.startswith("datalogger") or self.path.startswith("inverter"):
                if self.path.startswith("datalogger"):
                    if self.verbose:
                        print(
                            "\t - " + "Grotthttpserver - datalogger get received : ",
                            urlquery,
                        )
                    sendcommand = "19"
                else:
                    if self.verbose:
                        print(
                            "\t - " + "Grotthttpserver - inverter get received : ",
                            urlquery,
                        )
                    sendcommand = "05"

                # validcommand = False
                if not urlquery:
                    # no command entered return loggerreg info:
                    responsetxt = json.dumps(self.loggerreg).encode("utf-8") + b"\r\n"
                    responserc = 200
                    responseheader = "application/json"
                    htmlsendresp(self, responserc, responseheader, responsetxt)
                    return

                try:
                    # is valid command specified?
                    command = urlquery["command"][0]
                    # print(command)
                    if command in ("register", "regall"):
                        if self.verbose:
                            print("\t - " + "Grott: get command: ", command)
                    else:
                        # no valid command entered
                        responsetxt = b"no valid command entered\r\n"
                        responserc = 400
                        responseheader = "text/plain"
                        htmlsendresp(self, responserc, responseheader, responsetxt)
                        return
                except Exception:
                    responsetxt = b"no command entered\r\n"
                    responserc = 400
                    responseheader = "text/plain"
                    htmlsendresp(self, responserc, responseheader, responsetxt)
                    return

                # test if datalogger  and / or inverter id is specified.
                try:
                    if sendcommand == "05":
                        inverterid_found = False
                        try:
                            # test if inverter id is specified and get loggerid
                            inverterid = urlquery["inverter"][0]
                            for key in self.loggerreg.keys():
                                for key2 in self.loggerreg[key].keys():
                                    if key2 == inverterid:
                                        dataloggerid = key
                                        inverterid_found = True
                                        break
                        except Exception:
                            inverterid_found = False

                        if not inverterid_found:
                            responsetxt = b"no or no valid invertid specified\r\n"
                            responserc = 400
                            responseheader = "text/html"
                            htmlsendresp(self, responserc, responseheader, responsetxt)
                            return

                        try:
                            # is format keyword specified? (dec, text, hex)
                            formatval = urlquery["format"][0]
                            if formatval not in ("dec", "hex", "text"):
                                responsetxt = b"invalid format specified\r\n"
                                responserc = 400
                                responseheader = "text/plain"
                                htmlsendresp(
                                    self, responserc, responseheader, responsetxt
                                )
                                return
                        except Exception:
                            # no set default format op dec.
                            formatval = "dec"

                    if sendcommand == "19":
                        # if read datalogger info.
                        dataloggerid = urlquery["datalogger"][0]

                        try:
                            # Verify dataloggerid is specified
                            dataloggerid = urlquery["datalogger"][0]
                            test = self.loggerreg[dataloggerid]
                        except Exception:
                            responsetxt = b"invalid datalogger id\r\n"
                            responserc = 400
                            responseheader = "text/plain"
                            htmlsendresp(self, responserc, responseheader, responsetxt)
                            return
                except Exception:
                    # do not think we will come here
                    responsetxt = b"no datalogger or inverterid specified\r\n"
                    responserc = 400
                    responseheader = "text/plain"
                    htmlsendresp(self, responserc, responseheader, responsetxt)
                    return

                # test if register is specified and set reg value.
                if command == "register":
                    # test if valid reg is applied
                    if (
                        int(urlquery["register"][0]) >= 0
                        and int(urlquery["register"][0]) < 1024
                    ):
                        register = urlquery["register"][0]
                    else:
                        responsetxt = b"invalid reg value specified\r\n"
                        responserc = 400
                        responseheader = "text/plain"
                        htmlsendresp(self, responserc, responseheader, responsetxt)
                        return
                elif command == "regall":
                    comresp = self.commandresponse[sendcommand]
                    responsetxt = json.dumps(comresp).encode("utf-8") + b"\r\n"
                    responserc = 200
                    responseheader = "application/json"
                    htmlsendresp(self, responserc, responseheader, responsetxt)
                    return

                else:
                    responsetxt = b"command not defined or not available yet\r\n"
                    responserc = 400
                    responseheader = "text/plain"
                    htmlsendresp(self, responserc, responseheader, responsetxt)
                    return

                bodybytes = dataloggerid.encode("utf-8")
                body = bodybytes.hex()

                if self.loggerreg[dataloggerid]["protocol"] == "06":
                    body = body + "0000000000000000000000000000000000000000"
                body = body + f"{int(register):04x}"
                # assumption now only 1 reg query; other put below end register
                body = body + f"{int(register):04x}"
                # calculate length of payload = body/2 (str => bytes) + 2 bytes invertid + command.
                bodylen = int(len(body) / 2 + 2)

                header = (
                    f"{self.conf.sendseq:04x}"
                    + "00"
                    + self.loggerreg[dataloggerid]["protocol"]
                    + f"{bodylen:04x}"
                    + "01"
                    + sendcommand
                )
                body = header + body
                body = bytes.fromhex(body)

                if self.loggerreg[dataloggerid]["protocol"] != "02":
                    # encrypt message
                    body = decrypt(body)
                    crc16 = libscrc.modbus(bytes.fromhex(body))
                    body = bytes.fromhex(body) + crc16.to_bytes(2, "big")

                # add header
                if self.verbose:
                    print("\t - Grotthttpserver: command created :")
                    print(format_multi_line("\t\t ", body))

                # queue command
                qname = (
                    self.loggerreg[dataloggerid]["ip"]
                    + "_"
                    + str(self.loggerreg[dataloggerid]["port"])
                )
                self.send_queuereg[qname].put(body)
                responseno = f"{self.conf.sendseq:04x}"
                regkey = f"{int(register):04x}"
                try:
                    del self.commandresponse[sendcommand][regkey]
                except Exception:
                    pass

                # wait for response
                if self.verbose:
                    print("\t - Grotthttpserver - wait for GET response")
                for _ in range(self.conf.registerreadtimeout * 100):
                    try:
                        comresp = self.commandresponse[sendcommand][regkey]

                        if sendcommand == "05":
                            if formatval == "dec":
                                comresp["value"] = int(comresp["value"], 16)
                            elif formatval == "text":
                                comresp["value"] = codecs.decode(
                                    comresp["value"], "hex"
                                ).decode("utf-8")
                        responsetxt = json.dumps(comresp).encode("utf-8") + b"\r\n"
                        responserc = 200
                        responseheader = "application/json"
                        htmlsendresp(self, responserc, responseheader, responsetxt)
                        return

                    except Exception:
                        # wait for 0.01 second and try again
                        time.sleep(0.01)
                try:
                    if comresp:
                        responsetxt = json.dumps(comresp).encode("utf-8") + b"\r\n"
                        responserc = 200
                        responseheader = "application/json"
                        htmlsendresp(self, responserc, responseheader, responsetxt)
                        return

                except Exception:
                    responsetxt = b"no or invalid response received\r\n"
                    responserc = 400
                    responseheader = "text/plain"
                    htmlsendresp(self, responserc, responseheader, responsetxt)
                    return

                responsetxt = b"OK\r\n"
                responserc = 200
                responseheader = "text/plain"
                if self.verbose:
                    print(
                        "\t - " + "Grott: datalogger command response :",
                        responserc,
                        responsetxt,
                        responseheader,
                    )
                htmlsendresp(self, responserc, responseheader, responsetxt)
                return

            elif self.path == "help":
                responserc = 200
                responseheader = "text/plain"
                responsetxt = b"No help available yet\r\n"
                htmlsendresp(self, responserc, responseheader, responsetxt)
                return
            else:
                self.send_error(400, "Bad request")

        except Exception as e:
            print(
                "\t - Grottserver - exception in httpserver thread - get occured : ", e
            )

    def do_PUT(self):
        try:
            # if verbose: print("\t - Grott: datalogger PUT received")

            url = urlparse(self.path)
            urlquery = parse_qs(url.query)

            # only allow files from current directory
            if self.path[0] == "/":
                self.path = self.path[1 : len(self.path)]

            if self.path.startswith("datalogger") or self.path.startswith("inverter"):
                if self.path.startswith("datalogger"):
                    if self.verbose:
                        print(
                            "\t - Grotthttpserver - datalogger PUT received : ",
                            urlquery,
                        )
                    sendcommand = "18"
                else:
                    if self.verbose:
                        print(
                            "\t - Grotthttpserver - inverter PUT received : ", urlquery
                        )
                    sendcommand = "06"

                if not urlquery:
                    # no command entered return loggerreg info:
                    responsetxt = b"empty put received\r\n"
                    responserc = 400
                    responseheader = "text/html"
                    htmlsendresp(self, responserc, responseheader, responsetxt)
                    return

                try:
                    # is valid command specified?
                    command = urlquery["command"][0]
                    if command in ("register", "datetime"):
                        if self.verbose:
                            print("\t - Grotthttpserver - PUT command: ", command)
                    else:
                        responsetxt = b"no valid command entered\r\n"
                        responserc = 400
                        responseheader = "text/plain"
                        htmlsendresp(self, responserc, responseheader, responsetxt)
                        return
                except Exception:
                    responsetxt = b"no command entered\r\n"
                    responserc = 400
                    responseheader = "text/plain"
                    htmlsendresp(self, responserc, responseheader, responsetxt)
                    return

                # test if datalogger  and / or inverter id is specified.
                try:
                    if sendcommand == "06":
                        inverterid_found = False
                        try:
                            # test if inverter id is specified and get loggerid
                            inverterid = urlquery["inverter"][0]
                            for key in self.loggerreg.keys():
                                for key2 in self.loggerreg[key].keys():
                                    if key2 == inverterid:
                                        dataloggerid = key
                                        inverterid_found = True
                                        break
                        except Exception:
                            inverterid_found = False

                        if not inverterid_found:
                            responsetxt = b"no or invalid invertid specified\r\n"
                            responserc = 400
                            responseheader = "text/plain"
                            htmlsendresp(self, responserc, responseheader, responsetxt)
                            return

                    if sendcommand == "18":
                        # if read datalogger info.
                        dataloggerid = urlquery["datalogger"][0]

                        try:
                            # Verify dataloggerid is specified
                            dataloggerid = urlquery["datalogger"][0]
                            test = self.loggerreg[dataloggerid]

                        except Exception:
                            responsetxt = b"invalid datalogger id\r\n"
                            responserc = 400
                            responseheader = "text/plain"
                            htmlsendresp(self, responserc, responseheader, responsetxt)
                            return
                except Exception:
                    # do not think we will come here
                    responsetxt = b"no datalogger or inverterid specified\r\n"
                    responserc = 400
                    responseheader = "text/plain"
                    htmlsendresp(self, responserc, responseheader, responsetxt)
                    return

                # test if register is specified and set reg value.

                if command == "register":
                    # test if valid reg is applied
                    if (
                        int(urlquery["register"][0]) >= 0
                        and int(urlquery["register"][0]) < 1024
                    ):
                        register = urlquery["register"][0]
                    else:
                        responsetxt = b"invalid reg value specified\r\n"
                        responserc = 400
                        responseheader = "text/plain"
                        htmlsendresp(self, responserc, responseheader, responsetxt)
                        return

                    try:
                        value = urlquery["value"][0]
                    except Exception:
                        responsetxt = b"no value specified\r\n"
                        responserc = 400
                        responseheader = "text/plain"
                        htmlsendresp(self, responserc, responseheader, responsetxt)
                        return

                    if value == "":
                        responsetxt = b"no value specified\r\n"
                        responserc = 400
                        responseheader = "text/plain"
                        htmlsendresp(self, responserc, responseheader, responsetxt)
                        return

                elif command == "datetime":
                    # process set datetime, only allowed for datalogger!!!
                    if sendcommand == "06":
                        responsetxt = b"datetime command not allowed for inverter\r\n"
                        responserc = 400
                        responseheader = "text/plain"
                        htmlsendresp(self, responserc, responseheader, responsetxt)
                        return
                    # prepare datetime
                    register = 31
                    value = getcurrenttime(self.conf)

                else:
                    # Start additional command processing here, to be created:
                    # translate command to register (from list>)
                    responsetxt = b"command not defined or not available yet\r\n"
                    responserc = 400
                    responseheader = "text/plain"
                    htmlsendresp(self, responserc, responseheader, responsetxt)
                    return

                # test value:
                if sendcommand == "06":
                    try:
                        # is format keyword specified? (dec, text, hex)
                        formatval = urlquery["format"][0]
                        if formatval not in ("dec", "hex", "text"):
                            responsetxt = b"invalid format specified\r\n"
                            responserc = 400
                            responseheader = "text/plain"
                            htmlsendresp(self, responserc, responseheader, responsetxt)
                            return
                    except Exception:
                        # no set default format op dec.
                        formatval = "dec"

                    # convert value if necessary
                    if formatval == "dec":
                        # input in dec (standard)
                        value = int(value)
                    elif formatval == "text":
                        # input in text
                        value = int(value.encode("utf-8").hex(), 16)
                    else:
                        # input in Hex
                        value = int(value, 16)

                    if value < 0 and value > 65535:
                        responsetxt = b"invalid value specified\r\n"
                        responserc = 400
                        responseheader = "text/plain"
                        htmlsendresp(self, responserc, responseheader, responsetxt)
                        return

                # start creating command

                bodybytes = dataloggerid.encode("utf-8")
                body = bodybytes.hex()

                if self.loggerreg[dataloggerid]["protocol"] == "06":
                    body = body + "0000000000000000000000000000000000000000"

                if sendcommand == "06":
                    value = f"{value:04x}"
                    valuelen = ""
                else:
                    value = value.encode("utf-8").hex()
                    valuelen = int(len(value) / 2)
                    valuelen = f"{valuelen:04x}"

                body = body + f"{int(register):04x}" + valuelen + value
                bodylen = int(len(body) / 2 + 2)

                # create header
                header = (
                    f"{self.conf.sendseq:04x}"
                    + "00"
                    + self.loggerreg[dataloggerid]["protocol"]
                    + f"{bodylen:04x}"
                    + "01"
                    + sendcommand
                )
                body = header + body
                body = bytes.fromhex(body)

                if self.verbose:
                    print("\t - Grotthttpserver - unencrypted command:")
                    print(format_multi_line("\t\t ", body))

                if self.loggerreg[dataloggerid]["protocol"] != "02":
                    # encrypt message
                    body = decrypt(body)
                    crc16 = libscrc.modbus(bytes.fromhex(body))
                    body = bytes.fromhex(body) + crc16.to_bytes(2, "big")

                # queue command
                qname = (
                    self.loggerreg[dataloggerid]["ip"]
                    + "_"
                    + str(self.loggerreg[dataloggerid]["port"])
                )
                self.send_queuereg[qname].put(body)
                responseno = f"{self.conf.sendseq:04x}"
                regkey = f"{int(register):04x}"
                try:
                    # delete response: be aware a 18 command give 19 response,
                    # 06 send command gives 06 response in differnt format!
                    if sendcommand == "18":
                        del self.commandresponse[sendcommand][regkey]
                    else:
                        del self.commandresponse[sendcommand][regkey]
                except Exception:
                    pass

                # wait for response
                if self.verbose:
                    print("\t - Grotthttpserver - wait for PUT response")
                for _ in range(self.conf.registerwritetimeout * 100):
                    try:
                        # read response: be aware a 18 command give 19 response,
                        # 06 send command gives 06 response in differnt format!
                        if sendcommand == "18":
                            comresp = self.commandresponse["18"][regkey]
                        else:
                            comresp = self.commandresponse[sendcommand][regkey]
                        if self.verbose:
                            print(
                                "\t - " + "Grotthttperver - Commandresponse ",
                                responseno,
                                register,
                                self.commandresponse[sendcommand][regkey],
                            )
                        break
                    except Exception:
                        # wait for 0.01 second and try again
                        time.sleep(0.01)
                try:
                    if comresp != "":
                        responsetxt = b"OK\r\n"
                        responserc = 200
                        responseheader = "text/plain"
                        htmlsendresp(self, responserc, responseheader, responsetxt)
                        return

                except Exception:
                    responsetxt = b"no or invalid response received\r\n"
                    responserc = 400
                    responseheader = "text/plain"
                    htmlsendresp(self, responserc, responseheader, responsetxt)
                    return

                responsetxt = b"OK\r\n"
                responserc = 200
                responseheader = "text/plain"
                if self.verbose:
                    print(
                        "\t - " + "Grott: datalogger command response :",
                        responserc,
                        responsetxt,
                        responseheader,
                    )
                htmlsendresp(self, responserc, responseheader, responsetxt)
                return

        except Exception as e:
            print(
                "\t - Grottserver - exception in htppserver thread - put occured : ", e
            )


class GrottHttpServer:
    """This wrapper will create an HTTP server where the handler has access to the send_queue"""

    def __init__(self, conf, send_queuereg, loggerreg, commandresponse):
        def handler_factory(*args):
            """
            Using a function to create and return the handler,
            so we can provide our own argument (send_queue)
            """
            return GrottHttpRequestHandler(
                send_queuereg, conf, loggerreg, commandresponse, *args
            )

        self.server = http.server.HTTPServer(
            (conf.httphost, conf.httpport), handler_factory
        )
        self.server.allow_reuse_address = True
        print(
            f"\t - GrottHttpserver - Ready to listen at: {conf.httphost}:{conf.httpport}"
        )

    def run(self):
        print("\t - GrottHttpserver - server listening")
        self.server.serve_forever()


class sendrecvserver:
    def __init__(self, conf, send_queuereg, loggerreg, commandresponse):
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind((conf.grottip, conf.grottport))
        self.server.listen(5)

        self.commandresponse = commandresponse
        self.conf = conf
        self.forward_input = {}
        self.inputs = [self.server]
        self.loggerreg = loggerreg
        self.outputs = []
        self.send_queuereg = send_queuereg
        self.verbose = conf.verbose

        print(f"\t - Grottserver - Ready to listen at: {conf.grottip}:{conf.grottport}")

    def run(self):
        print("\t - Grottserver - server listening")
        while self.inputs:
            readable, writable, exceptional = select.select(
                self.inputs, self.outputs, self.inputs
            )

            for s in readable:
                self.handle_readable_socket(s)

            for s in writable:
                self.handle_writable_socket(s)

            for s in exceptional:
                self.handle_exceptional_socket(s)

    def handle_readable_socket(self, s):
        try:
            if s is self.server:
                self.handle_new_connection(s)
                if self.verbose:
                    print("\t - " + "Grottserver - input received: ", self.server)
            else:
                # Existing connection
                data = s.recv(1024)
                if data:
                    self.process_data(s, data)
                else:
                    self.close_connection(s)
        except Exception as e:
            print(
                "\t - Grottserver - exception in server thread - handle_readable_socket : ",
                e,
            )
            self.close_connection(s)

    def handle_writable_socket(self, s):
        try:
            client_address, client_port = s.getpeername()

            try:
                qname = f"{client_address}_{client_port}"
                next_msg = self.send_queuereg[qname].get_nowait()
                if self.verbose:
                    print(
                        "\t - " + "Grottserver - get response from queue: ",
                        qname + " msg: ",
                    )
                    print(format_multi_line("\t\t ", next_msg))
                s.send(next_msg)
            except queue.Empty:
                pass

        except Exception as e:
            print(
                "\t - Grottserver - exception in server thread - handle_writable_socket : ",
                e,
            )
            self.close_connection(s)

    def handle_exceptional_socket(self, s):
        if self.verbose:
            print("\t - " + "Grottserver - Encountered an exception")
        self.close_connection(s)

    def handle_new_connection(self, s):
        try:
            connection, client_address = s.accept()
            self.inputs.append(connection)
            self.outputs.append(connection)
            self.forward_input[connection] = ()
            if self.conf.serverforward:
                forward = Forward().start(self.conf.growattip, self.conf.growattport)
                if forward:
                    if self.verbose:
                        print(
                            "\t - " + "Grottserver - Forward started: ",
                            self.conf.growattip,
                            self.conf.growattport,
                        )
                    self.forward_input[connection] = (
                        forward,
                        self.conf.growattip,
                        self.conf.growattport,
                    )
                else:
                    print(
                        "\t - " + "Grottserver - Forward failed: ",
                        self.conf.growattip,
                        self.conf.growattport,
                    )
                    forward.close()
            print(
                f"\t - Grottserver - Socket connection received from {client_address}"
            )
            client_address, client_port = connection.getpeername()
            qname = f"{client_address}_{client_port}"

            # create queue
            self.send_queuereg[qname] = queue.Queue()
            # print(send_queuereg)
            if self.verbose:
                print(f"\t - Grottserver - Send queue created for : {qname}")
        except Exception as e:
            print(
                "\t - Grottserver - exception in server thread - handle_new_connection : ",
                e,
            )
            # self.close_connection(s)

    def forward_data(self, s, data, attempts=0):
        if not self.forward_input[s]:
            return
        fsock, host, port = self.forward_input[s]
        try:
            fsock.send(data)
            print(f"\t - Grottserver - Forward data sent for {host}:{port}")
        except Exception as e:
            fsock.close()
            del self.forward_input[s]

            forward = Forward().start(host, port)
            if forward:
                if self.verbose:
                    print("\t - Grottserver - Forward started: ", host, port)
                self.forward_input[s] = (forward, host, port)
                if attempts < 3:
                    self.forward_data(s, data, attempts + 1)
                else:
                    print("\t - Grottserver - Forward failed: ", host, port)

    def close_connection(self, s):
        try:
            print("\t - Grottserver - Close connection : ", s)
            s.close()

            if s in self.outputs:
                self.outputs.remove(s)
            self.inputs.remove(s)

            if s in self.forward_input:
                fsock, host, port = self.forward_input[s]
                fsock.close()

            client_address, client_port = s.getpeername()
            qname = f"{client_address}_{client_port}"
            del self.send_queuereg[qname]

            ### after this also clean the logger reg. To be implemented ?
            for key in self.loggerreg.keys():
                if (
                    self.loggerreg[key]["ip"] == client_address
                    and self.loggerreg[key]["port"] == client_port
                ):
                    del self.loggerreg[key]
                    print(
                        "\t - Grottserver - config information deleted for datalogger and connected inverters : ",
                        key,
                    )
                    # to be developed delete also register information for this datalogger (and connected inverters).
                    # Be aware this need redef of commandresp!
                    break

        except Exception as e:
            print(
                "\t - Grottserver - exception in server thread - close connection :", e
            )
            s.close()

    def process_data(self, s, data):

        # Prevent generic errors:
        try:
            # process data and create response
            client_address, client_port = s.getpeername()
            qname = f"{client_address}_{client_port}"

            # Display data
            print(
                f"\t - Grottserver - Data received from : {client_address}:{client_port}"
            )
            if self.verbose:
                print("\t - " + "Grottserver - Original Data:")
                print(format_multi_line("\t\t ", data))

            # get last two bytes for CRC16
            crc16 = data[-2:]
            # get crc16 of body
            crc16_body = libscrc.modbus(data[0:-2])
            # check if crc16 is correct
            if crc16_body == int.from_bytes(crc16, "big"):
                if self.verbose:
                    print("\t - Grottserver - CRC16 OK")
            else:
                print(
                    "\t - Grottserver - CRC16 ERROR - received: ",
                    crc16_body,
                    " expected: ",
                    int.from_bytes(crc16, "big"),
                )
                self.close_connection(s)
                return

            # Collect data for MQTT, PVOutput, InfluxDB, etc..
            if len(data) > self.conf.minrecl:
                grottdata(self.conf, data)
            else:
                if self.conf.verbose:
                    print(
                        "\t - "
                        + "Data less then minimum record length, data not processed"
                    )

            # Create header
            header = "".join(f"{n:02x}" for n in data[0:8])
            protocol = header[6:8]
            sequencenumber = header[0:4]
            protocol = header[6:8]
            command = header[14:16]
            if protocol in ("05", "06"):
                result_string = decrypt(data)
            else:
                result_string = data
            if self.verbose:
                print("\t - Grottserver - Plain record: ")
                print(format_multi_line("\t\t ", result_string))
            loggerid = result_string[16:36]
            loggerid = codecs.decode(loggerid, "hex").decode("utf-8")

            # Prepare response
            if header[14:16] in ("16"):
                # if ping send data as reply
                response = data
                if self.verbose:
                    print("\t - Grottserver - 16 - Ping response: ")
                    print(format_multi_line("\t\t ", response))

                # forward data for growatt
                self.forward_data(s, data)

            elif header[14:16] in ("03", "04", "50", "29", "1b", "20"):
                # if datarecord send ack.
                print("\t - Grottserver - " + header[12:16] + " data record received")

                # forward data for growatt
                self.forward_data(s, data)

                # create ack response
                if header[6:8] == "02":
                    # unencrypted ack
                    headerackx = bytes.fromhex(
                        header[0:8] + "0003" + header[12:16] + "00"
                    )
                else:
                    # encrypted ack
                    headerackx = bytes.fromhex(
                        header[0:8] + "0003" + header[12:16] + "47"
                    )

                # Create CRC 16 Modbus
                crc16 = libscrc.modbus(headerackx)

                # create response
                response = headerackx + crc16.to_bytes(2, "big")
                if self.verbose:
                    print("\t - Grottserver - Response: ")
                    print(format_multi_line("\t\t", response))

                if header[14:16] == "03":
                    # init record register logger/inverter id (including sessionid?)
                    # decrypt body.
                    if header[6:8] in ("05", "06"):
                        # print("header1 : ", header[6:8])
                        result_string = decrypt(data)
                    else:
                        result_string = data

                    loggerid = result_string[16:36]
                    loggerid = codecs.decode(loggerid, "hex").decode("utf-8")
                    if header[12:14] in ("02", "05"):
                        inverterid = result_string[36:56]
                    else:
                        inverterid = result_string[76:96]
                    inverterid = codecs.decode(inverterid, "hex").decode("utf-8")

                    try:
                        self.loggerreg[loggerid].update(
                            {
                                "ip": client_address,
                                "port": client_port,
                                "protocol": header[6:8],
                            }
                        )
                    except Exception:
                        self.loggerreg[loggerid] = {
                            "ip": client_address,
                            "port": client_port,
                            "protocol": header[6:8],
                        }

                    # add invertid
                    self.loggerreg[loggerid].update(
                        {inverterid: {"inverterno": header[12:14], "power": 0}}
                    )
                    self.send_queuereg[qname].put(response)
                    time.sleep(1)
                    response = createtimecommand(
                        self.conf, protocol, loggerid, "0001", self.commandresponse
                    )
                    if self.verbose:
                        print("\t - Grottserver 03 announce data record processed")

            elif header[14:16] in ("19", "05", "06", "18"):
                if self.verbose:
                    print(
                        "\t - Grottserver - "
                        + header[12:16]
                        + " record received, no response needed"
                    )

                offset = 0
                if protocol in ("06"):
                    offset = 40

                register = int(result_string[36 + offset : 40 + offset], 16)
                if command == "05":
                    # value = result_string[40+offset:44+offset]
                    value = result_string[44 + offset : 48 + offset]
                elif command == "06":
                    result = result_string[40 + offset : 42 + offset]
                    # print("06 response result :", result)
                    value = result_string[42 + offset : 46 + offset]
                elif command == "18":
                    result = result_string[40 + offset : 42 + offset]
                else:
                    # "19" response take length into account
                    valuelen = int(result_string[40 + offset : 44 + offset], 16)
                    value = codecs.decode(
                        result_string[44 + offset : 44 + offset + valuelen * 2], "hex"
                    ).decode("utf-8")

                regkey = f"{register:04x}"
                if command == "06":
                    # command 06 response has ack (result) + value. We will create a 06 response and a 05 response (for reg administration)
                    self.commandresponse["06"][regkey] = {
                        "value": value,
                        "result": result,
                    }
                    self.commandresponse["05"][regkey] = {"value": value}
                if command == "18":
                    self.commandresponse["18"][regkey] = {"result": result}
                else:
                    # command 05 or 19
                    self.commandresponse[command][regkey] = {"value": value}

                response = None

            else:
                if self.verbose:
                    print("\t - Grottserver - Unknown record received:")
                response = None

            if response is not None:
                if self.verbose:
                    print("\t - Grottserver - Put response on queue: ", qname, " msg: ")
                    print(format_multi_line("\t\t ", response))
                self.send_queuereg[qname].put(response)
        except Exception as e:
            print("\t - Grottserver - exception in main server thread occured : ", e)


class Server:
    def __init__(self, conf):
        self.conf = conf
        self.send_queuereg = {}
        self.loggerreg = {}
        self.commandresponse = defaultdict(dict)

    def main(self, conf):
        if conf.grottip == "default":
            conf.grottip = "0.0.0.0"

        http_server = GrottHttpServer(
            conf, self.send_queuereg, self.loggerreg, self.commandresponse
        )
        device_server = sendrecvserver(
            conf, self.send_queuereg, self.loggerreg, self.commandresponse
        )

        http_server_thread = threading.Thread(target=http_server.run)
        device_server_thread = threading.Thread(target=device_server.run)

        http_server_thread.start()
        device_server_thread.start()

        http_server_thread.join()
        device_server_thread.join()
