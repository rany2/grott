import codecs
import hashlib
import http.server
import json
import queue
import socket
import socketserver
import threading
from collections import defaultdict
from datetime import datetime
from urllib.parse import parse_qs, urlparse

import libscrc
import pytz

from grottdata import decrypt, format_multi_line, print
from grottdata import procdata as grottdata
from grottproxy import Forward

# grottserver.py emulates the server.growatt.com website and is
# initially developed for debugging and testing grott.


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
    except pytz.UnknownTimeZoneError:
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
    bodybytes = loggerid.encode("ascii")
    body = bodybytes.hex()
    if protocol == "06":
        body = body + "0000000000000000000000000000000000000000"
    register = 31
    body = body + f"{int(register):04x}"
    currenttime = getcurrenttime(conf)
    timex = currenttime.encode("ascii").hex()
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
    except KeyError:
        pass

    return body


def crc16_verify(data):
    crc16 = libscrc.modbus(data[:-2])
    return crc16 == int.from_bytes(data[-2:], "big")


def queue_commandrespcreate(commandresponse, qname, sendcommand, regkey):
    if "queue" not in commandresponse[qname]:
        commandresponse[qname]["queue"] = {}

    if sendcommand not in commandresponse[qname]["queue"]:
        commandresponse[qname]["queue"][sendcommand] = {}

    if regkey not in commandresponse[qname]["queue"][sendcommand]:
        commandresponse[qname]["queue"][sendcommand][regkey] = queue.Queue()


def queue_commandrespclear(commandresponse, qname, sendcommand, regkey):
    queue_commandrespcreate(commandresponse, qname, sendcommand, regkey)
    commandresponse[qname]["queue"][sendcommand][regkey].queue.clear()


def queue_commandrespadd(commandresponse, qname, sendcommand, regkey, value):
    queue_commandrespclear(commandresponse, qname, sendcommand, regkey)
    commandresponse[qname]["queue"][sendcommand][regkey].put_nowait(value)


def queue_commandrespget(commandresponse, qname, sendcommand, regkey, timeout=0):
    queue_commandrespcreate(commandresponse, qname, sendcommand, regkey)
    return commandresponse[qname]["queue"][sendcommand][regkey].get(timeout=timeout)


class GrottHttpRequestHandler(http.server.BaseHTTPRequestHandler):
    def __init__(self, send_queuereg, conf, loggerreg, commandresponse, *args):
        self.send_queuereg = send_queuereg
        self.conf = conf
        self.verbose = conf.verbose
        self.loggerreg = loggerreg
        self.commandresponse = commandresponse
        super().__init__(*args)

    def setup(self):
        self.request.settimeout(self.conf.httpsockettimeout)
        super().setup()

    def send_header(self, keyword, value):
        if keyword.lower() == "server":
            return
        super().send_header(keyword, value)

    def authorized(self):
        token = self.conf.httptoken
        if token is None:
            return True

        authorization = self.headers.get("authorization")
        if authorization is None:
            return False

        if authorization.split(" ")[0] != "Bearer":
            return False

        token_hash = hashlib.sha256(
            " ".join(authorization.split(" ")[1:]).encode("utf-8")
        ).hexdigest()
        if token_hash.lower() != token.lower():
            return False

        return True

    def match_invertid_to_dataloggerid(self, urlquery):
        dataloggerid = None
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
        except (KeyError, IndexError):
            pass

        if not inverterid_found:
            responsetxt = b"no or no valid invertid specified\r\n"
            responserc = 400
            responseheader = "text/html"
            htmlsendresp(self, responserc, responseheader, responsetxt)
            return None, None

        try:
            # is format keyword specified? (dec, text, hex)
            formatval = urlquery["format"][0]
            if formatval not in ("dec", "hex", "text"):
                responsetxt = b"invalid format specified\r\n"
                responserc = 400
                responseheader = "text/plain"
                htmlsendresp(self, responserc, responseheader, responsetxt)
                return None, None
        except (KeyError, IndexError):
            # no set default format op dec.
            formatval = "dec"

        return dataloggerid, formatval

    def validate_dataloggerid(self, urlquery):
        dataloggerid = None

        try:
            # Verify dataloggerid is specified
            dataloggerid = urlquery["datalogger"][0]
            _ = self.loggerreg[dataloggerid]
        except (KeyError, IndexError):
            responsetxt = b"invalid datalogger id\r\n"
            responserc = 400
            responseheader = "text/plain"
            htmlsendresp(self, responserc, responseheader, responsetxt)
            return None

        if dataloggerid is None:
            responsetxt = b"no datalogger id specified\r\n"
            responserc = 400
            responseheader = "text/plain"
            htmlsendresp(self, responserc, responseheader, responsetxt)
            return None

        return dataloggerid

    def get_qname(self, dataloggerid):
        return f"{self.loggerreg[dataloggerid]['ip']}_{self.loggerreg[dataloggerid]['port']}"

    def do_GET(self):
        if not self.authorized():
            self.send_error(401, "Unauthorized")
            return

        if self.verbose:
            print("\t - Grotthttpserver - Get received ")

        # parse url
        url = urlparse(self.path)
        urlquery = parse_qs(url.query)

        # only allow files from current directory
        if self.path[0] == "/":
            self.path = self.path[1 : len(self.path)]

        # strip query string
        self.path = self.path.split("?")[0]

        if self.path in ("datalogger", "inverter"):
            if self.path == "datalogger":
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
            except (KeyError, IndexError):
                responsetxt = b"no command entered\r\n"
                responserc = 400
                responseheader = "text/plain"
                htmlsendresp(self, responserc, responseheader, responsetxt)
                return

            if sendcommand == "05":
                # get inverter id
                dataloggerid, formatval = self.match_invertid_to_dataloggerid(urlquery)
                if None in (dataloggerid, formatval):
                    return
            elif sendcommand == "19":
                # get datalogger id
                dataloggerid = self.validate_dataloggerid(urlquery)
                if dataloggerid is None:
                    return

            qname = self.get_qname(dataloggerid)

            # test if register is specified and set reg value.
            if command == "register":
                # test if valid reg is applied
                try:
                    if 0 <= int(urlquery["register"][0]) < 1024:
                        register = urlquery["register"][0]
                    else:
                        raise ValueError("invalid register value")
                except (KeyError, IndexError, ValueError):
                    responsetxt = b"invalid reg value specified\r\n"
                    responserc = 400
                    responseheader = "text/plain"
                    htmlsendresp(self, responserc, responseheader, responsetxt)
                    return
            elif command == "regall":
                comresp = self.commandresponse[qname][sendcommand]
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

            bodybytes = dataloggerid.encode("ascii")
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
            self.send_queuereg[qname].put_nowait(body)
            # responseno = f"{self.conf.sendseq:04x}"
            regkey = f"{int(register):04x}"
            try:
                del self.commandresponse[qname][sendcommand][regkey]
            except KeyError:
                pass

            # clear all possible responses for this command to ensure no old responses are returned.
            queue_commandrespclear(self.commandresponse, qname, sendcommand, regkey)

            try:
                comresp = queue_commandrespget(
                    self.commandresponse,
                    qname,
                    sendcommand,
                    regkey,
                    timeout=self.conf.registerreadtimeout,
                )
                if sendcommand == "05":
                    if formatval == "dec":
                        comresp["value"] = int(comresp["value"], 16)
                    elif formatval == "text":
                        comresp["value"] = codecs.decode(
                            comresp["value"], "hex"
                        ).decode("ascii", "backslashreplace")
                    elif formatval == "hex":
                        # comresp["value"] already in hex,
                        # no need to do anything.
                        pass
                responsetxt = json.dumps(comresp).encode("utf-8") + b"\r\n"
                responserc = 200
                responseheader = "application/json"
                htmlsendresp(self, responserc, responseheader, responsetxt)
                return
            except (queue.Empty, KeyError, IndexError, ValueError):
                responsetxt = b"no or invalid response received\r\n"
                responserc = 400
                responseheader = "text/plain"
                htmlsendresp(self, responserc, responseheader, responsetxt)
                return

        elif self.path == "help":
            responserc = 200
            responseheader = "text/plain"
            responsetxt = b"No help available yet\r\n"
            htmlsendresp(self, responserc, responseheader, responsetxt)
            return
        else:
            self.send_error(404)

    def do_PUT(self):
        if not self.authorized():
            self.send_error(401, "Unauthorized")
            return

        url = urlparse(self.path)
        urlquery = parse_qs(url.query)

        # only allow files from current directory
        if self.path[0] == "/":
            self.path = self.path[1 : len(self.path)]
        self.path = self.path.split("?")[0]

        if self.path in ("datalogger", "inverter"):
            if self.path == "datalogger":
                if self.verbose:
                    print(
                        "\t - Grotthttpserver - datalogger PUT received : ",
                        urlquery,
                    )
                sendcommand = "18"
            else:
                if self.verbose:
                    print("\t - Grotthttpserver - inverter PUT received : ", urlquery)
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
            except (KeyError, IndexError):
                responsetxt = b"no command entered\r\n"
                responserc = 400
                responseheader = "text/plain"
                htmlsendresp(self, responserc, responseheader, responsetxt)
                return

            if sendcommand == "06":
                # match inverter id to dataloggerid
                dataloggerid, formatval = self.match_invertid_to_dataloggerid(urlquery)
                if None in (dataloggerid, formatval):
                    return
            elif sendcommand == "18":
                # get datalogger id
                dataloggerid = self.validate_dataloggerid(urlquery)
                if dataloggerid is None:
                    return

            if command == "register":
                # test if valid reg is applied
                try:
                    if 0 <= int(urlquery["register"][0]) < 1024:
                        register = urlquery["register"][0]
                    else:
                        raise ValueError("invalid register value")
                except (KeyError, IndexError, ValueError):
                    responsetxt = b"invalid reg value specified\r\n"
                    responserc = 400
                    responseheader = "text/plain"
                    htmlsendresp(self, responserc, responseheader, responsetxt)
                    return

                try:
                    value = urlquery["value"][0]
                except (KeyError, IndexError):
                    value = None

                if value is None:
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
                # convert value if necessary
                if formatval == "dec":
                    # input in dec (standard)
                    value = int(value)
                elif formatval == "text":
                    # input in text
                    try:
                        value = int(value.encode("ascii").hex(), 16)
                    except ValueError:
                        value = None
                else:
                    # input in Hex
                    value = int(value, 16)

                if not 0 <= value <= 65535 or value is None:
                    responsetxt = b"invalid value specified\r\n"
                    responserc = 400
                    responseheader = "text/plain"
                    htmlsendresp(self, responserc, responseheader, responsetxt)
                    return

            # start creating command

            bodybytes = dataloggerid.encode("ascii")
            body = bodybytes.hex()

            if self.loggerreg[dataloggerid]["protocol"] == "06":
                body = body + "0000000000000000000000000000000000000000"

            if sendcommand == "06":
                value = f"{value:04x}"
                valuelen = ""
            else:
                value = value.encode("ascii").hex()
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
            qname = self.get_qname(dataloggerid)
            self.send_queuereg[qname].put_nowait(body)
            responseno = f"{self.conf.sendseq:04x}"
            regkey = f"{int(register):04x}"
            try:
                # delete response: be aware a 18 command give 19 response,
                # 06 send command gives 06 response in differnt format!
                del self.commandresponse[qname][sendcommand][regkey]
            except KeyError:
                pass

            # clear all possible responses for this command to ensure no old responses are returned.
            queue_commandrespclear(self.commandresponse, qname, sendcommand, regkey)

            # wait for response
            if self.verbose:
                print("\t - Grotthttpserver - wait for PUT response")
            try:
                # read response: be aware a 18 command give 19 response,
                # 06 send command gives 06 response in differnt format!
                queue_commandrespget(
                    self.commandresponse,
                    qname,
                    sendcommand,
                    regkey,
                    timeout=self.conf.registerwritetimeout,
                )
                if self.verbose:
                    print(
                        "\t - " + "Grotthttperver - Commandresponse ",
                        responseno,
                        register,
                        self.commandresponse[qname][sendcommand][regkey],
                    )
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
            except queue.Empty:
                responsetxt = b"no or invalid response received\r\n"
                responserc = 400
                responseheader = "text/plain"
                htmlsendresp(self, responserc, responseheader, responsetxt)
                return
        else:
            self.send_error(404)


class GrottHttpServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
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

        self.allow_reuse_address = True
        super().__init__((conf.httphost, conf.httpport), handler_factory)
        print(
            f"\t - GrottHttpserver - Ready to listen at: {conf.httphost}:{conf.httpport}"
        )


class GrowattServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    """This wrapper will create a Growatt server where the handler has access to the send_queue"""

    def __init__(self, conf, send_queuereg, loggerreg, commandresponse):
        def handler_factory(*args):
            """
            Using a function to create and return the handler,
            so we can provide our own argument (send_queue)
            """
            return GrowattServerHandler(
                send_queuereg, conf, loggerreg, commandresponse, shutdown_queue, *args
            )

        shutdown_queue = {}
        self.allow_reuse_address = True
        super().__init__((conf.grottip, conf.grottport), handler_factory)
        print(
            f"\t - GrowattServer - Ready to listen at: {conf.grottip}:{conf.grottport}"
        )


class GrowattServerHandler(socketserver.BaseRequestHandler):
    def __init__(
        self, send_queuereg, conf, loggerreg, commandresponse, shutdown_queue, *args
    ):
        self.commandresponse = commandresponse
        self.conf = conf
        self.loggerreg = loggerreg
        self.loggerreg_lock = threading.Lock()
        self.send_queuereg = send_queuereg
        self.shutdown_queue = shutdown_queue
        self.verbose = conf.verbose
        super().__init__(*args)

    def setup(self):
        self.forward_input = ()
        if self.conf.serverforward:
            # Even if the forward failed and Forward().start returned False bool
            # forward_data would reattempt to connect to the growattip:growattport
            # and try to forward the data again. So we should add it without checking
            # the return value of Forward().start
            forward = Forward().start(self.conf.growattip, self.conf.growattport)

            self.forward_input = (
                forward,
                self.conf.growattip,
                self.conf.growattport,
            )

            if self.verbose:
                print(
                    "\t - " + "Grottserver - Forward started: ",
                    self.conf.growattip,
                    self.conf.growattport,
                )

        self.qname = f"{self.client_address[0]}_{self.client_address[1]}"

        # create queue
        self.send_queuereg[self.qname] = queue.Queue()
        if self.verbose:
            print(f"\t - Grottserver - Send queue created for : {self.qname}")

        # create command response
        self.commandresponse[self.qname] = defaultdict(dict)
        if self.verbose:
            print(f"\t - Grottserver - Command response created for : {self.qname}")

        # on any value, shutdown everything
        self.shutdown_queue[self.qname] = queue.Queue()

    def handle(self):
        print(f"\t - Grottserver - Client connected: {self.client_address}")

        # set socket timeout to prevent hanging
        self.request.settimeout(self.conf.serversockettimeout)

        # create read and write threads
        read_thread = threading.Thread(
            target=self.read_data,
        )
        write_thread = threading.Thread(
            target=self.write_data,
        )

        # make sure the threads are stopped when the main thread exits
        read_thread.daemon = True
        write_thread.daemon = True

        # start threads
        read_thread.start()
        write_thread.start()

        # wait for self.shutdown_queue to be filled
        self.shutdown_queue[self.qname].get()

    def finish(self):
        self.close_connection()

    def read_data(self):
        try:
            while True:
                try:
                    data = self.request.recv(1024)
                except OSError:
                    data = None
                if not data:
                    break
                self.process_data(data)
        finally:
            try:
                self.shutdown_queue[self.qname].put_nowait(True)
            except KeyError:
                pass

    def write_data(self):
        try:
            while True:
                data = self.send_queuereg[self.qname].get()
                try:
                    self.request.sendall(data)
                except OSError:
                    break
        finally:
            try:
                self.shutdown_queue[self.qname].put_nowait(True)
            except KeyError:
                pass

    def forward_data(self, data, attempts=0):
        if not self.forward_input:
            return
        fsock, host, port = self.forward_input
        try:
            fsock.send(data)
            if self.verbose:
                print(f"\t - Grottserver - Forward data sent for {host}:{port}")
        except (OSError, AttributeError):
            try:
                fsock.shutdown(socket.SHUT_WR)
            except (OSError, AttributeError):
                pass
            self.forward_input = ()

            forward = Forward().start(host, port)
            if self.verbose:
                print("\t - Grottserver - Forward started: ", host, port)
            self.forward_input = (forward, host, port)
            if attempts < 3:
                self.forward_data(data, attempts + 1)
            else:
                print("\t - Grottserver - Forward failed: ", host, port)

    def close_connection(self):
        print("\t - Grottserver - Close connection : ", self.client_address)

        client_address, client_port = self.client_address

        if self.qname in self.send_queuereg:
            del self.send_queuereg[self.qname]

        if self.qname in self.commandresponse:
            del self.commandresponse[self.qname]

        if self.qname in self.shutdown_queue:
            del self.shutdown_queue[self.qname]

        with self.loggerreg_lock:
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
                    break

        if self.forward_input:
            fsock, _, _ = self.forward_input
            self.forward_input = ()
            if not isinstance(fsock, bool):
                try:
                    fsock.shutdown(socket.SHUT_WR)
                except OSError:
                    pass

    def process_data(self, data):
        # Display data
        if self.verbose:
            print(f"\t - Grottserver - Data received from : {self.qname}")
            print("\t - Grottserver - Original Data:")
            print(format_multi_line("\t\t ", data))

        # Verify CRC16
        if not crc16_verify(data):
            print("\t - Grottserver - CRC16 failed ignoring data")
            return

        # Collect data for MQTT, PVOutput, InfluxDB, etc..
        if len(data) > self.conf.minrecl:
            grottdata(self.conf, data)
        else:
            if self.conf.verbose:
                print(
                    "\t - " + "Data less then minimum record length, data not processed"
                )

        # Create header
        header = "".join(f"{n:02x}" for n in data[0:8])
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
        loggerid = codecs.decode(loggerid, "hex").decode("ascii")

        # Prepare response
        if header[14:16] in ("16"):
            # if ping send data as reply
            response = data
            if self.verbose:
                print("\t - Grottserver - 16 - Ping response: ")
                print(format_multi_line("\t\t ", response))

            # forward data for growatt
            self.forward_data(data)

        elif header[14:16] in ("03", "04", "50", "29", "1b", "20"):
            # if datarecord send ack.
            if self.verbose:
                print("\t - Grottserver - " + header[12:16] + " data record received")

            # forward data for growatt
            self.forward_data(data)

            # create ack response
            if header[6:8] == "02":
                # unencrypted ack
                headerackx = bytes.fromhex(header[0:8] + "0003" + header[12:16] + "00")
            else:
                # encrypted ack
                headerackx = bytes.fromhex(header[0:8] + "0003" + header[12:16] + "47")

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
                loggerid = codecs.decode(loggerid, "hex").decode("ascii")
                if header[12:14] in ("02", "05"):
                    inverterid = result_string[36:56]
                else:
                    inverterid = result_string[76:96]
                inverterid = codecs.decode(inverterid, "hex").decode("ascii")

                if loggerid in self.loggerreg:
                    prev_qname = f"{self.loggerreg[loggerid]['ip']}_{self.loggerreg[loggerid]['port']}"
                    if prev_qname != self.qname:
                        self.shutdown_queue[prev_qname].put_nowait(True)
                        print(
                            f"\t - Grottserver - Shutdown previous connection {prev_qname} for {loggerid}"
                        )

                # we need to confirm before we update the self.loggerreg
                # so we must wait to make sure response is sent before any
                # possible command from HTTP API
                self.send_queuereg[self.qname].put(response)

                with self.loggerreg_lock:
                    if not loggerid in self.loggerreg:
                        self.loggerreg[loggerid] = {}

                    self.loggerreg[loggerid].update(
                        {
                            "ip": self.client_address[0],
                            "port": self.client_address[1],
                            "protocol": header[6:8],
                        }
                    )

                    # add invertid
                    self.loggerreg[loggerid].update(
                        {inverterid: {"inverterno": header[12:14], "power": 0}}
                    )

                response = createtimecommand(
                    self.conf,
                    protocol,
                    loggerid,
                    "0001",
                    self.commandresponse[self.qname],
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
                ).decode("ascii")

            regkey = f"{register:04x}"
            if command == "06":
                # command 06 response has ack (result) + value. We will create a
                # 06 response and a 05 response (for reg administration)
                self.commandresponse[self.qname]["06"][regkey] = {
                    "value": value,
                    "result": result,
                }
                queue_commandrespadd(
                    self.commandresponse,
                    self.qname,
                    command,
                    regkey,
                    {"value": value, "result": result},
                )
                self.commandresponse[self.qname]["05"][regkey] = {"value": value}
            if command == "18":
                self.commandresponse[self.qname]["18"][regkey] = {"result": result}
                queue_commandrespadd(
                    self.commandresponse,
                    self.qname,
                    command,
                    regkey,
                    {"result": result},
                )
            else:
                # command 05 or 19
                self.commandresponse[self.qname][command][regkey] = {"value": value}
                queue_commandrespadd(
                    self.commandresponse,
                    self.qname,
                    command,
                    regkey,
                    {"value": value},
                )

            response = None

        else:
            if self.verbose:
                print("\t - Grottserver - Unknown record received:")
            response = None

        if response is not None:
            if self.verbose:
                print(
                    "\t - Grottserver - Put response on queue: ",
                    self.qname,
                    " msg: ",
                )
                print(format_multi_line("\t\t ", response))
            self.send_queuereg[self.qname].put_nowait(response)


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
        device_server = GrowattServer(
            conf, self.send_queuereg, self.loggerreg, self.commandresponse
        )

        try:
            http_server_thread = threading.Thread(target=http_server.serve_forever)
            http_server_thread.daemon = True
            http_server_thread.start()

            device_server_thread = threading.Thread(target=device_server.serve_forever)
            device_server_thread.daemon = True
            device_server_thread.start()

            http_server_thread.join()
            device_server_thread.join()
        except KeyboardInterrupt:
            print("\t - Grottserver - KeyboardInterrupt received, shutting down")
            http_server.shutdown()
            device_server.shutdown()
