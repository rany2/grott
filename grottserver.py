"""
grottserver.py emulates the server.growatt.com website and was initial developed
for debugging and testing grott.
Updated: 2023-09-19
"""

import codecs
import hashlib
import json
import os
import queue
import socket
import threading
from collections import defaultdict
from datetime import datetime
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from socketserver import StreamRequestHandler, ThreadingTCPServer
from time import sleep
from typing import Any, Dict, Optional
from urllib.parse import parse_qs, urlparse

import libscrc
import pytz

from grottdata import procdata
from grotthelpers import (Forward, decrypt, format_multi_line, pr, queue_clear,
                          queue_clear_and_poison)

# Version:
verrel = "0.0.14e"

# Constant responses:
INVALID_DATALOGGER_ID = (
    HTTPStatus.BAD_REQUEST,
    "application/json",
    json.dumps({"error": "invalid datalogger id specified"}),
)
INVALID_INVERTER_ID = (
    HTTPStatus.BAD_REQUEST,
    "application/json",
    json.dumps({"error": "invalid inverter id specified"}),
)
INVALID_FORMAT = (
    HTTPStatus.BAD_REQUEST,
    "application/json",
    json.dumps({"error": "invalid format specified"}),
)
INVALID_REG = (
    HTTPStatus.BAD_REQUEST,
    "application/json",
    json.dumps({"error": "invalid register specified"}),
)
INVALID_VALUE = (
    HTTPStatus.BAD_REQUEST,
    "application/json",
    json.dumps({"error": "invalid value specified"}),
)
INVALID_START_REGISTER = (
    HTTPStatus.BAD_REQUEST,
    "application/json",
    json.dumps({"error": "invalid start register value specified"}),
)
INVALID_END_REGISTER = (
    HTTPStatus.BAD_REQUEST,
    "application/json",
    json.dumps({"error": "invalid end register value specified"}),
)
INVALID_COMMAND = (
    HTTPStatus.BAD_REQUEST,
    "application/json",
    json.dumps({"error": "invalid command entered"}),
)
NO_COMMAND = (
    HTTPStatus.BAD_REQUEST,
    "application/json",
    json.dumps({"error": "no command entered"}),
)
NO_VALUE = (
    HTTPStatus.BAD_REQUEST,
    "application/json",
    json.dumps({"error": "no value specified"}),
)
NO_RESPONSE = (
    HTTPStatus.TOO_MANY_REQUESTS,
    "application/json",
    json.dumps({"error": "no or invalid response received"}),
)
MULTIREGISTER_DATALOGGER_NOT_ALLOWED = (
    HTTPStatus.BAD_REQUEST,
    "application/json",
    json.dumps({"error": "multiregister command not allowed for datalogger"}),
)
DATETIME_NOT_ALLOWED_FOR_INVERTER = (
    HTTPStatus.BAD_REQUEST,
    "application/json",
    json.dumps({"error": "datetime command not allowed for inverter"}),
)
OK_RESPONSE = (
    HTTPStatus.OK,
    "application/json",
    json.dumps({"status": "ok"}),
)


def htmlsendresp(self: BaseHTTPRequestHandler, responserc, responseheader, responsetxt):
    """send http response"""
    self.send_response(responserc)
    self.send_header("Content-type", responseheader)
    self.end_headers()
    if not isinstance(responsetxt, bytes):
        responsetxt = str(responsetxt).encode("utf-8")
    self.wfile.write(responsetxt)


def getcurrenttime(conf):
    try:
        local = pytz.timezone(conf.tmzone)
    except pytz.UnknownTimeZoneError:
        if conf.verbose:
            if conf.tmzone == "local":
                pr("- Timezone local specified default timezone used")
            else:
                pr(
                    "- Grott unknown timezone:",
                    conf.tmzone,
                    "- default timezone used",
                )
        conf.tmzone = "local"

    if conf.tmzone == "local":
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    return datetime.now(local).strftime("%Y-%m-%d %H:%M:%S")


def createtimecommand(conf, protocol: str, loggerid: str):
    bodybytes = loggerid.encode("ascii")
    body = bodybytes.hex()
    if protocol == "06":
        body += "0000000000000000000000000000000000000000"
    register = 31
    body += f"{int(register):04x}"
    currenttime = getcurrenttime(conf)
    timex = currenttime.encode("ascii").hex()
    timel = f"{int(len(timex) / 2):04x}"
    body += timel + timex
    # calculate length of payload = body/2 (str => bytes) + 2 bytes invertid + command.
    bodylen = int(len(body) / 2 + 2)

    # create header
    header = "0001" + "00" + protocol + f"{bodylen:04x}" + "0118"
    # pr(header)
    body = header + body
    body = bytes.fromhex(body)
    if conf.verbose:
        pr("- GrottServer - Time plain body:\n" + format_multi_line("\t", body))

    if protocol != "02":
        # encrypt message
        body = decrypt(body)
        crc16 = libscrc.modbus(bytes.fromhex(body))
        body = bytes.fromhex(body) + crc16.to_bytes(2, "big")

    if conf.verbose:
        pr("- GrottServer - Time command created:\n" + format_multi_line("\t", body))

    return body


_QUEUE_COMMAND_RESP_CREATE_MUTEX = threading.Lock()


def queue_commandrespcreate(commandresponse, qname, sendcommand, regkey):
    with _QUEUE_COMMAND_RESP_CREATE_MUTEX:
        if sendcommand not in commandresponse[qname]:
            commandresponse[qname][sendcommand] = {}

        if regkey not in commandresponse[qname][sendcommand]:
            commandresponse[qname][sendcommand][regkey] = queue.Queue()


def queue_commandrespclear(commandresponse, qname, sendcommand, regkey):
    queue_commandrespcreate(commandresponse, qname, sendcommand, regkey)
    queue_clear(commandresponse[qname][sendcommand][regkey])


def queue_commandrespadd(commandresponse, qname, sendcommand, regkey, value):
    queue_commandrespcreate(commandresponse, qname, sendcommand, regkey)
    commandresponse[qname][sendcommand][regkey].put_nowait(value)


def queue_commandrespget(commandresponse, qname, sendcommand, regkey, timeout=0):
    queue_commandrespcreate(commandresponse, qname, sendcommand, regkey)
    return commandresponse[qname][sendcommand][regkey].get(timeout=timeout)


class Server:
    def __init__(self, conf):
        self.conf: Any = conf
        self.send_queuereg: Dict[str, queue.Queue] = {}
        self.loggerreg: Dict[str, Any] = {}
        self.register_mutex: Dict[str, threading.Lock] = {}
        self.shutdown_event: Dict[str, threading.Event] = {}
        self.commandresponse = defaultdict(dict)

    def main(self, conf):
        if conf.grottip == "default":
            conf.grottip = "0.0.0.0"

        http_server = GrottHttpServer(self)
        device_server = GrottServer(self)

        try:
            http_server_thread = threading.Thread(target=http_server.serve_forever)
            http_server_thread.start()

            device_server_thread = threading.Thread(target=device_server.serve_forever)
            device_server_thread.start()

            http_server_thread.join()
            device_server_thread.join()
        except KeyboardInterrupt:
            pr("- GrottServer - KeyboardInterrupt received, shutting down")
            http_server.shutdown()
            device_server.shutdown()


class GrottHttpRequestHandler(BaseHTTPRequestHandler):
    def __init__(self, server: Server, *args, **kwargs):
        self.send_queuereg = server.send_queuereg
        self.conf = server.conf
        self.verbose = server.conf.verbose
        self.loggerreg = server.loggerreg
        self.commandresponse = server.commandresponse
        self.register_mutex = server.register_mutex

        # set variables for StreamRequestHandler's setup()
        self.timeout = server.conf.httptimeout

        # save index.html in memory
        with open(
            os.path.join(os.path.dirname(__file__), "static", "index.html"), "rb"
        ) as f:
            self.indexhtml = f.read()

        super().__init__(*args, **kwargs)

    def log_message(self, format, *args):
        pr("- GrottHttpServer - %s - %s" % (self.address_string(), format % args))

    def send_header(self, keyword, value, *args, **kwargs):
        if keyword.lower() == "server":
            return
        super().send_header(keyword, value, *args, **kwargs)

    def authorized(self):
        token = self.conf.httptoken
        if token is None:
            return True

        authorization = self.headers.get("authorization")
        if authorization is None:
            return False

        if not authorization.startswith("Bearer "):
            return False

        token_hash = hashlib.sha256(
            authorization[len("Bearer ") :].encode("utf-8")
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
            htmlsendresp(self, *INVALID_INVERTER_ID)
            return None, None

        try:
            # is format keyword specified? (dec, text, hex)
            formatval = urlquery["format"][0]
            if formatval not in ("dec", "hex", "text"):
                htmlsendresp(self, *INVALID_FORMAT)
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
            htmlsendresp(self, *INVALID_DATALOGGER_ID)
            return

        if dataloggerid is None:
            htmlsendresp(self, *INVALID_DATALOGGER_ID)
            return

        return dataloggerid

    def get_qname(self, dataloggerid):
        return f"{self.loggerreg[dataloggerid]['ip']}_{self.loggerreg[dataloggerid]['port']}"

    def do_GET(self):
        if self.verbose:
            pr("- GrottHttpServer - Get received ")

        # parse url
        url = urlparse(self.path)
        urlquery = parse_qs(url.query)

        # only allow files from current directory
        if not (len(self.path) > 0 and self.path[0] == "/"):
            return
        self.path = self.path[1 : len(self.path)]

        # strip query string
        self.path = self.path.split("?")[0]

        if not self.path:  # no path specified
            responsetxt = self.indexhtml
            responserc = HTTPStatus.OK
            responseheader = "text/html"
            htmlsendresp(self, responserc, responseheader, responsetxt)
            return

        if not self.authorized():
            self.send_error(HTTPStatus.UNAUTHORIZED)
            return

        if self.path in ("datalogger", "inverter"):
            if self.verbose:
                pr(f"- GrottHttpServer - {self.path} GET received: {urlquery}")

            if self.path == "datalogger":
                sendcommand = "19"
            else:
                sendcommand = "05"

            if not urlquery:
                # no command entered return loggerreg info:
                responsetxt = json.dumps(self.loggerreg)
                responserc = HTTPStatus.OK
                responseheader = "application/json"
                htmlsendresp(self, responserc, responseheader, responsetxt)
                return

            try:
                # is valid command specified?
                command = urlquery["command"][0]
                if command in ("register",):
                    if self.verbose:
                        pr("- GrottHttpServer - get command:", command)
                else:
                    # no valid command entered
                    htmlsendresp(self, *INVALID_COMMAND)
                    return
            except (KeyError, IndexError):
                # no command entered
                htmlsendresp(self, *NO_COMMAND)
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
                    if 0 <= int(urlquery["register"][0]) <= 65535:
                        register = urlquery["register"][0]
                    else:
                        raise ValueError("invalid register value")
                except (KeyError, IndexError, ValueError):
                    htmlsendresp(self, *INVALID_REG)
                    return
            else:
                htmlsendresp(self, *INVALID_COMMAND)
                return

            bodybytes = dataloggerid.encode("ascii")
            body = bodybytes.hex()

            if self.loggerreg[dataloggerid]["protocol"] == "06":
                body += "0000000000000000000000000000000000000000"
            body += f"{int(register):04x}"
            # assumption now only 1 reg query; other put below end register
            body += f"{int(register):04x}"
            # calculate length of payload = body/2 (str => bytes) + 2 bytes invertid + command.
            bodylen = int(len(body) / 2 + 2)

            # device id for datalogger is by default "01" for inverter deviceid is inverterid!
            deviceid = "01"
            # test if it is inverter command and set
            if sendcommand == "05":
                deviceid = self.loggerreg[dataloggerid][urlquery["inverter"][0]][
                    "inverterno"
                ]
                if self.verbose:
                    pr(f"- GrottHttpServer - selected deviceid: {deviceid}")

            header = (
                f"{self.conf.sendseq:04x}"
                + "00"
                + self.loggerreg[dataloggerid]["protocol"]
                + f"{bodylen:04x}"
                + deviceid
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
                pr(
                    "- GrottHttpServer - command created:\n"
                    + format_multi_line("\t", body)
                )

            # responseno = f"{self.conf.sendseq:04x}"
            regkey = f"{int(register):04x}"

            register_mutex = self.register_mutex.get(qname, None)
            if register_mutex is None:
                htmlsendresp(self, *INVALID_DATALOGGER_ID)
                return

            with register_mutex:
                # clear all possible responses for this command to ensure no old responses are returned.
                queue_commandrespclear(self.commandresponse, qname, sendcommand, regkey)
                # queue command
                try:
                    self.send_queuereg[qname].put(body)
                except KeyError:
                    # If the queue is not found, it means that the datalogger has disconnected.
                    #
                    # We need to remove the datalogger from commandresponse and register_mutex.
                    self.commandresponse.pop(qname, None)
                    self.register_mutex.pop(qname, None)

                    # Send an error response
                    htmlsendresp(self, *INVALID_DATALOGGER_ID)
                    return

                try:
                    comresp = queue_commandrespget(
                        self.commandresponse,
                        qname,
                        sendcommand,
                        regkey,
                        timeout=self.conf.registerreadtimeout,
                    )
                    if comresp["value"] is None:
                        htmlsendresp(self, *NO_RESPONSE)
                        return
                    elif sendcommand == "05":
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
                    responsetxt = json.dumps(comresp)
                    responserc = HTTPStatus.OK
                    responseheader = "application/json"
                    htmlsendresp(self, responserc, responseheader, responsetxt)
                    return
                except (queue.Empty, KeyError, IndexError, ValueError):
                    htmlsendresp(self, *NO_RESPONSE)
                    return

        else:
            self.send_error(HTTPStatus.NOT_FOUND)

    def do_PUT(self):
        if not self.authorized():
            self.send_error(HTTPStatus.UNAUTHORIZED)
            return

        url = urlparse(self.path)
        urlquery = parse_qs(url.query)

        # only allow files from current directory
        if not (len(self.path) > 0 and self.path[0] == "/"):
            return
        self.path = self.path[1 : len(self.path)]

        # strip query string
        self.path = self.path.split("?")[0]

        if self.path in ("datalogger", "inverter"):
            if self.verbose:
                pr(f"- GrottHttpServer - {self.path} PUT received: {urlquery}")

            if self.path == "datalogger":
                sendcommand = "18"
            else:
                # Must be an inverter. Use 06 for now. May change to 10 later
                sendcommand = "06"

            if not urlquery:
                # no command entered
                htmlsendresp(self, *NO_COMMAND)
                return

            try:
                # is valid command specified?
                command = urlquery["command"][0]
                if command in ("register", "multiregister", "datetime"):
                    if self.verbose:
                        pr(f"- GrottHttpServer - PUT command: {command}")
                else:
                    # no valid command entered
                    htmlsendresp(self, *INVALID_COMMAND)
                    return
            except (KeyError, IndexError):
                # no command entered
                htmlsendresp(self, *NO_COMMAND)
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
                    if 0 <= int(urlquery["register"][0]) <= 65535:
                        register = urlquery["register"][0]
                    else:
                        raise ValueError("invalid register value")
                except (KeyError, IndexError, ValueError):
                    htmlsendresp(self, *INVALID_REG)
                    return

                try:
                    value = urlquery["value"][0]
                except (KeyError, IndexError):
                    value = None

                if value is None:
                    htmlsendresp(self, *NO_VALUE)
                    return

            elif command == "multiregister":
                if sendcommand == "18":
                    htmlsendresp(self, *MULTIREGISTER_DATALOGGER_NOT_ALLOWED)
                    return

                # Switch to multiregister command
                sendcommand = "10"

                # Check for valid start register
                try:
                    if 0 <= int(urlquery["startregister"][0]) <= 65535:
                        startregister = urlquery["startregister"][0]
                    else:
                        raise ValueError("invalid register value")
                except (KeyError, IndexError, ValueError):
                    htmlsendresp(self, *INVALID_START_REGISTER)
                    return

                # Check for valid end register
                try:
                    if 0 <= int(urlquery["endregister"][0]) <= 65535:
                        endregister = urlquery["endregister"][0]
                    else:
                        raise ValueError("invalid register value")
                except (KeyError, IndexError, ValueError):
                    htmlsendresp(self, *INVALID_END_REGISTER)
                    return

                # TODO: Check the value is the right length for the given start/end registers
                try:
                    value = urlquery["value"][0]
                except (KeyError, IndexError):
                    value = None

                if value is None:
                    htmlsendresp(self, *NO_VALUE)
                    return

            elif command == "datetime":
                # process set datetime, only allowed for datalogger!!!
                if sendcommand == "06":
                    htmlsendresp(self, *DATETIME_NOT_ALLOWED_FOR_INVERTER)
                    return
                # prepare datetime
                register = 31
                value = getcurrenttime(self.conf)

            else:
                htmlsendresp(self, *INVALID_COMMAND)
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
                    htmlsendresp(self, *INVALID_VALUE)
                    return

            # start creating command
            bodybytes = dataloggerid.encode("ascii")
            body = bodybytes.hex()

            if self.loggerreg[dataloggerid]["protocol"] == "06":
                body += "0000000000000000000000000000000000000000"

            if sendcommand == "06":
                value = f"{value:04x}"
                valuelen = ""
            elif sendcommand == "10":
                # Value is already in hex format
                pass
            else:
                value = value.encode("ascii").hex()
                valuelen = int(len(value) / 2)
                valuelen = f"{valuelen:04x}"

            if sendcommand == "10":
                body = (
                    body
                    + f"{int(startregister):04x}"
                    + f"{int(endregister):04x}"
                    + value
                )
            else:
                body += f"{int(register):04x}" + valuelen + value
            bodylen = int(len(body) / 2 + 2)

            # device id for datalogger is by default "01" for inverter deviceid is inverterid!
            deviceid = "01"
            # test if it is inverter command and set deviceid
            if sendcommand in ("06", "10"):
                deviceid = self.loggerreg[dataloggerid][urlquery["inverter"][0]][
                    "inverterno"
                ]
                if self.verbose:
                    pr(f"- GrottHttpServer - selected deviceid: {deviceid}")

            # create header
            header = (
                f"{self.conf.sendseq:04x}"
                + "00"
                + self.loggerreg[dataloggerid]["protocol"]
                + f"{bodylen:04x}"
                + deviceid
                + sendcommand
            )
            body = header + body
            body = bytes.fromhex(body)

            if self.verbose:
                pr(
                    "- GrottHttpServer - unencrypted PUT command:\n"
                    + format_multi_line("\t", body)
                )

            if self.loggerreg[dataloggerid]["protocol"] != "02":
                # encrypt message
                body = decrypt(body)
                crc16 = libscrc.modbus(bytes.fromhex(body))
                body = bytes.fromhex(body) + crc16.to_bytes(2, "big")

            if sendcommand == "10":
                regkey = f"{int(startregister):04x}" + f"{int(endregister):04x}"
            else:
                regkey = f"{int(register):04x}"
            qname = self.get_qname(dataloggerid)

            register_mutex = self.register_mutex.get(qname, None)
            if register_mutex is None:
                htmlsendresp(self, *INVALID_DATALOGGER_ID)
                return

            with register_mutex:
                # clear all possible responses for this command to ensure no old responses are returned.
                queue_commandrespclear(self.commandresponse, qname, sendcommand, regkey)
                # queue command
                try:
                    self.send_queuereg[qname].put(body)
                except KeyError:
                    # If the queue is not found, it means that the datalogger has disconnected.
                    #
                    # We need to remove the datalogger from commandresponse and register_mutex.
                    self.commandresponse.pop(qname, None)
                    self.register_mutex.pop(qname, None)

                    # Send an error response
                    htmlsendresp(self, *INVALID_DATALOGGER_ID)
                    return

                responseno = f"{self.conf.sendseq:04x}"

                # wait for response
                if self.verbose:
                    pr("- GrottHttpServer - wait for PUT response")
                try:
                    # read response: be aware a 18 command give 19 response,
                    # 06 send command gives 06 response in different format!
                    queue_commandrespget(
                        self.commandresponse,
                        qname,
                        sendcommand,
                        regkey,
                        timeout=self.conf.registerwritetimeout,
                    )
                    if self.verbose:
                        pr(
                            "- GrottHttpServer - Commandresponse:",
                            responseno,
                            register,
                            self.commandresponse[qname][sendcommand][regkey],
                        )
                    htmlsendresp(self, *OK_RESPONSE)
                    return
                except queue.Empty:
                    htmlsendresp(self, *NO_RESPONSE)
                    return
        else:
            self.send_error(HTTPStatus.NOT_FOUND)


class GrottHttpServer(ThreadingHTTPServer):
    """This wrapper will create an HTTP server where the handler has access to the send_queue"""

    def __init__(self, server: Server):
        def handler_factory(*args, **kwargs):
            """
            Using a function to create and return the handler,
            so we can provide our own argument (send_queue)
            """
            return GrottHttpRequestHandler(server, *args, **kwargs)

        self.allow_reuse_address = True
        httphost, httpport = server.conf.httphost, server.conf.httpport
        super().__init__((httphost, httpport), handler_factory)
        pr(f"- GrottHttpServer - Ready to listen at: {httphost}:{httpport}")


class GrottServer(ThreadingTCPServer):
    """This wrapper will create a Growatt server where the handler has access to the send_queue"""

    def __init__(self, server: Server):
        def handler_factory(*args, **kwargs):
            """
            Using a function to create and return the handler,
            so we can provide our own argument (send_queue)
            """
            return GrottServerHandler(server, *args, **kwargs)

        self.allow_reuse_address = True
        grottip, grottport = server.conf.grottip, server.conf.grottport
        super().__init__((grottip, grottport), handler_factory)
        pr(f"- GrottServer - Ready to listen at: {grottip}:{grottport}")


_LOGGERREG_CREATE_MUTEX = threading.Lock()


class GrottServerHandler(StreamRequestHandler):
    def __init__(self, server: Server, *args, **kwargs):
        self.commandresponse = server.commandresponse
        self.conf = server.conf
        self.loggerreg = server.loggerreg
        self.send_queuereg = server.send_queuereg
        self.shutdown_event = server.shutdown_event
        self.forward_input = ()
        self.forward_queue: Dict[str, queue.Queue] = {}
        self.verbose = server.conf.verbose
        self.register_mutex = server.register_mutex

        # set variables for StreamRequestHandler's setup()
        self.timeout = server.conf.timeout
        self.disable_nagle_algorithm = True

        super().__init__(*args, **kwargs)

    def handle(self):
        pr(
            f"- GrottServer - Client connected: {self.client_address[0]}:{self.client_address[1]}"
        )

        # setup forwarding to Growatt server if configured
        if self.conf.serverforward:
            self.forward_input = (
                self.conf.growattip,
                self.conf.growattport,
            )

            if self.verbose:
                pr(
                    "- GrottServer - Configured forward for:",
                    f"{self.conf.growattip}:{self.conf.growattport}",
                )

        # create qname from client address tuple
        self.qname = f"{self.client_address[0]}_{self.client_address[1]}"

        # create send queue
        self.send_queuereg[self.qname] = queue.Queue()
        if self.verbose:
            pr(f"- GrottServer - Send queue created for: {self.qname}")

        # create command response queue
        self.commandresponse[self.qname] = defaultdict(dict)
        if self.verbose:
            pr(f"- GrottServer - Command response created for: {self.qname}")

        # create register mutex
        self.register_mutex[self.qname] = threading.Lock()
        if self.verbose:
            pr(f"- GrottServer - Register mutex created for: {self.qname}")

        # on any value, shutdown everything
        self.shutdown_event[self.qname] = threading.Event()

        # create and start read thread
        read_thread = threading.Thread(target=self.read_data)
        read_thread.start()

        # create and start write thread
        write_thread = threading.Thread(target=self.write_data)
        write_thread.start()

        # if forward is enabled, start forward thread
        if self.forward_input:
            self.forward_queue[self.qname] = queue.Queue()

            forward_thread = threading.Thread(target=self.forward_data)
            forward_thread.start()

        # wait for self.shutdown_event to be set
        self.shutdown_event[self.qname].wait()

    def finish(self) -> None:
        self.close_connection()
        return super().finish()

    def read_data(self):
        try:
            while not self.rfile.closed:
                data = self.rfile.read(8)
                if not data:
                    break
                # header contains length excl the header itself
                len_payloadleft = int.from_bytes(data[4:6], "big")
                more_data = self.rfile.read(len_payloadleft)
                if not more_data:
                    break
                data += more_data
                self.process_data(data)
        except Exception as exc:
            if self.verbose:
                pr(f"- GrottServer - Read error: {exc}")
        finally:
            if tev := self.shutdown_event.pop(self.qname, None):
                tev.set()

    def write_data(self):
        try:
            while True:
                data = self.send_queuereg[self.qname].get()
                if not data:
                    break
                self.wfile.write(data)
                self.wfile.flush()
                sleep(self.conf.senddelay)
        except Exception:
            pass
        finally:
            if tev := self.shutdown_event.pop(self.qname, None):
                tev.set()

    def forward_data(self):
        def op(
            fsock, host, port, data, attempts=self.conf.forwardretry
        ) -> Optional[socket.socket]:
            try:
                if not isinstance(fsock, socket.socket):
                    fsock = Forward().start(host, port)
                    if self.verbose:
                        pr(f"- GrottServer - Forward started: {host}:{port}")

                try:
                    # Disable timeout to make this operation non-blocking
                    fsock.settimeout(0)

                    # Empty receive buffer to avoid TCP Window Full
                    # but only if there is data to receive (i.e.
                    # do not block on recv if there is no data)
                    fsock.recv(
                        fsock.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF),
                        socket.MSG_DONTWAIT,
                    )
                except BlockingIOError:
                    pass

                # Bring back timeout to detect when send buffer is full
                # and avoid blocking on send (which would block the
                # forward thread)
                fsock.settimeout(self.conf.forwardtimeout)

                # send data to growatt
                fsock.sendall(data)

                if self.verbose:
                    pr(f"- GrottServer - Forward data sent to {host}:{port}")

                return fsock
            except OSError as exc:
                # if forward fails, close connection and require reconnect
                if isinstance(fsock, socket.socket):
                    try:
                        fsock.shutdown(socket.SHUT_WR)
                    except OSError:
                        pass

                if attempts < 0:
                    pr(f"- GrottServer - Forward failed: {host}:{port} ({exc})")
                    return None

                pr(
                    f"- GrottServer - Forward failed: {host}:{port} ({exc}), retrying..."
                )
                return op(attempts - 1)

        q = self.forward_queue[self.qname]
        if not self.forward_input:
            return
        host, port, fsock = *self.forward_input, None
        while data := q.get():
            if self.verbose:
                pr(f"- GrottServer - Sending forward data to {host}:{port}")

            fsock = op(fsock, host, port, data)

        if isinstance(fsock, socket.socket):
            try:
                fsock.shutdown(socket.SHUT_WR)
            except OSError:
                pass

    def close_connection(self):
        pr(
            f"- GrottServer - Close connection: {self.client_address[0]}:{self.client_address[1]}"
        )

        client_address, client_port = self.client_address

        if q := self.send_queuereg.pop(self.qname, None):
            queue_clear_and_poison(q)

        self.commandresponse.pop(self.qname, None)
        self.register_mutex.pop(self.qname, None)

        if q := self.forward_queue.pop(self.qname, None):
            queue_clear_and_poison(q)

        with _LOGGERREG_CREATE_MUTEX:
            for key in self.loggerreg.keys():
                if (
                    self.loggerreg[key]["ip"] == client_address
                    and self.loggerreg[key]["port"] == client_port
                ):
                    del self.loggerreg[key]
                    pr(f"- GrottServer - config info deleted for {key}")
                    break

    def process_data(self, data):
        # V0.0.14: default response on record to none (ignore record)
        response = None

        # Display data
        if self.verbose:
            pr(
                f"- GrottServer - Data received from: {self.qname}\n"
                + "- GrottServer - Original Data:\n"
                + format_multi_line("\t", data)
            )

        # Collect data for MQTT, PVOutput, InfluxDB, etc..
        if len(data) > self.conf.minrecl:
            procdata(self.conf, data)
        else:
            if self.conf.verbose:
                pr("- Data less then minimum record length, data not processed")

        # Create header
        header = "".join(f"{n:02x}" for n in data[0:8])
        # sequencenumber = header[0:4]
        protocol = header[6:8]
        rectype = header[14:16]
        if protocol in ("05", "06"):
            result_string = decrypt(data)
        else:
            result_string = "".join(f"{n:02x}" for n in data)
        if self.verbose:
            pr(
                "- GrottServer - Plain record:\n"
                + format_multi_line("\t", result_string)
            )
        loggerid = result_string[16:36]
        loggerid = codecs.decode(loggerid, "hex").decode("ascii")

        # Prepare response
        if rectype in ("16",):
            # if ping send data as reply
            response = data
            if self.verbose:
                pr(
                    "- GrottServer - 16 - Ping response:\n"
                    + format_multi_line("\t", response)
                )

            with _LOGGERREG_CREATE_MUTEX:
                if not loggerid in self.loggerreg:
                    self.loggerreg[loggerid] = {}

                self.loggerreg[loggerid].update(
                    {
                        "ip": self.client_address[0],
                        "port": self.client_address[1],
                        "protocol": header[6:8],
                    }
                )

            # forward data for growatt
            if fwd_queue := self.forward_queue.get(self.qname, None):
                fwd_queue.put_nowait(data)

        # v0.0.14: remove "29" (no response will be sent for this record!)
        elif rectype in ("03", "04", "50", "1b", "20"):
            # if datarecord send ack.
            if self.verbose:
                pr(f"- GrottServer - {header[12:16]} data record received")

            # forward data for growatt
            if fwd_queue := self.forward_queue.get(self.qname, None):
                fwd_queue.put_nowait(data)

            # create ack response
            if header[6:8] == "02":
                # protocol 02, unencrypted ack
                response = bytes.fromhex(header[0:8] + "0003" + header[12:16] + "00")
            else:
                # protocol 05/06, encrypted ack
                headerackx = bytes.fromhex(header[0:8] + "0003" + header[12:16] + "47")
                # Create CRC 16 Modbus
                crc16 = libscrc.modbus(headerackx)
                # create response
                response = headerackx + crc16.to_bytes(2, "big")

            if self.verbose:
                pr("- GrottServer - Response:\n" + format_multi_line("\t", response))

            if rectype in ("03",):
                # init record register logger/inverter id (including sessionid?)
                # decrypt body.
                if header[6:8] in ("05", "06"):
                    # pr("header1 : ", header[6:8])
                    result_string = decrypt(data)
                else:
                    result_string = data.hex()

                loggerid = result_string[16:36]
                loggerid = codecs.decode(loggerid, "hex").decode("ascii")
                if header[6:8] in ("02", "05"):
                    inverterid = result_string[36:56]
                else:
                    inverterid = result_string[76:96]
                inverterid = codecs.decode(inverterid, "hex").decode("ascii")

                # check if loggerid is already in loggerreg
                if loggerreg := self.loggerreg.get(loggerid, None):
                    prev_qname = f"{loggerreg.get('ip')}_{loggerreg.get('port')}"
                    if prev_qname != self.qname:
                        if tev := self.shutdown_event.pop(prev_qname, None):
                            tev.set()
                            pr(
                                f"- GrottServer - Shutdown previous connection {prev_qname} for {loggerid}"
                            )

                # we need to confirm before we update the self.loggerreg
                # so we must wait to make sure response is sent before any
                # possible command from HTTP API
                self.send_queuereg[self.qname].put(response)

                with _LOGGERREG_CREATE_MUTEX:
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

                # Create time command and put on queue
                response = createtimecommand(
                    self.conf,
                    protocol,
                    loggerid,
                )
                if self.verbose:
                    pr("- GrottServer 03 announce data record processed")

        elif rectype in ("19", "05", "06", "18"):
            if self.verbose:
                pr(
                    "- GrottServer - "
                    + header[12:16]
                    + " command response record received, no response needed"
                )

            offset = 0
            if protocol in ("06",):
                offset = 40

            value = None
            result = None

            register = int(result_string[36 + offset : 40 + offset], 16)
            if rectype == "05":
                # v0.0.14: test if empty response is sent (this will give CRC code as values)
                # pr("length resultstring:", len(result_string))
                # pr("result starts on:", 48+offset)
                if len(result_string) == 48 + offset:
                    if self.verbose:
                        pr(
                            "\t - Grottserver - empty register get response recieved, response ignored"
                        )
                else:
                    value = result_string[44 + offset : 48 + offset]
            elif rectype == "06":
                result = result_string[40 + offset : 42 + offset]
                # pr("06 response result :", result)
                value = result_string[42 + offset : 46 + offset]
            elif rectype == "18":
                result = result_string[40 + offset : 42 + offset]
            else:
                # "19" response take length into account
                valuelen = int(result_string[40 + offset : 44 + offset], 16)
                value = codecs.decode(
                    result_string[44 + offset : 44 + offset + valuelen * 2], "hex"
                ).decode("ISO-8859-1")

            regkey = f"{register:04x}"
            if rectype == "06":
                # command 06 response has ack (result) + value. We will create a
                # 06 response and a 05 response (for reg administration)
                data_to_put = {"value": value, "result": result}
            elif rectype == "18":
                data_to_put = {"result": result}
            else:
                # rectype 05 or 19
                data_to_put = {"value": value}

            # push rectype response for HTTP server to be aware of
            queue_commandrespadd(
                self.commandresponse,
                self.qname,
                rectype,
                regkey,
                data_to_put,
            )

        elif rectype in ("10",):
            if self.verbose:
                pr(
                    f"- GrottServer - {header[12:16]} record received, no response needed"
                )

            startregister = int(result_string[76:80], 16)
            endregister = int(result_string[80:84], 16)
            value = result_string[84:86]

            regkey = f"{startregister:04x}" + f"{endregister:04x}"
            queue_commandrespadd(
                self.commandresponse,
                self.qname,
                rectype,
                regkey,
                {"value": value},
            )

        elif rectype in ("29",):
            if self.verbose:
                pr(
                    f"- GrottServer - {header[12:16]} record received, no response needed"
                )
        else:
            if self.verbose:
                pr(
                    "- GrottServer - Unknown record received:"
                    + header[12:16]
                    + "\n"
                    + format_multi_line("\t", data)
                )

        if response is not None:
            if self.verbose:
                pr(
                    "- GrottServer - Put response on queue: ",
                    self.qname,
                    " msg:\n" + format_multi_line("\t", response),
                )
            self.send_queuereg[self.qname].put_nowait(response)
