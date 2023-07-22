"""
grottserver.py emulates the server.growatt.com website and was initial developed
for debugging and testing grott.
Updated: 2023-01-20
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
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from socketserver import StreamRequestHandler, ThreadingTCPServer
from urllib.parse import parse_qs, urlparse

import libscrc
import pytz

from grottdata import decrypt, format_multi_line, pr, procdata
from grottproxy import Forward, is_record_valid

# Version:
verrel = "0.0.12"


def htmlsendresp(self, responserc, responseheader, responsetxt):
    """send http response"""
    self.send_response(responserc)
    self.send_header("Content-type", responseheader)
    self.end_headers()
    self.wfile.write(responsetxt)
    if self.verbose:
        pr(
            "- GrottHttpServer - http response send:",
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


def createtimecommand(conf, protocol, loggerid):
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
    # print(header)
    body = header + body
    body = bytes.fromhex(body)
    if conf.verbose:
        pr("- Grottserver - Time plain body:\n" + format_multi_line("\t", body))

    if protocol != "02":
        # encrypt message
        body = decrypt(body)
        crc16 = libscrc.modbus(bytes.fromhex(body))
        body = bytes.fromhex(body) + crc16.to_bytes(2, "big")

    if conf.verbose:
        pr("- Grottserver - Time command created:\n" + format_multi_line("\t", body))

    return body


def queue_clear(q: queue.Queue):
    with q.mutex:
        q.queue.clear()
        q.all_tasks_done.notify_all()
        q.unfinished_tasks = 0


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


class GrottHttpRequestHandler(BaseHTTPRequestHandler):
    def __init__(
        self, send_queuereg, conf, loggerreg, commandresponse, register_mutex, *args
    ):
        self.send_queuereg = send_queuereg
        self.conf = conf
        self.verbose = conf.verbose
        self.loggerreg = loggerreg
        self.commandresponse = commandresponse
        self.register_mutex = register_mutex

        # set variables for StreamRequestHandler's setup()
        self.timeout = conf.httptimeout

        # save index.html in memory
        with open(
            os.path.join(os.path.dirname(__file__), "static", "index.html"), "rb"
        ) as f:
            self.indexhtml = f.read()

        super().__init__(*args)

    def log_message(self, format, *args):
        pr("- GrottHttpServer - %s - %s" % (self.address_string(), format % args))

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
        if self.verbose:
            pr("- GrottHttpServer - Get received ")

        # parse url
        url = urlparse(self.path)
        urlquery = parse_qs(url.query)

        # only allow files from current directory
        if self.path[0] == "/":
            self.path = self.path[1 : len(self.path)]

        # strip query string
        self.path = self.path.split("?")[0]

        if not self.path:  # no path specified
            responsetxt = self.indexhtml
            responserc = 200
            responseheader = "text/html"
            htmlsendresp(self, responserc, responseheader, responsetxt)
            return

        if not self.authorized():
            self.send_error(401, "Unauthorized")
            return

        if self.path in ("datalogger", "inverter"):
            if self.path == "datalogger":
                if self.verbose:
                    pr(
                        "- GrottHttpServer - datalogger get received: ",
                        urlquery,
                    )
                sendcommand = "19"
            else:
                if self.verbose:
                    pr(
                        "- GrottHttpServer - inverter get received: ",
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
                if command in ("register",):
                    if self.verbose:
                        pr("- Grott - get command:", command)
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
                    if 0 <= int(urlquery["register"][0]) <= 65535:
                        register = urlquery["register"][0]
                    else:
                        raise ValueError("invalid register value")
                except (KeyError, IndexError, ValueError):
                    responsetxt = b"invalid reg value specified\r\n"
                    responserc = 400
                    responseheader = "text/plain"
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
                responsetxt = b"datalogger not found\r\n"
                responserc = 400
                responseheader = "text/plain"
                htmlsendresp(self, responserc, responseheader, responsetxt)
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
                    responsetxt = b"datalogger not found\r\n"
                    responserc = 400
                    responseheader = "text/plain"
                    htmlsendresp(self, responserc, responseheader, responsetxt)
                    return

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
                    pr(
                        "- GrottHttpServer - datalogger PUT received:",
                        urlquery,
                    )
                sendcommand = "18"
            else:
                if self.verbose:
                    pr("- GrottHttpServer - inverter PUT received:", urlquery)
                # Must be an inverter. Use 06 for now. May change to 10 later
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
                if command in ("register", "multiregister", "datetime"):
                    if self.verbose:
                        pr("- GrottHttpServer - PUT command:", command)
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
                    if 0 <= int(urlquery["register"][0]) <= 65535:
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

            elif command == "multiregister":
                if sendcommand == "18":
                    responsetxt = (
                        b"multiregister command not allowed for datalogger\r\n"
                    )
                    responserc = 400
                    responseheader = "text/plain"
                    htmlsendresp(self, responserc, responseheader, responsetxt)
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
                    responsetxt = b"invalid start register value specified\r\n"
                    responserc = 400
                    responseheader = "text/plain"
                    htmlsendresp(self, responserc, responseheader, responsetxt)
                    return

                # Check for valid end register
                try:
                    if 0 <= int(urlquery["endregister"][0]) <= 65535:
                        endregister = urlquery["endregister"][0]
                    else:
                        raise ValueError("invalid register value")
                except (KeyError, IndexError, ValueError):
                    responsetxt = b"invalid end register value specified\r\n"
                    responserc = 400
                    responseheader = "text/plain"
                    htmlsendresp(self, responserc, responseheader, responsetxt)
                    return

                # TODO: Check the value is the right length for the given start/end registers
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
                pr(
                    "- GrottHttpServer - unencrypted command:\n"
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
                responsetxt = b"datalogger not found\r\n"
                responserc = 400
                responseheader = "text/plain"
                htmlsendresp(self, responserc, responseheader, responsetxt)
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
                    responsetxt = b"datalogger not found\r\n"
                    responserc = 400
                    responseheader = "text/plain"
                    htmlsendresp(self, responserc, responseheader, responsetxt)
                    return

                responseno = f"{self.conf.sendseq:04x}"

                # wait for response
                if self.verbose:
                    pr("- GrottHttpServer - wait for PUT response")
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
                        pr(
                            "- Grotthttperver - Commandresponse:",
                            responseno,
                            register,
                            self.commandresponse[qname][sendcommand][regkey],
                        )
                    responsetxt = b"OK\r\n"
                    responserc = 200
                    responseheader = "text/plain"
                    if self.verbose:
                        pr(
                            "- Grott - datalogger command response:",
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


class GrottHttpServer(ThreadingHTTPServer):
    """This wrapper will create an HTTP server where the handler has access to the send_queue"""

    def __init__(self, conf, send_queuereg, loggerreg, commandresponse, register_mutex):
        def handler_factory(*args):
            """
            Using a function to create and return the handler,
            so we can provide our own argument (send_queue)
            """
            return GrottHttpRequestHandler(
                send_queuereg, conf, loggerreg, commandresponse, register_mutex, *args
            )

        self.allow_reuse_address = True
        super().__init__((conf.httphost, conf.httpport), handler_factory)
        pr(f"- GrottHttpServer - Ready to listen at: {conf.httphost}:{conf.httpport}")


class GrottServer(ThreadingTCPServer):
    """This wrapper will create a Growatt server where the handler has access to the send_queue"""

    def __init__(self, conf, send_queuereg, loggerreg, commandresponse, register_mutex):
        def handler_factory(*args):
            """
            Using a function to create and return the handler,
            so we can provide our own argument (send_queue)
            """
            return GrottServerHandler(
                send_queuereg,
                conf,
                loggerreg,
                commandresponse,
                shutdown_queue,
                register_mutex,
                *args,
            )

        shutdown_queue = {}
        self.allow_reuse_address = True
        self.daemon_threads = True
        super().__init__((conf.grottip, conf.grottport), handler_factory)
        pr(f"- Grottserver - Ready to listen at: {conf.grottip}:{conf.grottport}")


_LOGGERREG_CREATE_MUTEX = threading.Lock()

class GrottServerHandler(StreamRequestHandler):
    def __init__(
        self,
        send_queuereg,
        conf,
        loggerreg,
        commandresponse,
        shutdown_queue,
        register_mutex,
        *args,
    ):
        self.commandresponse = commandresponse
        self.conf = conf
        self.loggerreg = loggerreg
        self.send_queuereg = send_queuereg
        self.shutdown_queue = shutdown_queue
        self.forward_input = ()
        self.forward_queue = {}
        self.verbose = conf.verbose
        self.register_mutex = register_mutex

        # set variables for StreamRequestHandler's setup()
        self.timeout = conf.timeout
        self.disable_nagle_algorithm = True

        super().__init__(*args)

    def handle(self):
        pr(
            f"- GrottServer - Client connected: {self.client_address[0]}:{self.client_address[1]}"
        )

        # setup forwarding to Growatt server if configured
        if self.conf.serverforward:
            self.forward_input = (
                False,
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
        self.shutdown_queue[self.qname] = queue.Queue()

        # create and start read thread
        read_thread = threading.Thread(
            target=self.read_data,
        )
        read_thread.daemon = True
        read_thread.start()

        # create and start write thread
        write_thread = threading.Thread(
            target=self.write_data,
        )
        write_thread.daemon = True
        write_thread.start()

        # if forward is enabled, start forward thread
        if self.forward_input:
            self.forward_queue[self.qname] = queue.Queue()

            forward_thread = threading.Thread(
                target=self.forward_data,
            )
            forward_thread.daemon = True
            forward_thread.start()

        # wait for self.shutdown_queue to be filled, then shutdown
        self.shutdown_queue[self.qname].get()

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
        except Exception:
            pass
        finally:
            try:
                self.shutdown_queue[self.qname].put_nowait(True)
            except KeyError:
                pass

    def write_data(self):
        try:
            while True:
                data = self.send_queuereg[self.qname].get()
                if not data:
                    break
                self.wfile.write(data)
                self.wfile.flush()
        except Exception:
            pass
        finally:
            try:
                self.shutdown_queue[self.qname].put_nowait(True)
            except KeyError:
                pass

    def forward_data(self):
        while True:
            data = self.forward_queue[self.qname].get()
            if data is None:
                fsock, _, _ = self.forward_input
                if not isinstance(fsock, bool):
                    try:
                        fsock.shutdown(socket.SHUT_WR)
                    except OSError:
                        pass
                return
            self.forward_data_op(data)

    def forward_data_op(self, data, attempts=0):
        fsock, host, port = self.forward_input
        try:
            if self.verbose:
                pr(f"- GrottServer - Sending forward data for {host}:{port}")
            fsock.send(data)
            if self.verbose:
                pr(f"- GrottServer - Forward data sent for {host}:{port}")
        except (OSError, AttributeError):
            try:
                fsock.shutdown(socket.SHUT_WR)
            except (OSError, AttributeError):
                pass

            forward = Forward(self.conf.forwardtimeout).start(host, port)
            if self.verbose:
                pr(f"- GrottServer - Forward started: {host}:{port}")
            self.forward_input = (forward, host, port)
            if attempts < self.conf.forwardretry:
                self.forward_data_op(data, attempts + 1)
            else:
                pr(f"- GrottServer - Forward failed: {host}:{port}")

    def close_connection(self):
        pr(
            f"- GrottServer - Close connection: {self.client_address[0]}:{self.client_address[1]}"
        )

        client_address, client_port = self.client_address

        if item := self.send_queuereg.pop(self.qname, None):
            queue_clear(item)
            item.put(None)

        self.commandresponse.pop(self.qname, None)
        self.register_mutex.pop(self.qname, None)

        if item := self.shutdown_queue.pop(self.qname, None):
            queue_clear(item)

        if item := self.forward_queue.pop(self.qname, None):
            queue_clear(item)
            item.put(None)

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
        # Display data
        if self.verbose:
            pr(
                f"- GrottServer - Data received from: {self.qname}\n"
                + "- GrottServer - Original Data:\n"
                + format_multi_line("\t", data)
            )

        # validate data (Length + CRC for 05/06)
        # join gebeurt nu meerdere keren! Stroomlijnen!!!!
        vdata = "".join(f"{n:02x}" for n in data)
        if not is_record_valid(vdata):
            pr("- GrottServer - Invalid data record received, not processing")
            # Create response if needed?
            # self.send_queuereg[qname].put(response)
            return

        # Collect data for MQTT, PVOutput, InfluxDB, etc..
        if len(data) > self.conf.minrecl:
            procdata(self.conf, data)
        else:
            if self.conf.verbose:
                pr("- Data less then minimum record length, data not processed")

        # Create header
        header = "".join(f"{n:02x}" for n in data[0:8])
        sequencenumber = header[0:4]
        protocol = header[6:8]
        command = header[14:16]
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
        if header[14:16] in ("16"):
            # if ping send data as reply
            response = data
            if self.verbose:
                pr(
                    "- GrottServer - 16 - Ping response:\n"
                    + format_multi_line("\t", response)
                )

            # forward data for growatt
            if self.qname in self.forward_queue:
                self.forward_queue[self.qname].put_nowait(data)

        elif header[14:16] in ("03", "04", "50", "29", "1b", "20"):
            # if datarecord send ack.
            if self.verbose:
                pr("- GrottServer - " + header[12:16] + " data record received")

            # forward data for growatt
            if self.qname in self.forward_queue:
                self.forward_queue[self.qname].put_nowait(data)

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

            if header[14:16] == "03":
                # init record register logger/inverter id (including sessionid?)
                # decrypt body.
                if header[6:8] in ("05", "06"):
                    # print("header1 : ", header[6:8])
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

                if loggerid in self.loggerreg:
                    prev_qname = f"{self.loggerreg[loggerid]['ip']}_{self.loggerreg[loggerid]['port']}"
                    if prev_qname != self.qname:
                        self.shutdown_queue[prev_qname].put_nowait(True)
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

        elif header[14:16] in ("19", "05", "06", "18"):
            if self.verbose:
                pr(
                    "- GrottServer - "
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
                data_to_put = {"value": value, "result": result}
            elif command == "18":
                data_to_put = {"result": result}
            else:
                # command 05 or 19
                data_to_put = {"value": value}

            # push command response for HTTP server to be aware of
            queue_commandrespadd(
                self.commandresponse,
                self.qname,
                command,
                regkey,
                data_to_put,
            )

            response = None

        elif header[14:16] in ("10"):
            if self.verbose:
                pr(
                    "\t - GrottServer - "
                    + header[12:16]
                    + " record received, no response needed"
                )

            startregister = int(result_string[76:80], 16)
            endregister = int(result_string[80:84], 16)
            value = result_string[84:86]

            regkey = f"{startregister:04x}" + f"{endregister:04x}"
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
                pr("- GrottServer - Unknown record received:")
            response = None

        if response is not None:
            if self.verbose:
                pr(
                    "- GrottServer - Put response on queue: ",
                    self.qname,
                    " msg:\n" + format_multi_line("\t", response),
                )
            self.send_queuereg[self.qname].put_nowait(response)


class Server:
    def __init__(self, conf):
        self.conf = conf
        self.send_queuereg = {}
        self.loggerreg = {}
        self.register_mutex = {}
        self.commandresponse = defaultdict(dict)

    def main(self, conf):
        if conf.grottip == "default":
            conf.grottip = "0.0.0.0"

        http_server = GrottHttpServer(
            conf,
            self.send_queuereg,
            self.loggerreg,
            self.commandresponse,
            self.register_mutex,
        )
        device_server = GrottServer(
            conf,
            self.send_queuereg,
            self.loggerreg,
            self.commandresponse,
            self.register_mutex,
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
            pr("- GrottServer - KeyboardInterrupt received, shutting down")
            http_server.shutdown()
            device_server.shutdown()
