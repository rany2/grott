"""
Grott Growatt monitor :  Proxy
Updated: 2022-08-07
Version 2.7.5
"""

import queue
import socket
import threading
from socketserver import StreamRequestHandler, ThreadingTCPServer

import libscrc

from grottdata import decrypt, format_multi_line, pr, procdata


def validate_record(xdata):
    """validata data record on length and CRC (for "05" and "06" records)

    Args:
        xdata (str): data record in hex format

    Returns:
        int: 0 if valid, 8 if invalid
    """

    data = bytes.fromhex(xdata)
    ldata = len(data)
    len_orgpayload = int.from_bytes(data[4:6], "big")
    header = "".join(f"{n:02x}" for n in data[0:8])
    protocol = header[6:8]

    if protocol in ("05", "06"):
        lcrc = 4
        crc = int.from_bytes(data[ldata - 2 : ldata], "big")
    else:
        lcrc = 0

    len_realpayload = (ldata * 2 - 12 - lcrc) / 2

    if protocol != "02":
        crc_calc = libscrc.modbus(data[0 : ldata - 2])

    if len_realpayload == len_orgpayload:
        returncc = 0
        if protocol != "02" and crc != crc_calc:
            returncc = 8
    else:
        returncc = 8

    return returncc


class Forward:
    def __init__(self, timeout):
        self.forward = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.forward.settimeout(timeout)

    def start(self, host, port):
        try:
            self.forward.connect((host, port))

            # Disable Nagle's Algorithm
            self.forward.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, True)

            return self.forward
        except Exception as e:
            pr(f"- Grott - grottproxy forward error: {e}")
            return False


class GrottProxy(ThreadingTCPServer):
    """This wrapper will create a Growatt server where the handler has access to the config"""

    def __init__(self, conf):
        def handler_factory(*args):
            """
            Using a function to create and return the handler,
            so we can provide our own argument (config)
            """
            return GrottProxyHandler(conf, *args)

        self.allow_reuse_address = True
        self.daemon_threads = True
        super().__init__((conf.grottip, conf.grottport), handler_factory)
        pr(f"- Grottproxy - Ready to listen at: {conf.grottip}:{conf.grottport}")


class GrottProxyHandler(StreamRequestHandler):
    def __init__(self, conf, *args):
        self.conf = conf
        self.verbose = conf.verbose
        self.forward_to = (conf.growattip, conf.growattport)

        self.send_to_device = queue.Queue()
        self.send_to_fwd = queue.Queue()

        self.shutdown_queue = queue.Queue()

        # set variables for StreamRequestHandler's setup()
        self.timeout = conf.timeout
        self.disable_nagle_algorithm = True

        super().__init__(*args)

    def handle(self):
        pr("- Grottproxy - Client connected:", self.client_address)

        self.forward = Forward(self.conf.timeout).start(*self.forward_to)
        if not self.forward:
            pr("- Grottproxy - Forward connection failed:", ":".join(self.forward_to))
            return

        read_thread = threading.Thread(
            target=self.read_data,
        )
        read_thread.daemon = True
        read_thread.start()

        write_thread = threading.Thread(
            target=self.write_data,
        )
        write_thread.daemon = True
        write_thread.start()

        fwd_read_thread = threading.Thread(target=self.fwd_read_data)
        fwd_read_thread.daemon = True
        fwd_read_thread.start()

        fwd_write_thread = threading.Thread(target=self.fwd_write_data)
        fwd_write_thread.daemon = True
        fwd_write_thread.start()

        # wait for self.shutdown_queue to be filled, then shutdown
        self.shutdown_queue.get()

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
                self.process_data(data, queues=[self.send_to_fwd])
        except Exception:
            pr("- Grottproxy - Datalogger read error")
        finally:
            self.shutdown_queue.put_nowait(True)

    def write_data(self):
        try:
            while True:
                data = self.send_to_device.get()
                if not data:
                    break
                self.wfile.write(data)
                self.wfile.flush()
        except Exception:
            pr("- Grottproxy - Datalogger write error")
        finally:
            self.shutdown_queue.put_nowait(True)

    def fwd_read_data(self):
        try:
            while True:
                data = self.forward.recv(8, socket.MSG_WAITALL)
                if not data:
                    break
                # header contains length excl the header itself
                len_payloadleft = int.from_bytes(data[4:6], "big")
                more_data = self.forward.recv(len_payloadleft, socket.MSG_WAITALL)
                if not more_data:
                    break
                data += more_data
                self.process_data(data, queues=[self.send_to_device])
        except OSError:
            pr("- Grottproxy - Forward read error")
        finally:
            self.shutdown_queue.put_nowait(True)

    def fwd_write_data(self):
        try:
            while True:
                data = self.send_to_fwd.get()
                if not data:
                    break
                try:
                    self.forward.send(data)
                except OSError:
                    break
        except OSError:
            pr("- Grottproxy - Forward write error")
        finally:
            self.shutdown_queue.put_nowait(True)

    def process_data(self, data, queues):
        # test if record is not corrupted
        vdata = "".join(f"{n:02x}" for n in data)
        validatecc = validate_record(vdata)
        if validatecc != 0:
            pr("- Grott - grottproxy - Invalid data record received, not processing")
            # Create response if needed?
            # self.send_queuereg[qname].put(response)
            return

        # FILTER!!!!!!!! Detect if configure data is sent!
        header = "".join(f"{n:02x}" for n in data[0:8])
        if self.conf.blockcmd:
            # standard everything is blocked!
            pr("- Growatt command block checking started")
            blockflag = True
            # partly block configure Shine commands
            if header[14:16] == "18":
                if self.conf.blockcmd:
                    if header[6:8] == "05" or header[6:8] == "06":
                        confdata = decrypt(data)
                    else:
                        confdata = data

                    # get conf command (location depends on record type), maybe later more flexibility is needed
                    if header[6:8] == "06":
                        confcmd = confdata[76:80]
                    else:
                        confcmd = confdata[36:40]

                    if header[14:16] == "18":
                        # do not block if configure time command of configure IP (if noipf flag set)
                        if self.verbose:
                            pr("- Grott: Shine Configure command detected")
                        if confcmd == "001f" or (confcmd == "0011" and self.conf.noipf):
                            blockflag = False
                            if confcmd == "001f":
                                confcmd = "Time"
                            if confcmd == "0011":
                                confcmd = "Change IP"
                            if self.verbose:
                                pr(
                                    "- Grott: Configure command not blocked : ",
                                    confcmd,
                                )
                    else:
                        # All configure inverter commands will be blocked
                        if self.verbose:
                            pr("- Grott: Inverter Configure command detected")

            # allow records:
            if header[12:16] in self.conf.recwl:
                blockflag = False

            if blockflag:
                if header[6:8] == "05" or header[6:8] == "06":
                    blockeddata = decrypt(data)
                else:
                    blockeddata = data
                pr(
                    f"- Grott: Record blocked: {header[12:16]}"
                    + "\n"
                    + format_multi_line("\t", blockeddata),
                )
                return

        # send data to destination
        for q in queues:
            q.put_nowait(data)
        if len(data) > self.conf.minrecl:
            # process received data
            procdata(self.conf, data)
        else:
            if self.verbose:
                pr("- Data less then minimum record length, data not processed")

    def close_connection(self):
        pr("- Grottproxy - Close connection:", self.client_address)
        self.send_to_device.put_nowait(None)
        self.send_to_fwd.put_nowait(None)
        if self.forward:
            self.forward.shutdown(socket.SHUT_WR)


class Proxy:
    def __init__(self, conf):
        self.conf = conf

    def main(self, conf):
        if conf.grottip == "default":
            conf.grottip = "0.0.0.0"

        proxy_server = GrottProxy(conf)
        try:
            proxy_server_thread = threading.Thread(target=proxy_server.serve_forever)
            proxy_server_thread.daemon = True

            proxy_server_thread.start()
            proxy_server_thread.join()
        except KeyboardInterrupt:
            pr("- Grottproxy - KeyboardInterrupt received, shutting down")
            proxy_server.shutdown()
