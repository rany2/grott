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

from grottdata import pr, procdata


def is_record_valid(xdata):
    """validata data record on length and CRC (for "05" and "06" records)

    Args:
        xdata (str): data record in hex format

    Returns:
        bool: True if valid, False if invalid
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

    if len_realpayload != len_orgpayload:
        return False

    if protocol != "02" and crc != crc_calc:
        return False

    return True


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
            pr(f"- GrottProxy - Forward error: {e}")
            return False


def queue_put_nowait_no_exc(q: queue.Queue, data) -> None:
    try:
        q.put_nowait(data)
    except queue.Full:
        pass


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
        pr(f"- GrottProxy - Ready to listen at: {conf.grottip}:{conf.grottport}")


class GrottProxyHandler(StreamRequestHandler):
    def __init__(self, conf, *args):
        self.conf = conf
        self.verbose = conf.verbose
        self.forward_to = (conf.growattip, conf.growattport)

        self.send_to_device = queue.Queue()
        self.send_to_fwd = queue.Queue()

        self.shutdown_queue = queue.Queue(1)

        # set variables for StreamRequestHandler's setup()
        self.timeout = conf.timeout
        self.disable_nagle_algorithm = True

        super().__init__(*args)

    def handle(self):
        pr(
            f"- GrottProxy - Client connected: {self.client_address[0]}:{self.client_address[1]}"
        )

        self.forward = Forward(self.conf.timeout).start(*self.forward_to)
        if not self.forward:
            pr("- GrottProxy - Forward connection failed:", ":".join(self.forward_to))
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
            pr("- GrottProxy - Datalogger read error")
        finally:
            queue_put_nowait_no_exc(self.shutdown_queue, True)

    def write_data(self):
        try:
            while True:
                data = self.send_to_device.get()
                if not data:
                    break
                self.wfile.write(data)
                self.wfile.flush()
        except Exception:
            pr("- GrottProxy - Datalogger write error")
        finally:
            queue_put_nowait_no_exc(self.shutdown_queue, True)

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
            pr("- GrottProxy - Forward read error")
        finally:
            queue_put_nowait_no_exc(self.shutdown_queue, True)

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
            pr("- GrottProxy - Forward write error")
        finally:
            queue_put_nowait_no_exc(self.shutdown_queue, True)

    def process_data(self, data, queues):
        # test if record is not corrupted
        vdata = "".join(f"{n:02x}" for n in data)
        if not is_record_valid(vdata):
            pr("- GrottProxy - Invalid data record received, not processing")
            # Create response if needed?
            # self.send_queuereg[qname].put(response)
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
        pr(
            f"- GrottProxy - Close connection: {self.client_address[0]}:{self.client_address[1]}"
        )
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
            pr("- GrottProxy - KeyboardInterrupt received, shutting down")
            proxy_server.shutdown()
