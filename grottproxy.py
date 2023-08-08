"""
Grott Growatt monitor :  Proxy
Updated: 2022-08-07
Version 2.7.5
"""

import queue
import socket
import threading
from socketserver import StreamRequestHandler, ThreadingTCPServer

from grottdata import procdata
from grotthelpers import Forward, is_record_valid, pr, queue_clear_and_poison


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

        self.shutdown_event = threading.Event()

        # set variables for StreamRequestHandler's setup()
        self.timeout = conf.timeout
        self.disable_nagle_algorithm = True

        super().__init__(*args)

    def handle(self):
        pr(
            f"- GrottProxy - Client connected: {self.client_address[0]}:{self.client_address[1]}"
        )

        try:
            self.forward = Forward().start(*self.forward_to)
            self.forward.settimeout(self.conf.timeout)
        except OSError:
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

        # wait for self.shutdown_event to be set
        self.shutdown_event.wait()

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
                self.process_data(data, q=self.send_to_fwd)
        except Exception:
            pr("- GrottProxy - Datalogger read error")
        finally:
            self.shutdown_event.set()

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
            self.shutdown_event.set()

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
                self.process_data(data, q=self.send_to_device)
        except OSError:
            pr("- GrottProxy - Forward read error")
        finally:
            self.shutdown_event.set()

    def fwd_write_data(self):
        try:
            while True:
                data = self.send_to_fwd.get()
                if not data:
                    break
                self.forward.sendall(data)
        except OSError:
            pr("- GrottProxy - Forward write error")
        finally:
            self.shutdown_event.set()

    def process_data(self, data: bytes, q: queue.Queue):
        # test if record is not corrupted
        vdata = "".join(f"{n:02x}" for n in data)
        if not is_record_valid(vdata):
            pr("- GrottProxy - Invalid data record received, not processing")
            # Create response if needed?
            # self.send_queuereg[qname].put(response)
            return

        # send data to destination
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
        queue_clear_and_poison(self.send_to_device)
        queue_clear_and_poison(self.send_to_fwd)
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
