# Grott Growatt monitor :  Proxy
#
# Updated: 2022-08-07
# Version 2.7.5

import select
import socket
import sys
import time

import libscrc

from grottdata import decrypt, format_multi_line, pr, procdata

## to resolve errno 32: broken pipe issue (only linux)
if sys.platform != "win32":
    from signal import SIG_DFL, SIGPIPE, signal


# Changing the buffer_size and delay, you can improve the speed and bandwidth.
# But when buffer get to high or delay go too down, you can broke things
buffer_size = 4096
# buffer_size = 65535
delay = 0.0002


def validate_record(xdata):
    # validata data record on length and CRC (for "05" and "06" records)

    data = bytes.fromhex(xdata)
    ldata = len(data)
    len_orgpayload = int.from_bytes(data[4:6], "big")
    header = "".join("{:02x}".format(n) for n in data[0:8])
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
            return self.forward
        except Exception as e:
            pr(f"- Grott - grottproxy forward error: {e}")
            return False


class Proxy:
    input_list = []
    channel = {}

    def __init__(self, conf):
        pr("\nGrott proxy mode started")

        ## to resolve errno 32: broken pipe issue (Linux only)
        if sys.platform != "win32":
            signal(SIGPIPE, SIG_DFL)
        ##
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # set default grottip address
        if conf.grottip == "default":
            conf.grottip = "0.0.0.0"
        self.server.bind((conf.grottip, conf.grottport))
        # socket.gethostbyname(socket.gethostname())
        try:
            hostname = socket.gethostname()
            pr("Hostname:", hostname)
            pr(
                "IP : ",
                socket.gethostbyname(hostname),
                ", port : ",
                conf.grottport,
                "\n",
            )
        except Exception:
            pr("IP and port information not available")

        self.server.listen(200)
        self.forward_to = (conf.growattip, conf.growattport)

    def main(self, conf):
        self.input_list.append(self.server)
        while True:
            time.sleep(delay)
            inputready, _, _ = select.select(self.input_list, [], [])
            for self.s in inputready:
                if self.s == self.server:
                    self.on_accept(conf)
                    break
                try:
                    self.data, self.addr = self.s.recvfrom(buffer_size)
                except Exception:
                    if conf.verbose:
                        pr("- Grott connection error")
                    self.on_close(conf)
                    break
                if len(self.data) == 0:
                    self.on_close(conf)
                    break
                self.on_recv(conf)

    def on_accept(self, conf):
        forward = Forward(conf.forwardsockettimeout).start(
            self.forward_to[0], self.forward_to[1]
        )
        clientsock, clientaddr = self.server.accept()
        if forward:
            if conf.verbose:
                pr("-", clientaddr, "has connected")
            self.input_list.append(clientsock)
            self.input_list.append(forward)
            self.channel[clientsock] = forward
            self.channel[forward] = clientsock
        else:
            if conf.verbose:
                pr(
                    "- Can't establish connection with remote server.\n"
                    "- Closing connection with client side",
                    clientaddr,
                )
            clientsock.close()

    def on_close(self, conf):
        if conf.verbose:
            # try / except to resolve errno 107: Transport endpoint is not connected
            try:
                pr("-", self.s.getpeername(), "has disconnected")
            except Exception:
                pr("-", "peer has disconnected")

        # remove objects from input_list
        self.input_list.remove(self.s)
        self.input_list.remove(self.channel[self.s])
        out = self.channel[self.s]
        # close the connection with client
        self.channel[out].close()  # equivalent to do self.s.close()
        # close the connection with remote server
        self.channel[self.s].close()
        # delete both objects from channel dict
        del self.channel[out]
        del self.channel[self.s]

    def on_recv(self, conf):
        data = self.data
        pr("\n- Growatt packet received:\n\t", self.channel[self.s])

        # test if record is not corrupted
        vdata = "".join("{:02x}".format(n) for n in data)
        validatecc = validate_record(vdata)
        if validatecc != 0:
            pr("- Grott - grottproxy - Invalid data record received, not processing")
            # Create response if needed?
            # self.send_queuereg[qname].put(response)
            return

        # FILTER!!!!!!!! Detect if configure data is sent!
        header = "".join(f"{n:02x}" for n in data[0:8])
        if conf.blockcmd:
            # standard everything is blocked!
            pr("- Growatt command block checking started")
            blockflag = True
            # partly block configure Shine commands
            if header[14:16] == "18":
                if conf.blockcmd:
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
                        if conf.verbose:
                            pr("- Grott: Shine Configure command detected")
                        if confcmd == "001f" or (confcmd == "0011" and conf.noipf):
                            blockflag = False
                            if confcmd == "001f":
                                confcmd = "Time"
                            if confcmd == "0011":
                                confcmd = "Change IP"
                            if conf.verbose:
                                pr(
                                    "- Grott: Configure command not blocked : ",
                                    confcmd,
                                )
                    else:
                        # All configure inverter commands will be blocked
                        if conf.verbose:
                            pr("- Grott: Inverter Configure command detected")

            # allow records:
            if header[12:16] in conf.recwl:
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
        self.channel[self.s].send(data)
        if len(data) > conf.minrecl:
            # process received data
            procdata(conf, data)
        else:
            if conf.verbose:
                pr("- Data less then minimum record length, data not processed")
