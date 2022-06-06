import socket
import struct

from grottdata import procdata

# import select
# import time
# import sys


# import textwrap
# from itertools import cycle # to support "cycling" the iterator
# import time, json, datetime, codecs


class Sniff:
    def __init__(self, conf):
        self.conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
        # if conf.verbose: print("\nGrott monitoring started\n")
        if conf.verbose:
            print("")
            print("\nGrott sniff mode started\n")

    def main(self, conf):
        while True:
            self.raw_data, self.addr = self.conn.recvfrom(65535)
            self.eth = Ethernet(self.raw_data)
            if conf.trace:
                # fmt: off
                print("\n" + "\t - " + "Ethernet Frame:")
                print(f"\t - Destination: {self.eth.dest_mac}, Source: {self.eth.src_mac}, Protocol: {self.eth.proto}")
                # fmt: on
            # IPv4
            if self.eth.proto == 8:
                self.ipv4 = IPv4(self.eth.data)
                if conf.trace:
                    # fmt: off
                    print("\t - " + "IPv4 Packet protocol 8 :")
                    print("\t\t - Version: {self.ipv4.version}, Header Length: {self.ipv4.header_length}, TTL: {self.ipv4.ttl},")
                    print("\t\t - Protocol: {self.ipv4.proto}, Source: {self.ipv4.src}, Target: {self.ipv4.target}")
                    # fmt: on

                # TCP
                # elif self.ipv4.proto == 6:
                if self.ipv4.proto == 6:
                    self.tcp = TCP(self.ipv4.data)
                    if conf.trace:
                        # fmt: off
                        print("\t - " + "TCP Segment protocol 6 found")
                        print("\t\t - Source Port: {self.tcp.src_port}, Destination Port: {self.tcp.dest_port}")
                        print("\t\t - Source IP: {self.ipv4.src}, Destination IP: {self.ipv4.target}")
                        # fmt: on

                    if (
                        self.tcp.dest_port == conf.growattport
                        and self.ipv4.target == conf.growattip
                    ):
                        if conf.verbose:
                            # fmt: off
                            print("\t - " + "TCP Segment Growatt:")
                            print("\t\t - Source Port: {self.tcp.src_port}, Destination Port: {self.tcp.dest_port}")
                            print(f"\t\t - Source IP: {self.ipv4.src}, Destination IP: {self.ipv4.target}")
                            print(f"\t\t - Sequence: {self.tcp.sequence}, Acknowledgment: {self.tcp.acknowledgment}")
                            print("\t\t - " + "Flags:")
                            print(f"\t\t\t - URG: {self.tcp.flag_urg}, ACK: {self.tcp.flag_ack}, PSH: {self.tcp.flag_psh}")
                            print(f"\t\t\t - RST: {self.tcp.flag_rst}, SYN: {self.tcp.flag_syn}, FIN:{self.tcp.flag_fin}")
                            # fmt: on

                        # fmt: off
                        if len(self.tcp.data) > conf.minrecl:
                            procdata(conf, self.tcp.data)
                        else:
                            if conf.verbose:
                                print("\t - Data less then minimum record length, data not processed")
                        # fmt: on

                # Other IPv4 Not used
                else:
                    if conf.trace:
                        print("\t - " + "Other IPv4 Data")
                        # print(format_multi_line(DATA_TAB_2, self.ipv4.data))

            else:
                if conf.trace:
                    print("\t - " + "No IPV4 Ethernet Data")
                    # print(TAB_1 + format_multi_line(DATA_TAB_1, self.eth.data))


# Returns MAC as string from bytes (ie AA:BB:CC:DD:EE:FF)
def get_mac_addr(mac_raw):
    byte_str = map("{:02x}".format, mac_raw)
    mac_addr = ":".join(byte_str).upper()
    return mac_addr


# Unpack ethernet packet
class Ethernet:
    def __init__(self, raw_data):

        dest, src, prototype = struct.unpack("! 6s 6s H", raw_data[:14])

        self.dest_mac = get_mac_addr(dest)
        self.src_mac = get_mac_addr(src)
        self.proto = socket.htons(prototype)
        self.data = raw_data[14:]


# Unpacks IPV4 packet
class IPv4:
    def __init__(self, raw_data):
        version_header_length = raw_data[0]
        self.version = version_header_length >> 4
        self.header_length = (version_header_length & 15) * 4
        self.ttl, self.proto, src, target = struct.unpack(
            "! 8x B B 2x 4s 4s", raw_data[:20]
        )
        self.src = self.ipv4addr(src)
        self.target = self.ipv4addr(target)
        self.data = raw_data[self.header_length :]

    # Returns properly formatted IPv4 address
    def ipv4addr(self, addr):
        return ".".join(map(str, addr))


# Unpack TCP Segment
class TCP:
    def __init__(self, raw_data):
        (
            self.src_port,
            self.dest_port,
            self.sequence,
            self.acknowledgment,
            offset_reserved_flags,
        ) = struct.unpack("! H H L L H", raw_data[:14])
        offset = (offset_reserved_flags >> 12) * 4
        self.flag_urg = (offset_reserved_flags & 32) >> 5
        self.flag_ack = (offset_reserved_flags & 16) >> 4
        self.flag_psh = (offset_reserved_flags & 8) >> 3
        self.flag_rst = (offset_reserved_flags & 4) >> 2
        self.flag_syn = (offset_reserved_flags & 2) >> 1
        self.flag_fin = offset_reserved_flags & 1
        self.data = raw_data[offset:]
