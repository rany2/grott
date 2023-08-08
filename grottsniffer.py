import socket
import struct

from grottdata import procdata
from grotthelpers import pr


class Sniff:
    def __init__(self, conf):
        self.conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
        if conf.verbose:
            pr("")
            pr("\nGrott sniff mode started\n")

    def main(self, conf):
        while True:
            raw_data, _ = self.conn.recvfrom(65535)
            eth = Ethernet(raw_data)
            if conf.trace:
                # fmt: off
                pr("\n- Ethernet Frame:\n" +
                f"\t - Destination: {eth.dest_mac}, Source: {eth.src_mac}, Protocol: {eth.proto}")
                # fmt: on
            # IPv4
            if eth.proto == 8:
                ipv4 = IPv4(eth.data)
                if conf.trace:
                    # fmt: off
                    pr("- IPv4 Packet protocol 8:"
                    +f"\n\t - Version: {ipv4.version}, Header Length: {ipv4.header_length}, TTL: {ipv4.ttl},"
                    +f"\n\t - Protocol: {ipv4.proto}, Source: {ipv4.src}, Target: {ipv4.target}")
                    # fmt: on

                # TCP
                # elif ipv4.proto == 6:
                if ipv4.proto == 6:
                    tcp = TCP(ipv4.data)
                    if conf.trace:
                        # fmt: off
                        pr("- TCP Segment protocol 6 found"
                        +f"\n\t - Source Port: {tcp.src_port}, Destination Port: {tcp.dest_port}"
                        +f"\n\t - Source IP: {ipv4.src}, Destination IP: {ipv4.target}")
                        # fmt: on

                    if (
                        tcp.dest_port == conf.growattport
                        and ipv4.target == conf.growattip
                    ):
                        if conf.verbose:
                            # fmt: off
                            pr("- TCP Segment Growatt:"
                            +f"\n\t - Source Port: {tcp.src_port}, Destination Port: {tcp.dest_port}"
                            +f"\n\t - Source IP: {ipv4.src}, Destination IP: {ipv4.target}"
                            +f"\n\t - Sequence: {tcp.sequence}, Acknowledgment: {tcp.acknowledgment}"
                            +"\n\t - Flags:"
                            +f"\n\t\t - URG: {tcp.flag_urg}, ACK: {tcp.flag_ack}, PSH: {tcp.flag_psh}"
                            +f"\n\t\t - RST: {tcp.flag_rst}, SYN: {tcp.flag_syn}, FIN:{tcp.flag_fin}")
                            # fmt: on

                        # fmt: off
                        if len(tcp.data) > conf.minrecl:
                            procdata(conf, tcp.data)
                        else:
                            if conf.verbose:
                                pr("- Data less then minimum record length, data not processed")
                        # fmt: on

                # Other IPv4 Not used
                else:
                    if conf.trace:
                        pr("- Other IPv4 Data")
            else:
                if conf.trace:
                    pr("- No IPV4 Ethernet Data")


def get_mac_addr(mac_raw):
    """Returns MAC as string from bytes (ie AA:BB:CC:DD:EE:FF)"""
    mac_addr = struct.unpack("!6B", mac_raw)
    return ":".join(map(lambda x: format(x, "X"), mac_addr))


class Ethernet:
    """Unpack ethernet packet"""

    def __init__(self, raw_data):
        dest, src, prototype = struct.unpack("! 6s 6s H", raw_data[:14])

        self.dest_mac = get_mac_addr(dest)
        self.src_mac = get_mac_addr(src)
        self.proto = socket.htons(prototype)
        self.data = raw_data[14:]


class IPv4:
    """Unpacks IPV4 packet"""

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

    def ipv4addr(self, addr):
        """Returns properly formatted IPv4 address"""
        return ".".join(map(str, addr))


class TCP:
    """Unpack TCP Segment"""

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
