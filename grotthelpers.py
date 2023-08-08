"""
Helper functions for Growatt server
"""

import queue
import socket
import sys
import textwrap
from contextlib import nullcontext
from itertools import cycle

import libscrc


def decrypt(decdata):
    """decrypt data"""

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

    return result_string


def queue_clear(q: queue.Queue, acquire_mutex=True):
    ctx = q.mutex if acquire_mutex else nullcontext()
    with ctx:
        q.queue.clear()
        q.all_tasks_done.notify_all()
        q.unfinished_tasks = 0


def queue_clear_and_poison(q: queue.Queue):
    with q.mutex:
        queue_clear(q, acquire_mutex=False)
        q.queue.append(None)
        q.unfinished_tasks += 1
        q.not_empty.notify()


def format_multi_line(prefix, string, size=80):
    """Formats multi-line data"""
    size -= len(prefix)
    if isinstance(string, bytes):
        string = "".join(rf"\x{byte:02x}" for byte in string)
        if size % 2:
            size -= 1
    return "\n".join([prefix + line for line in textwrap.wrap(string, size)])


def pr(*args, **kwargs):
    kwargs.setdefault("flush", True)
    kwargs.setdefault("file", sys.stderr)
    return print(*args, **kwargs)


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
    def __init__(self):
        self.forward = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def start(self, host, port):
        self.forward.connect((host, port))

        # Disable Nagle's Algorithm
        self.forward.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, True)

        return self.forward
