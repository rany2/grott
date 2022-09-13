import codecs
import sys
from enum import IntEnum
from typing import Dict, Union


class ModbusFuncType(IntEnum):
    READ_DISCRETE_INPUTS = 2
    READ_COILS = 1
    WRITE_SINGLE_COIL = 5
    WRITE_MULTIPLE_COILS = 15
    READ_INPUT_REGISTERS = 4
    READ_MULTIPLE_HOLDING_REGISTERS = 3
    WRITE_SINGLE_HOLDING_REGISTER = 6
    WRITE_MULTIPLE_HOLDING_REGISTERS = 16
    READ_WRITE_MULTIPLE_REGISTERS = 23
    MASK_WRITE_REGISTER = 22
    READ_FIFO_QUEUE = 24
    READ_FILE_RECORD = 20
    WRITE_FILE_RECORD = 21


class ModbusTcp:
    def __init__(self, data: Union[bytes, None]) -> None:
        if data is None:
            data = b"\x00" * 8

        self._header = {
            "trans": int.from_bytes(data[0:2], "big"),
            "proto": int.from_bytes(data[2:4], "big"),
            "len": int.from_bytes(data[4:6], "big"),
            "unit": data[6],
            "func": data[7],
        }

        self._data = data[8:]

    def set_header(self, key: str, value: int) -> None:
        if key not in self._header:
            raise KeyError(f"{key} not in header")
        elif not isinstance(value, int):
            raise TypeError("value needs to be an int")

        if key not in ("unit", "func") and not 0 <= value <= 2 ** 16 - 1:
            raise ValueError("value needs to be in 0 <= v <= 2**16-1")
        elif key in ("unit", "func") and not 0 <= value <= 2 ** 8 - 1:
            raise ValueError("value needs to be in 0 <= v <= 2**8-1")

        self._header[key] = value

    def set_data(self, data: bytes) -> None:
        self._data = data

    def get_header(self) -> Dict[str, int]:
        try:
            func = ModbusFuncType(self._header["func"])
        except ValueError:
            func = self._header["func"]
        return {
            "trans": self._header["trans"],
            "proto": self._header["proto"],
            "len": self._header["len"],
            "unit": self._header["unit"],
            "func": func,
        }

    def get_data_len(self) -> int:
        return len(self._data)

    def get_data(self) -> bytes:
        return self._data

    def get_raw(self) -> bytes:
        return (
            int.to_bytes(self._header["trans"], 2, "big")
            + int.to_bytes(self._header["proto"], 2, "big")
            + int.to_bytes(self._header["len"], 2, "big")
            + int.to_bytes(self._header["unit"], 1, "big")
            + int.to_bytes(self._header["func"], 1, "big")
            + self._data
        )

    def validate_len(self) -> bool:
        return len(self._data) == self._header["len"]


if __name__ == "__main__":
    print("run with `python -i modbus.py'")
    print()
    print("paste hex string and press ctrl-d when done")
    data = sys.stdin.read()
    data = "".join(data.split())
    data = codecs.decode(data, "hex")
    x = ModbusTcp(data)
    print("access variable `x' for info about this modbus frame")
