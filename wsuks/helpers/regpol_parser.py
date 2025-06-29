import re
import struct
from registrypol.values import RegistryValue
import logging


REG_NONE = 0
REG_SZ = 1
REG_EXPAND_SZ = 2
REG_BINARY = 3
REG_DWORD = 4
REG_DWORD_LITTLE_ENDIAN = 4
REG_DWORD_BIG_ENDIAN = 5
REG_LINK = 6
REG_MULTI_SZ = 7
REG_QWORD = 11
REG_QWORD_LITTLE_ENDIAN = 11

REG_TYPES = {
    0: "REG_NONE",
    1: "REG_SZ",
    2: "REG_EXPAND_SZ",
    3: "REG_BINARY",
    4: "REG_DWORD_LITTLE_ENDIAN",
    5: "REG_DWORD_BIG_ENDIAN",
    6: "REG_LINK",
    7: "REG_MULTI_SZ",
    11: "REG_QWORD_LITTLE_ENDIAN",
}


class RegistryPolicy:
    header = b"Preg" + b"\x01\x00\x00\x00"

    def __init__(self, policy_data):
        self.data = policy_data
        self.parsed_regpol = []
        self.policies = []
        self.logger = logging.getLogger("wsuks")

        # Start parsing the registry policy data
        self.parse_policy()

        for policy in self.parsed_regpol:
            # Parsing the data based on the type
            # src: https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-value-types
            if policy.type == REG_NONE:
                data = policy.data
            elif policy.type == REG_SZ:  # noqa: SIM114
                data = policy.data.decode("utf-16-le").rstrip("\x00")
            elif policy.type == REG_EXPAND_SZ:
                data = policy.data.decode("utf-16-le").rstrip("\x00")
            elif policy.type == REG_BINARY:
                data = policy.data
            elif policy.type == REG_DWORD_LITTLE_ENDIAN:  # REG_DWORD
                data = struct.unpack("<I", policy.data)[0]
            elif policy.type == REG_DWORD_BIG_ENDIAN:
                data = struct.unpack(">I", policy.data)[0]
            elif policy.type == REG_LINK:
                data = policy.data.decode("utf-16-le").rstrip("\x00")
            elif policy.type == REG_MULTI_SZ:
                data = []
                for string in policy.data.decode("utf-16-le").split("\x00"):
                    if string:
                        data.append(string.decode("utf-16-le"))
            elif policy.type == REG_QWORD_LITTLE_ENDIAN:  # REG_QWORD
                data = struct.unpack("<Q", policy.data)[0]
            else:
                data = policy.data

            self.policies.append({
                "key": policy.key.rstrip("\x00"),
                "value": policy.value.rstrip("\x00"),
                "type": REG_TYPES[policy.type],
                "size": policy.size,
                "data": data,
            })

    def get_policies(self):
        return self.policies

    def parse_policy(self):
        values = re.findall(rb"\x5b\x00.*?\x5d\x00", self.data)
        for value in values:
            try:
                self.parsed_regpol.append(RegistryValue.from_bytes(value))
            except ValueError as e:
                self.logger.error(f"Error parsing registry value: {e}. Skipping value: {value}")
