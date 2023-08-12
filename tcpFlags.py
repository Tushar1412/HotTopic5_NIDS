from enum import IntEnum
from functools import reduce

class TcpFlag(IntEnum):
    FIN = 0x01
    SYN = 0x02
    RST = 0x04
    PSH = 0x08
    ACK = 0x10
    URG = 0x20
    ECE = 0x40
    CWR = 0x80

flag_table = {
    'F': TcpFlag.FIN,
    'S': TcpFlag.SYN,
    'R': TcpFlag.RST,
    'P': TcpFlag.PSH,
    'A': TcpFlag.ACK,
    'U': TcpFlag.URG,
    'E': TcpFlag.ECE,
    'C': TcpFlag.CWR
}

def flags_from_string(text):
    return reduce(lambda a, b: a | b, [flag_table[x] for x in list(text)], 0)




