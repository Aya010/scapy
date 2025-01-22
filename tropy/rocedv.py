# scapy.contrib.description = RoCE v2
# scapy.contrib.status = loads

"""
RoCE: RDMA over Converged Ethernet
"""
from scapy.packet import Packet, bind_layers, Raw
from scapy.fields import ByteEnumField, ByteField, XByteField, \
    ShortField, XShortField, XLongField, BitField, XBitField, FCSField
from scapy.layers.inet import IP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether
from scapy.compat import raw
from scapy.error import warning
from scapy.contrib.roce import *
from zlib import crc32
import struct

from typing import (
    Tuple
)

RoCEV2_DPORT = 4791
RoCEV2_PKEY = 0xffff

class RETH(Packet):
    name = "RETH"
    fields_desc = [
        BitField("va", 0, 64),
        BitField("rkey", 0, 32),
        BitField("len", 0, 32),
    ]

class AtomicETH(Packet):
    name = "AtomicETH"
    fields_desc = [
        BitField("va", 0, 64),
        BitField("rkey", 0, 32),
        BitField("swap", 0, 64),
        BitField("cmp", 0, 64),
    ]

bind_layers(BTH, RETH, opcode=opcode('RC', 'RDMA_READ_REQUEST')[0])
bind_layers(BTH, RETH, opcode=opcode('RC', 'RDMA_WRITE_ONLY')[0])
bind_layers(BTH, RETH, opcode=opcode('RC', 'RDMA_WRITE_FIRST')[0])
bind_layers(BTH, RETH, opcode=opcode('RC', 'RDMA_WRITE_ONLY_WITH_IMMEDIATE')[0])

bind_layers(BTH, AtomicETH, opcode=opcode('RC', 'COMPARE_SWAP')[0])
bind_layers(BTH, AtomicETH, opcode=opcode('RC', 'FETCH_ADD')[0])


bind_layers(BTH, RETH, opcode=opcode('UC', 'RDMA_READ_REQUEST')[0])
bind_layers(BTH, RETH, opcode=opcode('UC', 'RDMA_WRITE_ONLY')[0])
bind_layers(BTH, RETH, opcode=opcode('UC', 'RDMA_WRITE_FIRST')[0])
bind_layers(BTH, RETH, opcode=opcode('UC', 'RDMA_WRITE_ONLY_WITH_IMMEDIATE')[0])

