"""
RoCE: RDMA over Converged Ethernet
"""
import random
import os
from scapy.packet import Raw
from scapy.layers.inet import IP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether
from scapy.contrib.roce import BTH, opcode, _ops, _transports, AETH
from tropy.rocedv import RETH, AtomicETH, RoCEV2_DPORT, RoCEV2_PKEY

from scapy.sendrecv import sendp


class RoPY:
    l2_id = 0x0000
    l2_ttl = 64
    l2_flags = 'DF'
    l2_frag = 0
    l2_tos = 1
    l2_version = 4
    l2_ihl = 5

    psn = 0

    pkt_history = []

    def __init__(self, dev, dst_qpn, dst_ip, dst_mac, src_ip, src_mac, src_port=None, psn=None, transport='RC', opc='SEND_ONLY'):
        self.dev = dev
        self.transport = transport
        self.eth = Ether(src=src_mac, dst=dst_mac)
        self.ip = IP(src=src_ip, dst=dst_ip, version=self.l2_version, ihl=self.l2_ihl, ttl=self.l2_ttl,
                     flags=self.l2_flags, frag=self.l2_frag, tos=self.l2_tos, id=self.l2_id)
        src_port = src_port if src_port else random.randint(0, 65535)
        self.psn = psn if psn else 0
        self.udp = UDP(sport=src_port, dport=RoCEV2_DPORT, chksum=0)
        self.bth = BTH(opcode=opcode(self.transport, opc)[1], pkey=RoCEV2_PKEY, dqpn=dst_qpn)
        self.hdr = self.eth / self.ip / self.udp

    def send(self, ack_req=1, mig_req=1, se=0, psn=None, pld=None, len=1024, opc='SEND_ONLY'):
        if psn is None:
            psn = self.psn
            self.psn += 1
        self.bth.opcode = opcode(self.transport, opc)[1]
        self.bth.psn = psn
        self.bth.se = se
        self.bth.ackreq = ack_req
        self.bth.migreq = mig_req
        if pld is None:
            pld = Raw(os.urandom(len))  # 使用os.urandom替代random.randbytes
        else:
            len = len(pld)  # 使用pld的长度而不是len参数
        pad_cnt = (4 - (len % 4)) % 4
        self.bth.padcnt = pad_cnt

        pkt = self.hdr / self.bth / pld
        pkt = Ether(pkt.build())
        sendp(pkt, iface=self.dev, verbose=0)
        # pkt.show()
        self.pkt_history.append(pkt)
        self.l2_id += 1
        self.eth.id = self.l2_id

    def write(self, ack_req=1, mig_req=1, se=0, psn=None, pld=None, len=1024, opc='RDMA_WRITE_ONLY', va=0, rkey=0, dlen=0):
        if psn is None:
            psn = self.psn
            self.psn += 1
        self.bth.opcode = opcode(self.transport, opc)[1]
        self.bth.psn = psn
        self.bth.se = se
        self.bth.ackreq = ack_req
        self.bth.migreq = mig_req
        if pld is None:
            pld = Raw(os.urandom(len))  # 使用os.urandom替代random.randbytes
        else:
            len = len(pld)  # 使用pld的长度而不是len参数
        pad_cnt = (4 - (len % 4)) % 4
        self.bth.padcnt = pad_cnt

        pkt = self.hdr / self.bth
        # 仅当opc为RDMA_WRITE_ONLY或RDMA_WRITE_FIRST时添加RETH字段
        if opc in ['RDMA_WRITE_ONLY', 'RDMA_WRITE_FIRST']:
            reth = RETH(va=va, rkey=rkey, len=dlen)
            pkt /= reth
        pkt /= pld
        pkt = Ether(pkt.build())
        sendp(pkt, iface=self.dev, verbose=0)
        self.pkt_history.append(pkt)
        self.l2_id += 1
        self.eth.id = self.l2_id

    def read(self, ack_req=1, mig_req=1, se=0, psn=None, opc='RDMA_READ_REQUEST', va=0, rkey=0, dlen=0):
        if psn is None:
            psn = self.psn
            self.psn += 1
        self.bth.opcode = opcode(self.transport, opc)[1]
        self.bth.psn = psn
        self.bth.se = se
        self.bth.ackreq = ack_req
        self.bth.migreq = mig_req
        pad_cnt = 0  # 读操作不需要填充
        self.bth.padcnt = pad_cnt

        pkt = self.hdr / self.bth
        reth = RETH(va=va, rkey=rkey, len=dlen)
        pkt /= reth
        pkt = Ether(pkt.build())
        sendp(pkt, iface=self.dev, verbose=0)
        self.pkt_history.append(pkt)
        self.l2_id += 1
        self.eth.id = self.l2_id

    def atomic(self, ack_req=1, mig_req=1, se=0, psn=None, opc='COMPARE_SWAP', va=0, rkey=0, comp=0, swap=0, fetch=0):
        if psn is None:
            psn = self.psn
            self.psn += 1
        self.bth.opcode = opcode(self.transport, opc)[1]
        self.bth.psn = psn
        self.bth.se = se
        self.bth.ackreq = ack_req
        self.bth.migreq = mig_req
        pad_cnt = 0  # 原子操作不需要填充
        self.bth.padcnt = pad_cnt

        pkt = self.hdr / self.bth

        if opc == 'COMPARE_SWAP':
            atomic_eth = AtomicETH(va=va, rkey=rkey, cmp=comp, swap=swap)
        elif opc == 'FETCH_ADD':
            atomic_eth = AtomicETH(va=va, rkey=rkey, cmp=comp, swap=fetch)
        else:
            raise ValueError("Unsupported atomic operation")

        pkt /= atomic_eth
        pkt = Ether(pkt.build())
        sendp(pkt, iface=self.dev, verbose=0)
        self.pkt_history.append(pkt)
        self.l2_id += 1
        self.eth.id = self.l2_id
