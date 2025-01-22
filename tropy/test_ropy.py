import unittest
from scapy.contrib.roce import BTH, opcode
from scapy.packet import Raw
from tropy.rocedv import RETH
from tropy.ropy import RoPY

# 测试通过
class TestRoPY(unittest.TestCase):
    def setUp(self):
        self.ropy = RoPY(
            dev='eth0',
            dst_qpn=0x123456,
            dst_ip='192.168.1.1',
            dst_mac='00:11:22:33:44:55',
            src_ip='192.168.1.2',
            src_mac='55:44:33:22:11:00'
        )

    def test_send(self):
        self.ropy.send(opc='SEND_ONLY')

    def test_send_fragmented(self):
        self.ropy.send(opc='SEND_FIRST', len=1024)
        self.ropy.send(opc='SEND_MIDDLE', len=1024)
        self.ropy.send(opc='SEND_LAST', len=1024)

    def test_write(self):
        self.ropy.write(opc='RDMA_WRITE_ONLY', va=0x1000, rkey=0x1001, dlen=1024)

    def test_write_fragmented(self):
        self.ropy.write(opc='RDMA_WRITE_FIRST', va=0x1000, rkey=0x1001, dlen=1024)
        self.ropy.write(opc='RDMA_WRITE_MIDDLE', va=0x1000, rkey=0x1001, dlen=1024)
        self.ropy.write(opc='RDMA_WRITE_LAST', va=0x1000, rkey=0x1001, dlen=1024)

    def test_read(self):
        self.ropy.read(opc='RDMA_READ_REQUEST', va=0x1000, rkey=0x1001, dlen=1024)

    def test_atomic_compare_swap(self):
        self.ropy.atomic(opc='COMPARE_SWAP', va=0x1000, rkey=0x1001, comp=0x1002, swap=0x1003)

    def test_atomic_fetch_add(self):
        self.ropy.atomic(opc='FETCH_ADD', va=0x1000, rkey=0x1001, comp=0x1002, fetch=0x1003)


# 还没测
class TestRoPYUC(unittest.TestCase):
    def setUp(self):
        self.ropy_uc = RoPY(
            dev='eth0',
            dst_qpn=0x123456,
            dst_ip='192.168.1.1',
            dst_mac='00:11:22:33:44:55',
            src_ip='192.168.1.2',
            src_mac='55:44:33:22:11:00',
            transport='UC'
        )

    def test_send(self):
        self.ropy_uc.send(opc='SEND_ONLY')

    def test_send_fragmented(self):
        self.ropy_uc.send(opc='SEND_FIRST', len=1024)
        self.ropy_uc.send(opc='SEND_MIDDLE', len=1024)
        self.ropy_uc.send(opc='SEND_LAST', len=1024)

    def test_write(self):
        self.ropy_uc.write(opc='RDMA_WRITE_ONLY', va=0x1000, rkey=0x1001, dlen=1024)

    def test_write_fragmented(self):
        self.ropy_uc.write(opc='RDMA_WRITE_FIRST', va=0x1000, rkey=0x1001, dlen=1024)
        self.ropy_uc.write(opc='RDMA_WRITE_MIDDLE', va=0x1000, rkey=0x1001, dlen=1024)
        self.ropy_uc.write(opc='RDMA_WRITE_LAST', va=0x1000, rkey=0x1001, dlen=1024)

    def test_random_operations(self):
        import random
        operations = ['SEND_ONLY', 'SEND_FIRST', 'SEND_MIDDLE', 'SEND_LAST', 'RDMA_WRITE_ONLY', 'RDMA_WRITE_FIRST', 'RDMA_WRITE_MIDDLE', 'RDMA_WRITE_LAST']
        for _ in range(100):
            opc = random.choice(operations)
            if opc == 'SEND_ONLY':
                self.ropy_uc.send(opc=opc)
            elif opc == 'RDMA_WRITE_ONLY':
                self.ropy_uc.write(opc=opc, va=0x1000, rkey=0x1001, dlen=1024)
            else:
                if opc == 'RDMA_WRITE_FIRST':
                    # 确保 dlen 是 1024 的整数倍
                    dlen = random.randint(1, 10) * 1024  # 生成 1024 到 10240 之间的 1024 的整数倍
                    self.ropy_uc.write(opc=opc, va=0x1000, rkey=0x1001, dlen=dlen)
                else:
                    self.ropy_uc.send(opc=opc, len=1024) if 'SEND' in opc else self.ropy_uc.write(opc=opc, va=0x1000, rkey=0x1001, dlen=1024)

        # 统计连续的完整报文的个数
        pkt_history = self.ropy_uc.pkt_history
        complete_packets = 0
        i = 0
        state = None  # 状态机状态：None, 'FIRST', 'MIDDLE', 'LAST'
        current_payload_length = 0
        expected_payload_length = None

        while i < len(pkt_history):
            opc = pkt_history[i][BTH].opcode

            if opc == opcode('UC', 'SEND_FIRST')[0] or opc == opcode('UC', 'RDMA_WRITE_FIRST')[0]:
                state = 'FIRST'
                current_payload_length = len(pkt_history[i][Raw])
                if opc == opcode('UC', 'RDMA_WRITE_FIRST')[0]:
                    expected_payload_length = pkt_history[i][RETH].len
            elif opc == opcode('UC', 'SEND_MIDDLE')[0] or opc == opcode('UC', 'RDMA_WRITE_MIDDLE')[0]:
                if state == 'FIRST' or state == 'MIDDLE':
                    state = 'MIDDLE'
                    current_payload_length += len(pkt_history[i][Raw])
                else:
                    state = None
                    current_payload_length = 0
                    expected_payload_length = None
            elif opc == opcode('UC', 'SEND_LAST')[0] or opc == opcode('UC', 'RDMA_WRITE_LAST')[0]:
                if state == 'FIRST' or state == 'MIDDLE':
                    current_payload_length += len(pkt_history[i][Raw])
                    if opc == opcode('UC', 'RDMA_WRITE_LAST')[0] and current_payload_length != expected_payload_length:
                        print(f"Invalid packet sequence detected: expected {expected_payload_length}, got {current_payload_length}")
                    else:
                        complete_packets += 1
                    state = 'LAST'
                else:
                    state = None
                    current_payload_length = 0
                    expected_payload_length = None
            elif opc == opcode('UC', 'SEND_ONLY')[0] or opc == opcode('UC', 'RDMA_WRITE_ONLY')[0]:
                complete_packets += 1
                state = None
                current_payload_length = 0
                expected_payload_length = None
            else:
                state = None
                current_payload_length = 0
                expected_payload_length = None

            i += 1

        print(f"Number of complete packets: {complete_packets}")

if __name__ == "__main__":
    unittest.main()