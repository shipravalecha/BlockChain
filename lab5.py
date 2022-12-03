from datetime import datetime
import os
import socket
import sys
import hashlib

BUF_SIZE = 1024 * 100
class NumberConverter:
    @staticmethod
    def compactsize_t(n):
        if n < 252:
            return NumberConverter.uint8_t(n)
        if n < 0xffff:
            return NumberConverter.uint8_t(0xfd) + NumberConverter.uint16_t(n)
        if n < 0xffffffff:
            return NumberConverter.uint8_t(0xfe) + NumberConverter.uint32_t(n)
        return NumberConverter.uint8_t(0xff) + NumberConverter.uint64_t(n)

    @staticmethod
    def uint8_t(n):
        return int(n).to_bytes(1, byteorder='little', signed=False)
    @staticmethod
    def uint16_t(n):
        return int(n).to_bytes(2, byteorder='little', signed=False)

    @staticmethod
    def int32_t(n):
        return int(n).to_bytes(4, byteorder='little', signed=True)

    @staticmethod
    def uint32_t(n):
        return int(n).to_bytes(4, byteorder='little', signed=False)

    @staticmethod
    def int64_t(n):
        return int(n).to_bytes(8, byteorder='little', signed=True)

    @staticmethod
    def uint64_t(n):
        return int(n).to_bytes(8, byteorder='little', signed=False)

class BitCoinConnect:
    def ipv6_from_ipv4(ipv4_str):
        pchIPv4 = bytearray([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff])
        return pchIPv4 + bytearray((int(x) for x in ipv4_str.split('.')))
    
    def __init__(self, peer_ip, peer_port, transmit_port) -> None:
        self.peer_ip = peer_ip
        self.peer_port = peer_port
        self.transmit_port = transmit_port
        self.version_message = None
        self.header = None

    def create_headers(self):
        magic_hex_string = "f9beb4d9"
        print("magic size")
        print(len(magic_hex_string) / 2)
        final_array = 'version\0\0\0\0\0'.encode('utf-8').hex()
        print(final_array)
        payload_size = f"{hex(len(self.version_message))}"
        print(f"actual payload size is {payload_size}")
        print(f"actual payload size is {len(self.version_message)}")
        checksum = hashlib.sha256(hashlib.sha256(self.version_message.encode('utf-8')).hexdigest().encode('utf-8')).hexdigest()[:8]
        print(f"checksum size is {len(checksum) / 2}")
        self.header = magic_hex_string + final_array + payload_size + checksum
        print("header size is ")
        print(len(self.header.encode('utf-8')))

    def ipv6_from_ipv4(self, ipv4_str):
        pchIPv4 = bytearray([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff])
        return pchIPv4 + bytearray((int(x) for x in ipv4_str.split('.')))


    def ipv6_to_ipv4(self, ipv6):
        return '.'.join([str(b) for b in ipv6[12:]])
    def create_version_message(self):
        version = NumberConverter.int32_t(70016).hex()
        print(f"version is {version}")
        service = NumberConverter.uint64_t(1).hex()
        print(f"service {service}")
        timestamp = NumberConverter.int64_t(datetime.now().timestamp()).hex()
        print("timestamp is ")
        print(timestamp)
        addr_recv_services = NumberConverter.uint64_t(1).hex()
        print(f"addr_recv_services {addr_recv_services}")
        addr_recv_ip = self.ipv6_from_ipv4(self.peer_ip).hex()
        print(f"addr_recv_ip {addr_recv_ip}")
        addr_recv_port = NumberConverter.uint16_t(self.peer_port).hex()
        print(f"addr_recv_port {addr_recv_port}")
        addr_trans_services =  NumberConverter.uint64_t(0).hex()
        print(f"addr_trans_services {addr_trans_services}")
        addr_trans_ip = self.ipv6_from_ipv4("127.0.0.1").hex()
        print(f"addr_trans_ip {addr_trans_ip}")
        addr_trans_port = NumberConverter.uint16_t(transmit_port).hex()
        print(f"addr_trans_port {addr_trans_port}")
        nonce = NumberConverter.uint64_t(0).hex()
        print(f"nonce {nonce}")
        user_agent = bytes('', 'utf-8').hex()
        print(f"user_agent {user_agent}")
        user_agent_size = NumberConverter.compactsize_t(0).hex()
        print(f"user_agent_size {user_agent_size}")
        start_height = NumberConverter.int32_t(0).hex()
        print(f"start_height {start_height}")
        relay = bytes(0).hex()
        message = version + service + timestamp + addr_recv_services + addr_recv_ip + addr_recv_port + addr_trans_services + addr_trans_ip + addr_trans_port +  nonce + user_agent_size + user_agent  + start_height + relay
        self.version_message = message
        print("version is ")
        print(self.version_message)
        print("length of version message is ")
        print(len(self.version_message))
    def send_version_message(self):
        if self.version_message != None:
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.connect((self.peer_ip, self.peer_port))
            print("header is ")
            print(self.header)
            print("sending message ... ")
            final_message = self.header + self.version_message
            print(bytes(final_message.encode('utf-8')))
            client_socket.sendall(bytes(final_message.encode('utf-8')))
            print("receiving .. ")
            print(client_socket.recv(BUF_SIZE))




if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("Required peer node ip and port")
    peer_ip = sys.argv[1]
    peer_port = int(sys.argv[2])
    transmit_port = int(sys.argv[3])
    bc  = BitCoinConnect(peer_ip, peer_port, transmit_port)
    bc.create_version_message()
    bc.create_headers()
    bc.send_version_message()