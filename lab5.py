"""
This file has the logic to send the version message and the header message to the bitcoin network
and in return get the verack messages. We also call getnodes to receive multiple blocks from the bitcoin network.
While running the program, we provide the node IP and port to connect to and also provide our own port number.
It has also number converter file that do the data conversion.
The bitcoin node I am hitting is 193.187.90.122:8333
The command to run the program is python3 lab5.py 193.187.90.122 8333 4000
Author: Fnu Shipra
Version: 1.0
"""
from datetime import datetime
import socket
import sys
import hashlib
from time import strftime, gmtime

BUF_SIZE = 1024 * 100
HDR_SZ = 24

"""
Start of the class NumberConverter
"""
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
    def unmarshal_compactsize(b):
        key = b[0]
        if key == 0xff:
            return b[0:9], NumberConverter.unmarshal_uint(b[1:9])
        if key == 0xfe:
            return b[0:5], NumberConverter.unmarshal_uint(b[1:5])
        if key == 0xfd:
            return b[0:3], NumberConverter.unmarshal_uint(b[1:3])
        return b[0:1], NumberConverter.unmarshal_uint(b[0:1])

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

    @staticmethod
    def unmarshal_int(b):
        return int.from_bytes(b, byteorder='little', signed=True)

    @staticmethod
    def unmarshal_uint(b):
        return int.from_bytes(b, byteorder='little', signed=False)

"""
Start of the class BitcoinConnect
"""
class BitCoinConnect:
    
    """
    The init method that takes the peer ip and port to connect to and our own port number
    """
    def __init__(self, peer_ip, peer_port, transmit_port) -> None:
        self.peer_ip = peer_ip
        self.peer_port = peer_port
        self.transmit_port = transmit_port
        self.version_message = None
        self.header = None

    """
    The method that do the sha256 of sha256 of the payload.
    """
    def checksum(self, payload):
        return hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]

    """
    The method to create the header, it prepares the header message
    """
    def create_headers(self, cmd, payload):
        magic_hex_string = bytes.fromhex("F9BEB4D9")
        final_array = bytes(cmd, 'utf-8')
        final_array+= bytes('\00'*(12 - len(cmd)), 'utf-8')
        payload_size =  NumberConverter.uint32_t(len(payload))
        checksum = self.checksum(payload)
        return magic_hex_string + final_array + payload_size + checksum

    """
    The method to do the conversion from ipv4 to ipv6
    """
    def ipv6_from_ipv4(self, ipv4_str):
        pchIPv4 = bytearray([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff])
        return pchIPv4 + bytearray((int(x) for x in ipv4_str.split('.')))

    """
    The method that give the layout to print the version message
    Report the contents of the given bitcoin version message (sans the header)
    :param payload: version message contents
    """
    def print_version_msg(self, b):
        version, my_services, epoch_time, your_services = b[:4], b[4:12], b[12:20], b[20:28]
        rec_host, rec_port, my_services2, my_host, my_port = b[28:44], b[44:46], b[46:54], b[54:70], b[70:72]
        nonce = b[72:80]
        user_agent_size, uasz = NumberConverter.unmarshal_compactsize(b[80:])
        i = 80 + len(user_agent_size)
        user_agent = b[i:i + uasz]
        i += uasz
        start_height, relay = b[i:i + 4], b[i + 4:i + 5]
        extra = b[i + 5:]
        prefix = '  '
        print(prefix + 'VERSION')
        print(prefix + '-' * 56)
        prefix *= 2
        print('{}{:32} version {}'.format(prefix, version.hex(), NumberConverter.unmarshal_int(version)))
        print('{}{:32} my services'.format(prefix, my_services.hex()))
        time_str = strftime("%a, %d %b %Y %H:%M:%S GMT", gmtime(NumberConverter.unmarshal_int(epoch_time)))
        print('{}{:32} epoch time {}'.format(prefix, epoch_time.hex(), time_str))
        print('{}{:32} your services'.format(prefix, your_services.hex()))
        print('{}{:32} your host {}'.format(prefix, rec_host.hex(), self.ipv6_to_ipv4(rec_host)))
        print('{}{:32} your port {}'.format(prefix, rec_port.hex(), NumberConverter.unmarshal_uint(rec_port)))
        print('{}{:32} my services (again)'.format(prefix, my_services2.hex()))
        print('{}{:32} my host {}'.format(prefix, my_host.hex(), self.ipv6_to_ipv4(my_host)))
        print('{}{:32} my port {}'.format(prefix, my_port.hex(), NumberConverter.unmarshal_uint(my_port)))
        print('{}{:32} nonce'.format(prefix, nonce.hex()))
        print('{}{:32} user agent size {}'.format(prefix, user_agent_size.hex(), uasz))
        print('{}{:32} user agent \'{}\''.format(prefix, user_agent.hex(), str(user_agent, encoding='utf-8')))
        print('{}{:32} start height {}'.format(prefix, start_height.hex(), NumberConverter.unmarshal_uint(start_height)))
        print('{}{:32} relay {}'.format(prefix, relay.hex(), bytes(relay) != b'\0'))
        if len(extra) > 0:
            print('{}{:32} EXTRA!!'.format(prefix, extra.hex()))

    """
    The method is used to print the block messages
    Report the contents of the given bitcoin version message (sans the header)
    :param payload: version message contents
    """
    def print_block_nmsg(self, b):
        version, hash_count, hash, stop_hash = b[:4], b[4:5], b[5:37], b[37:]
        prefix = '  '
        print(prefix + 'GETBLOCKS')
        print(prefix + '-' * 56)
        prefix *= 2
        print('{}{:32} version {}'.format(prefix, version.hex(), NumberConverter.unmarshal_int(version)))
        print('{}{:1} hash_count'.format(prefix, NumberConverter.unmarshal_uint(hash_count)))
        print('{}{:32} block hash'.format(prefix, hash.hex()))
        print('{}{:32} stop_hash'.format(prefix, stop_hash.hex()))

    """
    The method is used to print the message.
    Report the contents of the given bitcoin message
    :param msg: bitcoin message including header
    :return: message type
    """
    def print_message(self, msg, text=None):
        print('\n{}MESSAGE'.format('' if text is None else (text + ' ')))
        print('({}) {}'.format(len(msg), msg[:60].hex() + ('' if len(msg) < 60 else '...')))
        payload = msg[HDR_SZ:]
        command = self.print_header(msg[:HDR_SZ], self.checksum(payload))
        if command == 'version':
            self.print_version_msg(payload)
        return command

    """
    This method is used to print the header.
    Report the contents of the given bitcoin message header
    :param header: bitcoin message header (bytes or bytearray)
    :param expected_cksum: the expected checksum for this version message, if known
    :return: message type
    """
    def print_header(self, header, expected_cksum=None):
        magic, command_hex, payload_size, cksum = header[:4], header[4:16], header[16:20], header[20:]
        print(f"magic: {magic} ")
        print(f"command_hex: {command_hex} ")
        command = str(bytearray([b for b in command_hex if b != 0]), encoding='utf-8')
        psz = NumberConverter.unmarshal_uint(payload_size)
        if expected_cksum is None:
            verified = ''
        elif expected_cksum == cksum:
            verified = '(verified)'
        else:
            verified = '(WRONG!! ' + expected_cksum.hex() + ')'
        prefix = '  '
        print(prefix + 'HEADER')
        print(prefix + '-' * 56)
        prefix *= 2
        print('{}{:32} magic'.format(prefix, magic.hex()))
        print('{}{:32} command: {}'.format(prefix, command_hex.hex(), command))
        print('{}{:32} payload size: {}'.format(prefix, payload_size.hex(), psz))
        print('{}{:32} checksum {}'.format(prefix, cksum.hex(), verified))
        return command    

    """
    The method to do the conversion from ipv4 to ipv6
    """
    def ipv6_to_ipv4(self, ipv6):
        return '.'.join([str(b) for b in ipv6[12:]])

    """
    This method is used to create the version message that we need to send to the bitcoin network
    """
    def create_version_message(self):
        version = NumberConverter.int32_t(70015)
        service = NumberConverter.uint64_t(1)
        timestamp = NumberConverter.int64_t(datetime.now().timestamp())
        addr_recv_services = NumberConverter.uint64_t(1)
        addr_recv_ip = self.ipv6_from_ipv4(self.peer_ip)
        addr_recv_port = NumberConverter.uint16_t(self.peer_port)
        addr_trans_services =  NumberConverter.uint64_t(0)
        addr_trans_ip = self.ipv6_from_ipv4("127.0.0.1")
        addr_trans_port = NumberConverter.uint16_t(transmit_port)
        nonce = NumberConverter.uint64_t(0)
        user_agent = bytes(bytearray('', 'utf-8'))
        user_agent_size = NumberConverter.compactsize_t(0)
        start_height = NumberConverter.int32_t(0)
        relay =  NumberConverter.compactsize_t(0)
        message = version + service + timestamp + addr_recv_services + addr_recv_ip + addr_recv_port + addr_trans_services + addr_trans_ip + addr_trans_port +  nonce + user_agent_size + user_agent  + start_height + relay
        self.version_message = message

    """
    The method is used to create the block message. We provide the hash count and the starting block hash
    """
    def create_block_msg(self, hc, starting_block_hash):
        version = NumberConverter.int32_t(70015)
        hash_count = NumberConverter.compactsize_t(hc)
        hash =  bytes.fromhex(starting_block_hash[::-1])
        print(len(hash))
        block_header_hash = hash
        stop_hash_bytes =   bytes.fromhex("0" * 64)
        return version + hash_count + block_header_hash + stop_hash_bytes

    """
    This method is used to get the blocks from the blockchain
    """
    def get_blocks_from_blockchain(self, client_socket, hash_count, starting_block_hash, retry_count):
        if retry_count == 5:
            return []
        block_msg = self.create_block_msg(hash_count, starting_block_hash)
        print("starting hash")
        print(starting_block_hash)
        header = self.create_headers("getblocks", block_msg)
        final_block_msg = header + block_msg
        # self.print_message(final_block_msg)
        print("sending message get blocks")
        client_socket.sendall(final_block_msg)
        print("RECEIVING....")
        msg_header = client_socket.recv(24)
        command = msg_header[4:16]
        payload_size = NumberConverter.unmarshal_uint(msg_header[16:20])
        payload = client_socket.recv(payload_size)
        block_count = NumberConverter.unmarshal_compactsize(payload[:3])
        start = 3                                                       # read data from here
        blocks = []
        print("block count is")
        print(block_count)
        for _ in range(0, block_count[1]):
            block = payload[start + 4 : start + 36][::-1].hex()
            if len(block)  == 64 :
                    blocks.append(block)
            start = start + 36
        print(f"total number of blocks {len(blocks)} ")
        print(f"start is {start}")
        return blocks

    """
    This method is used to send the version message. Create the socket and send the header and version
    message to the bitcoin network and receives the verack message in return.
    """
    def send_version_message(self):
        if self.version_message != None:
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.connect((self.peer_ip, self.peer_port))
            header = self.create_headers("version", self.version_message)
            final_message = header + self.version_message
            print("SENDING VERSION MESSAGE.... ")
            self.print_message(final_message)
            client_socket.sendall(final_message)
            print("RECEIVING....")
            header = client_socket.recv(24)
            payload_size = NumberConverter.unmarshal_uint(header[16:20])
            payload = client_socket.recv(payload_size)
            self.print_header(header, self.checksum(payload))
            self.print_version_msg(payload)
            print("SENDING VERACK MESSAGE..")
            verack_msg = self.create_headers("verack", bytes(bytearray('', 'utf-8')))
            self.print_message(verack_msg)
            client_socket.sendall(verack_msg)
            print("RECEIVING....")
            msg = client_socket.recv(24)
            self.print_message(msg)
            msg = client_socket.recv(24)
            self.print_message(msg)
            msg = client_socket.recv(33)
            self.print_message(msg)
            msg = client_socket.recv(33)
            self.print_message(msg)
            msg = client_socket.recv(32)
            self.print_message(msg)
            msg = client_socket.recv(55)
            self.print_message(msg)
            msg = client_socket.recv(1053)
            self.print_message(msg)
            msg = client_socket.recv(32)
            self.print_message(msg)
            blocks = []
            suid = 600
            print(suid)
            starting_block_hash = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
            blocks+= self.get_blocks_from_blockchain(client_socket, 1, starting_block_hash, 0) 
            print(len(blocks))
            print(blocks)

"""
The main method, entry point to the program
"""  
if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("Required peer node ip and port")
    peer_ip = sys.argv[1]
    peer_port = int(sys.argv[2])
    transmit_port = int(sys.argv[3])
    bc  = BitCoinConnect(peer_ip, peer_port, transmit_port)
    bc.create_version_message()
    bc.send_version_message()