#DotSlashProtocol - A TCP/IP Fork
#Author: dotSlashCosmic
#TODO merge frag offset/data size
#TODO add bytes_wrap def
#TODO add binary de/reserialization def

import socket, time, binascii, struct, os

class DSP:
    def __init__(self, source_ip, target_ip, source_port, dest_port, data):
        self.source_ip = source_ip
        self.target_ip = target_ip
        self.source_port = source_port
        self.dest_port = dest_port
        self.data = data

    def hexify(self, input):
        if isinstance(input, str):
            return bytes(input, 'utf-8')
        elif isinstance(input, int):
            return input.to_bytes((input.bit_length() + 7) // 8, 'big')

    def total_length(self):
        length = len(self.data.encode())
        total_length = int(length) + 36
        if total_length < 256:
            return b'\x00' + total_length.to_bytes(1, 'big')
        else:
            return total_length.to_bytes(2, 'big')
    
    def dec_to_hex(self, d):
        return '\\x' + format(d, '02x')

    def int_to_hex(self, i):
        return ''.join('\\x'+hex(byte)[2:] for byte in i.to_bytes((i.bit_length() + 7) // 8, 'big'))

    def str_to_hex(self, s):
        if isinstance(s, int):
            return ''.join('\\x'+hex(byte)[2:] for byte in s.to_bytes((s.bit_length() + 7) // 8, 'big'))
        else:
            return ''.join('\\x'+hex(byte)[2:] for byte in s.encode())
            
    def str_to_bytes(self, s):
        return bytes.fromhex(s.replace('\\x', ''))
        
    def char_to_hex(self, c):
        return self.str_to_hex(c)

    def port_to_hex(self, port):
        return '\\x' + '\\x'.join([hex(port)[2:].zfill(4)[i:i+2] for i in range(0, 4, 2)])

    def format_hex(self, hexip):
        return b''.join(rb'\x'+hexip[i:i+2] for i in range(0, len(hexip), 2))
        
    def checksum(self, header):
        pos = len(header)
        if pos & 1:
            pos -= 1
            sum = header[pos]
        else:
            sum = 0
        while pos > 0:
            pos -= 2
            sum += (header[pos + 1] << 8) + header[pos]
        sum = (sum >> 16) + (sum & 0xffff)
        sum += sum >> 16
        result = (~sum) & 0xffff
        hexresult = self.hexify(result)
        return hexresult

    def cluster(self):
        cluster_id = os.urandom(4)
        hex_cluster_id = cluster_id.hex()
        assert len(hex_cluster_id) == 8
        full_id = self.str_to_bytes(hex_cluster_id)
        return full_id
        
    def fragmentation(self, data_bytes):
        max_data_size = (255**2) - 36
        self.frag_offset = 0
        fragments = []
        while data_bytes:
            if len(data_bytes) > max_data_size:
                fragment, data_bytes = data_bytes[:max_data_size], data_bytes[max_data_size:]
                fragments.append((fragment, self.frag_offset))
                self.frag_offset += 1
            else:
                fragments.append((data_bytes, self.frag_offset))
                data_bytes = b''
        return fragments
        
    def serialization(self, stream):
        #convert self.dsp.packet from \xhex into ascii, then remove any extra '\', then convert back to \xhex
        pass
        
    def bytes_wrap(self, b):
        #binary wrap any \xhex
        pass
        
    def dsp(self):
        fragments = self.fragmentation(self.data.encode())
        frag_offset = self.frag_offset
        header1 = b'\xaa\x18' + self.total_length()# Version, IHL | Total Length of Packet
        print(header1, ' Version, IHL, Total Length of Packet')
        header2 = b'\xcc\xc0\x00\x00'# Identification | Fragment Offset
        print('REAL FRAG OFFSET:', self.port_to_hex(frag_offset))
        print(header2, ' Identification | Fragment Offset')
        header3 = socket.inet_aton(self.source_ip)# Source Address
        print(header3, ' Source Address')
        header4 = socket.inet_aton(self.target_ip)# Destination Address
        print(header4, ' Destination Address')
        header5 = self.port_to_hex(self.source_port) + self.port_to_hex(self.dest_port)# Source Port | Destination Port
        header5 = self.str_to_bytes(header5)
        print(header5, ' Source Port | Destination Port')
        mainheader = header1 + header2 + header3 + header4 + header5
        header6 = b'\xff\xd7' + self.checksum(mainheader)# TTL, Protocol | Header Checksum
        print(header6, ' TTL, Protocol | Header Checksum')
        header7 = self.cluster()# Cluster Number
        print(header7, ' Cluster Number')
        print('REAL DATA SIZE:', self.port_to_hex(len(self.data.encode())))
        header8 = b'\x35\x02' + self.port_to_hex(len(self.data.encode()))# Data Offset, Reserved | Data Size
        print(header8, ' Data Offset, Reserved | Data Size')
        header9 = self.char_to_hex(self.data)# Data, max of 255^2-36 bytes per fragment
        mainheader = mainheader + header6
        dataheader = header7 + header8 + header9 + header10
        print(header9, ' Data')
        header10 = self.checksum(fullheader) + b'\x00\x00'# Data Checksum | Urgent Pointer
        packet = mainheader + dataheader + header10
        print(header10, ' Checksum | Urgent Pointer')
        print(packet)
        time.sleep(10)

def get_user_input():
    source_ip = input("Enter the source IP address (default: 192.168.1.1):") or '192.168.1.1'
    target_ip = input("Enter the destination IP address (default: 192.168.1.2):") or '192.168.1.2'
    source_port = int(input("Enter the source port (default: 80):") or 80)
    dest_port = int(input("Enter the destination port (default: 80):") or 80)
    data_type = input("Do you want to enter data, upload a file, or default: (data/file/default)")
    if data_type.lower() == "data":
        data = input("Enter the data:")
    elif data_type.lower() == "file":
        filename = input("Enter the filename:")
        try:
            with open(filename, 'r') as file:
                data = file.read()
        except FileNotFoundError:
            print("File not found. Using default data.")
            data = 'Hello, world!'
    else:
        data = 'Hello, world!'
    return source_ip, target_ip, source_port, dest_port, data

if __name__ == "__main__":
    print("Welcome to DotSlashProtocol - A TCP/IP Fork")
    source_ip, target_ip, source_port, dest_port, data = get_user_input()
    send = DSP(source_ip, target_ip, source_port, dest_port, data)
    send.dsp()
