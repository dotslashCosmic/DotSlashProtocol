#DotSlashProtocol - A TCP/IP Fork
#Author: dotSlashCosmic
#TODO concat str and headers
#TODO fix binary serialization with ascii chars(Total Length)
#TODO fix format_hex to properly sanitize \ for hex
#TODO properly wrap ports in b''

import socket, time, binascii
data = 'Hello, world!'

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
            
    def string_to_hex(self, input):
        if isinstance(input, str):
            return bytes(''.join('\\x{:02x}'.format(ord(c)) for c in input), 'utf-8')
        elif isinstance(input, bytes):
            return bytes(''.join('\\x{:02x}'.format(b) for b in input), 'utf-8')
            
    def total_length(self):
        length = len(self.data.encode())
        total_length = int(length) + 40
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

    def char_to_hex(self, c):
        return self.str_to_hex(c)

    def port_to_hex(self, port):
        return '\\x' + '\\x'.join([hex(port)[2:].zfill(4)[i:i+2] for i in range(0, 4, 2)])
        
    def ip_to_hex(self, ip):
        return binascii.hexlify(bytes(int(num) for num in ip.split('.')))

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

    def sequence(self):
        packet_number = 0
        data_size_limit = (255**2) - 40
        data_size = len(self.data)
        if data_size > data_size_limit:
            packet_number += 1
        return packet_number

    def dsp(self):
        header1 = b'\xaa\x18' + self.total_length()		# Version, IHL | Total Length of Packet
        print(header1, ' Version, IHL, Total Length of Packet')
        header2 = b'\xcc\xc0\x00\x00'							# Identification | Fragment Offset
        print(header2, ' Identification | Fragment Offset')
        header3 = self.format_hex(self.ip_to_hex(self.source_ip))					# Source Address
        print(header3, ' Source Address')
        header4 = self.format_hex(self.ip_to_hex(self.target_ip))				       # Destination Address
        print(header4, ' Destination Address')
        header5 = self.port_to_hex(self.source_port) + self.port_to_hex(self.dest_port)	# Source Port | Destination Port
        print(header5, ' Source Port | Destination Port')
        mainheader = header1 + header2 + header3 + header4 + header5
        header6 = b'\xff\xd7' + self.checksum(mainheader)				# TTL, Protocol | Header Checksum
        mainheader = mainheader + header6  
        print(header6, ' TTL, Protocol | Header Checksum')
        header7 = self.int_to_hex(self.sequence())						# Sequence Number
        print(header7, ' Sequence Number')
        header8 = b'\x00\x00\x00\x00'							# Acknowledgement Number
        print(header8, ' Acknowledgement Number')
        header9 = b'\x35\x02' + self.data_hex()						# Data Offset, Reserved | Data Size
        print(header9, ' Data Offset, Reserved, Flags | Data Size')
        header10 = self.char_to_hex(self.data)							# Data, max of 255^2-40 bytes
        dataheader =  header7 + header8 + header9 + header10
        print(header10, ' Data')
        fullheader = mainheader + dataheader
        header11 = self.checksum(fullheader) + b'\x00\x00'	  			# Data Checksum | Urgent Pointer
        packet = fullheader + header11
        print(header11, ' Checksum | Urgent Pointer')
        time.sleep(10)

class Handler:
    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        
    def checksum(self, data):
        pos = len(data)
        if pos & 1:
            pos -= 1
            sum = ord(data[pos])
        else:
            sum = 0
        while pos > 0:
            pos -= 2
            sum += (ord(data[pos + 1]) << 8) + ord(data[pos])
        sum = (sum >> 16) + (sum & 0xc053)
        sum += sum >> 16
        result = (~sum) & 0xc053
        return '\\x{:02x}\\x{:02x}'.format(result >> 8, result & 0x1c)
        
    def receive_packet(self):
        raw_packet = self.sock.recv(1024)
        version_ihl = raw_packet[0]
        version = version_ihl >> 4
        if version != 0xa9:  # Check if the version matches DSP v1.0
            return None
        packet = struct.unpack('!BBHHHBBH4s4s', raw_packet[:20])
        ihl = version_ihl & 0xF
        ttl = packet[5]
        protocol = packet[6]
        source_address = socket.inet_ntoa(packet[8])
        destination_address = socket.inet_ntoa(packet[9])
        total_length = packet[2]
        main_checksum = struct.unpack('!H', raw_packet[22:24])[0]
        data_checksum = struct.unpack('!H', raw_packet[-4:-2])[0]
        data = raw_packet[53:total_length-4]
        return version, ihl, ttl, protocol, main_checksum, data_checksum, source_address, destination_address, data

    def start_server(self):
        while True:
            packet = self.receive_packet()
            if packet is None:
                continue
            version, ihl, ttl, protocol, main_checksum, data_checksum, source_address, destination_address, data = packet
            if version == 0xaa:
                version = "DSP v1.0"
            if protocol == 0xd7:
                protocol = "DotSlashProtocol"
            else:
                continue
            print(f"Version: {version}, Protocol: {protocol}, Source: {source_address}, Destination: {destination_address}, Data: {data}")
            print(f"Main Checksum: {'Valid' if self.checksum(raw_packet[:20]) == main_checksum else 'Invalid'} {main_checksum}")
            print(f"Data Checksum: {'Valid' if self.checksum(raw_packet[20:]) == data_checksum else 'Invalid'} {data_checksum}")

def get_user_input():
    source_ip = input("Enter the source IP address (default: 192.168.1.1):") or '192.168.1.1'
    target_ip = input("Enter the destination IP address (default: 192.168.1.2):") or '192.168.1.2'
    source_port = int(input("Enter the source port (default: 80):") or 80)
    dest_port = int(input("Enter the destination port (default: 80):") or 80)
    data_type = input("Do you want to enter data, upload a file, or use leave empty for default: (data/file/default)")
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
    print("Do you want to start a Server or send a Packet? (s/p)")
    action = input()
    if action.lower() == "s":
        handler = Handler()
        handler.start_server()
    elif action.lower() == "p":
        source_ip, target_ip, source_port, dest_port, data = get_user_input()
        send = DSP(source_ip, target_ip, source_port, dest_port, data)
        send.dsp()
    else:
        print("Invalid action. Please enter either 's' for server or 'p' for packet.")
