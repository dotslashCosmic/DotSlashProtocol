#DotSlashProtocol - A TCP/IP Fork
#Author: dotSlashCosmic
#TODO Fix the encryption, it works, but I'm lazy rn

import socket, time, binascii, struct, os, logging, time, re, getpass
from Crypto.Cipher import AES
from Crypto.Hash import SHA3_512
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import zlib

class Encrypt:
    def __init__(self, password):
        self.password = password
        hash_object = SHA3_512.new(self.password.encode())
        self.hashed_password = hash_object.digest()[:32]

    def encrypt_data(self, data):
        if isinstance(data, str):
            data = data.encode()
        print('Data:',data)
        compressed_data = zlib.compress(data)
        cipher = AES.new(self.hashed_password, AES.MODE_CBC)
        ct_bytes = cipher.encrypt(pad(compressed_data, AES.block_size))
        iv = cipher.iv
        encrypted_data = bytes([(b + iv[0]) % 256 for b in ct_bytes])
        encrypted_data_with_iv = iv + encrypted_data
        print('Encrypted Data:', encrypted_data)
        print('IV:', iv)
        return encrypted_data_with_iv

    def decrypt_data(self, encrypted_data_with_iv):
        iv = encrypted_data_with_iv[:16]
        encrypted_data = encrypted_data_with_iv[16:]
        decrypted_data = bytes([(b - iv[0]) % 256 for b in encrypted_data])
        cipher = AES.new(self.hashed_password, AES.MODE_CBC, iv=iv)
        pt = unpad(cipher.decrypt(decrypted_data), AES.block_size)
        decompressed_pt = zlib.decompress(pt)
        print('Decrypted Data:', decompressed_pt.decode())
        return decompressed_pt.decode()
       
class DSP:
    def __init__(self, source_ip, dest_ip, source_port, dest_port, dest_mac, data, password):
        self.source_ip = source_ip
        self.dest_ip = dest_ip
        self.source_port = source_port
        self.dest_port = dest_port
        self.dest_mac = dest_mac
        self.data = data
        self.frag_offset = 0
        self.cipher = Encrypt(password)
    
    def dataint(self, t):
        print('t:',t)
        b = b''.join(part for part in t)
        print('b:',b)
        s = b.decode('utf-8', 'ignore')
        return len(s)
        
    def hexify(self, input):
        if isinstance(input, str):
            return bytes(input, 'utf-8')
        elif isinstance(input, int):
            return input.to_bytes((input.bit_length() + 7) // 8, 'big')

    def total_length(self):
        length = self.dataint(self.encrypted_data)
        total_length = int(length) + 36
        if total_length < 256:
            return b'\x00' + total_length.to_bytes(1, 'big')
        else:
            return total_length.to_bytes(2, 'big')
    
    def dec_to_hex(self, d):
        return '\\x' + format(d, '02x')

    def str_to_hex(self, s):
        if isinstance(s, int):
            return ''.join('\\x'+hex(byte)[2:] for byte in s.to_bytes((s.bit_length() + 7) // 8, 'big'))
        else:
            return ''.join('\\x'+hex(byte)[2:] for byte in s.encode())
            
    def str_to_bytes(self, s):
        return bytes.fromhex(s.replace('\\x', ''))
        
    def data_to_bytes(self, d):
        return bytes(int(d[i:i+2], 16) for i in range(2, len(d), 4))
        
    def tuple_to_bytes(self, t):
        return b''.join(part for part in t) 
        
    def port_to_hex(self, port):
        return '\\x' + '\\x'.join([hex(port)[2:].zfill(4)[i:i+2] for i in range(0, 4, 2)])

    def format_hex(self, hexf):
        return b''.join(rb'\x'+hexf[i:i+2] for i in range(0, len(hexf), 2))
        
    def ip_to_bytes(self, ip):
        print(ip)
        parts = ip.split('.')
        hex_parts = ['\\x{:02x}'.format(int(part)) for part in parts]
        return ''.join(hex_parts)
    
    def final_cs(self, c1, c2):
        final = c1 + c2
        return self.cs(final)
        
    def cs(self, header):
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
        cluster_id = os.urandom(2)
        hex_cluster_id = cluster_id.hex()
        assert len(hex_cluster_id) == 4
        hex_cluster_id = 'cc' + hex_cluster_id
        full_id = self.str_to_bytes(hex_cluster_id)
        return full_id
        
    def fragmentation(self, data_bytes):
        max_data_size = (255**2) - 36
        while data_bytes:
            if len(data_bytes) > max_data_size:
                fragment, data_bytes = data_bytes[:max_data_size], data_bytes[max_data_size:]
                yield (fragment, self.frag_offset)
                self.frag_offset += 1
            else:
                yield (data_bytes, self.frag_offset)
                data_bytes = b''
        return fragments
                
    def log(self, packet):
        current_time = time.strftime("%Y%m%d-%H%M%S")
        logging.basicConfig(filename=f'packet_{current_time}.txt', level=logging.INFO, format='DotSlashProtocol:%(message)s')
        logging.info(packet)

    def dsp(self):
        e = Encrypt(password)
        self.encrypted_data = e.encrypt_data(self.data.encode())
        fragments = self.fragmentation(self.data.encode())
        frag_offset = self.frag_offset
        header1 = b'\x45\x18' + self.total_length()# Version, IHL | Total Length of Packet
        print('\nPACKET BREAKDOWN:')
        print(header1, ' Version, IHL, Total Length of Packet')
        header2 = b'\xc0\x53' + self.str_to_bytes(self.port_to_hex(frag_offset))# Identification | Fragment Offset
        print(header2, ' Identification | Fragment Offset')
        header3 = b'\xff' + self.cluster()# TTL | Cluster Number
        print(header3, ' TTL | Cluster Number')
        header4 = socket.inet_aton(self.source_ip)# Source Address
        print(header4, ' Source Address')
        header5 = socket.inet_aton(self.dest_ip)# Destination Address
        print(header5, ' Destination Address')
        header6 = self.port_to_hex(self.source_port) + self.port_to_hex(self.dest_port)# Source Port | Destination Port
        header6 = self.str_to_bytes(header6)
        print(header6, ' Source Port | Destination Port')
        mainheader = header1 + header2 + header3 + header4 + header5 + header6
        header7 = b'\x00\x1c' + self.cs(mainheader)# Reserved, Protocol | Header Checksum
        mainheader = mainheader + header7
        print(header7, ' Reserved, Protocol | Header Checksum')
        header8 = b'\x21\xb2' + self.str_to_bytes(self.port_to_hex(len(self.data.encode())))# Data Offset, Reserved | Data Size
        print(header8, ' Data Offset, Reserved | Data Size')
        header9 = self.tuple_to_bytes(self.encrypted_data)# Data, max of 255^2-36 bytes per fragment
        print(header9, ' Data')
        dataheader = header8 + header9
        header10 = self.cs(dataheader) + self.final_cs(self.cs(mainheader), self.cs(dataheader))# Data Checksum | Final Checksum
        packet = mainheader + dataheader + header10
        print(header10, ' Data Checksum | Final Checksum')
        print('\nPACKET:', packet, '\n\nDATA PLAINTEXT:', self.data)
        self.log(packet)
        eths = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
        interface = 'eth0'
        src_mac = 'c0:53:1c:c0:53:1c'
        eth_type = 0x0800
        src_mac_bytes = bytes.fromhex(src_mac.replace(':', ''))
        dst_mac_bytes = bytes.fromhex(dest_mac.replace(':', ''))
        eth_header = struct.pack('!6s6sH', dst_mac_bytes, src_mac_bytes, eth_type)
        ethpacket = eth_header + packet
        eths.sendto(ethpacket, (interface, 0))
        
def verify_port(port):
    return 0 <= port <= 65535

def verify_ip(ip):
    parts = ip.split('.')
    if len(parts) != 4:
        return False
    for part in parts:
        if not part.isdigit() or not 0 <= int(part) <= 255:
            return False
    return True  
    
def verify_mac(mac):
    pattern = re.compile(
        r"^"
        r"([0-9A-Fa-f]{2}[:-]){5}"
        r"([0-9A-Fa-f]{2})"
        r"$"
    )
    if pattern.match(mac):
        return True
    else:
        return False
    
def get_user_input():
    spoof = input("Do you want to spoof the IP source address? (y/n): ")
    if spoof.lower() == 'y':
        source_ip = input("Enter the IP address to spoof: ")
        if verify_ip(source_ip):
            print(f"{source_ip} is a valid IP address. Spoofing enabled.")
        else:
            print(f"{source_ip} is not a valid IP address. Please enter a valid IP address.")
    else:
        source_ip = socket.gethostbyname(socket.gethostname())
    spoofm = input("Do you want to spoof the MAC source address? (y/n): ")
    if spoofm.lower() == 'y':
        mac = input("Enter the MAC address to spoof: ")
        if verify_mac(mac):
            print(f"{mac} is a valid MAC address. Spoofing enabled.")
        else:
            mac = 'c0:53:1c:c0:53:1c'
    else:
        mac = 'c0:53:1c:c0:53:1c'
    dest_mac = input("Enter the destination MAC address (default: 12:12:12:12:12:12):") or '12:12:12:12:12:12'
    if verify_mac(dest_mac):
        print(f"{dest_mac} is a valid MAC address.")
    else:
        dest_mac = '12:12:12:12:12:12'
    print(f"DSP Source IP Address: {source_ip}\nDSP Source MAC Address: {mac}\nDSP Destination MAC Address: {dest_mac}")
    dest_ip = input("Enter the destination IP address (default: 192.168.1.2):") or '192.168.1.2'
    if not verify_ip(dest_ip):
        print(f"{dest_ip} is not a valid IP address.")
    source_port = int(input("Enter the source port (default: 80):") or 80)
    if not verify_port(source_port):
        print(f"{source_port} is not a valid port number.")
    dest_port = int(input("Enter the destination port (default: 80):") or 80)
    if not verify_port(dest_port):
        print(f"{dest_port} is not a valid port number.")
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
            data = 'Welcome to DotSlashProtocol!'
    else:
        data = 'Welcome to DotSlashProtocol!'
    return source_ip, dest_ip, source_port, dest_port, dest_mac, data

if __name__ == "__main__":
    print("Welcome to DotSlashProtocol - A TCP/IP Fork")
    source_ip, dest_ip, source_port, dest_port, dest_mac, data = get_user_input()
    password = getpass.getpass("Enter encryption password: ")
    send = DSP(source_ip, dest_ip, source_port, dest_port, dest_mac, data, password)
#    encrypted_data = send.cipher.encrypt_data(data)
#    decrypted_data = send.cipher.decrypt_data(encrypted_data)
    send.dsp()
