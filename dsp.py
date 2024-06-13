#DotSlashProtocol - A TCP/IPv4 Fork
#Author: dotSlashCosmic
#TODO Fix the encryption. commented code is encryption related. requires pycryptodome

import argparse, base64, socket, time, struct, os, logging, time, re, sys, getpass, zlib, uuid, requests
#from Crypto.Cipher import AES
#from Crypto.Hash import SHA3_512
#from Crypto.Util.Padding import pad, unpad

#class Encrypt:
#    def __init__(self, password):
#        self.password = password
#        hash_object = SHA3_512.new(self.password.encode())
#        self.hashed_password = hash_object.digest()[:32]

#    def encrypt_data(self, data):
#        if isinstance(data, str):
#            data = data.encode()
#        print('Data:',data)
#        compressed_data = zlib.compress(data)
#        cipher = AES.new(self.hashed_password, AES.MODE_CBC)
#        ct_bytes = cipher.encrypt(pad(compressed_data, AES.block_size))
#        iv = cipher.iv
#        encrypted_data = bytes([(b + iv[0]) % 256 for b in ct_bytes])
#        encrypted_data_with_iv = iv + encrypted_data
#        print('Encrypted Data:', encrypted_data)
#        print('IV:', iv)
#        return encrypted_data_with_iv

#    def decrypt_data(self, encrypted_data_with_iv):
#        iv = encrypted_data_with_iv[:16]
#        encrypted_data = encrypted_data_with_iv[16:]
#        decrypted_data = bytes([(b - iv[0]) % 256 for b in encrypted_data])
#        cipher = AES.new(self.hashed_password, AES.MODE_CBC, iv=iv)
#        pt = unpad(cipher.decrypt(decrypted_data), AES.block_size)
#        decompressed_pt = zlib.decompress(pt)
#        print('Decrypted Data:', decompressed_pt.decode())
#        return decompressed_pt.decode()

class DSP:
#    def __init__(self, source_ip, dest_ip, source_port, dest_port, source_mac, dest_mac, data, password):
    def __init__(self, source_ip, dest_ip, source_port, dest_port, source_mac, dest_mac, data):
        self.source_ip = srcip
        self.dest_ip = dstip
        self.source_port = srcport
        self.source_mac = srcmac
        self.dest_port = dstport
        self.dest_mac = dstmac
        self.data = data
        self.frag_offset = 0
#        self.cipher = Encrypt(password)

    def dataint(self, t):
        b = bytes(t)
        s = b.decode('utf-8', 'ignore')
        return len(s)

    def hexify(self, input):
        if isinstance(input, str):
            return bytes(input, 'utf-8')
        elif isinstance(input, int):
            return input.to_bytes((input.bit_length() + 7) // 8, 'big')

    def total_length(self):
#        length = self.dataint(self.encrypted_data)
        length = self.dataint(self.data.encode())
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
        print(f"pre bytes tuple: {t}")
        return b''.join(part for part in t) 

    def port_to_hex(self, port):
        return '\\x' + '\\x'.join([hex(int(port))[2:].zfill(4)[i:i+2] for i in range(0, 4, 2)])

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
#        e = Encrypt(password)
#        self.encrypted_data = e.encrypt_data(self.data.encode())
        e = self.data.encode()
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
        header9 = self.str_to_bytes(self.data)# Data, max of 255^2-36 bytes per fragment
        print(header9, ' Data')
        dataheader = header8 + header9
        header10 = self.cs(dataheader) + self.final_cs(self.cs(mainheader), self.cs(dataheader))# Data Checksum | Final Checksum
        packet = mainheader + dataheader + header10
        print(header10, ' Data Checksum | Final Checksum')
        print('\nDATA HEX:', self.data)
        self.log(packet)
        eths = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
        interface = 'eth0'
        eth_type = 0x0800
        src_mac_bytes = bytes.fromhex(src_mac.replace(':', ''))
        dst_mac_bytes = bytes.fromhex(dest_mac.replace(':', ''))
        eth_header = struct.pack('!6s6sH', dst_mac_bytes, src_mac_bytes, eth_type)
        eth_packet = eth_header + packet
        print(f"Eth Packet: {eth_packet}")
        eths.sendto(eth_packet, (interface, 0))
        
def get_public_ip():
    try:
        response = requests.get('https://api64.ipify.org?format=json')
        if response.status_code == 200:
            data = response.json()
            public_ip = data.get('ip')
            return public_ip
        else:
            return "Error fetching public IP."
    except Exception as e:
        return f"An error occurred: {str(e)}"

def base_encode_64(inp):
    b = base64.b64encode(bytes(inp, 'utf-8'))
    b64_str = b.decode('utf-8')
    return b64_str
    
def verify_port(port):
    if 0 <= port <= 65535:
        return True, ""
    else:
        return False, f"{port} is not a valid port number."

def verify_ip(ip):
    parts = ip.split('.')
    if len(parts) == 4 and all(part.isdigit() and 0 <= int(part) <= 255 for part in parts):
        return True, ""
    else:
        return False, f"{ip} is not a valid IP address."

def verify_mac(mac):
    pattern = re.compile(r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$")
    if pattern.match(mac):
        return True, ""
    else:
        return False, f"{mac} is not a valid MAC address."
    
def handle_args():
    parser = argparse.ArgumentParser(description="DotSlashProtocol - A TCP/IP Fork")
    parser.add_argument('-dev', type=str, metavar='"SrcMac@SrcIp:SrcPort>DstMac@DstIp:DstPort" - Spoofing mode')
    parser.add_argument('-pck', type=str, metavar='DstMac@DstIp:DstPort - Normal mode (port optional)')
    group = parser.add_mutually_exclusive_group()
    group.add_argument('-Ds', type=str, default='Welcome to DotSlashProtocol!', help='Data string')
    group.add_argument('-Df', type=str, help='Data file')
    args = parser.parse_args()

    public_ip = get_public_ip()  # Store the public IP address

    if args.dev:
        src, dst = args.dev.split('>')
        srcmac, srcip_srcport = src.split('@')
        srcip, srcport = srcip_srcport.split(':')
        srcip = srcip or '192.168.1.2'  # Set a default IP address if not provided
        srcport = srcport or '80'  # Set a default port value if not provided
        srcmac = srcmac or 'C0:53:1C:C0:53:1C'  # Set a default MAC address if not provided
        src = f'{srcmac}@{srcip}:{srcport}'  # Construct src with default values
        dstmac, dstip_dstport = dst.split('@')
        dstip, dstport = dstip_dstport.split(':')
        dstport = dstport or '80'
        dstmac = dstmac or 'C0:53:1C:C0:53:1C'
        dst = f'{dstmac}@{dstip}:{dstport}'
        print("Source:", src)
        print("Destination:", dst)

    elif args.pck:
        dstmac, dstip_dstport = args.pck.split('@')
        dstip, dstport = dstip_dstport.split(':')
        dstport = dstport or '80'
        dstmac = dstmac or 'C0:53:1C:C0:53:1C'
        dst = f'{dstmac}@{dstip}:{dstport}'
        mac_num = hex(uuid.getnode()).replace('0x', '')
        srcmac = ':'.join(mac_num[i: i + 2] for i in range(0, 11, 2))
        srcport = '80' or srcport
        srcip = public_ip
        print("Source:", f'{srcmac}@{srcip}:{srcport}')
        print("Destination:", dst)
    else:
        print("Either -dev or -dst argument is required.")
        parser.print_help()
        sys.exit(1)
    if args.Ds and args.Ds != 'True':
        data = DSP.str_to_hex(1, base_encode_64(args.Ds))
    elif args.Df:
        with open(args.Df, 'r') as file:
            file_content = file.read()
            data = DSP.str_to_hex(1, base_encode_64(file_content))
    else:
        data = DSP.str_to_hex(1, base_encode_64('Welcome to DotSlashProtocol!'))
#    return srcip, dstip, srcport, dstport, srcmac, dstmac, data, password
    return srcip, dstip, srcport, dstport, srcmac, dstmac, data

if __name__ == "__main__":
    print("Welcome to DotSlashProtocol - A TCP/IP Fork")
#    srcip, dstip, srcport, dstport, srcmac, dstmac, data, password = handle_args()
#    send = DSP(srcip, dstip, srcport, dstport, srcmac, dstmac, data, password)
    srcip, dstip, srcport, dstport, srcmac, dstmac, data = handle_args()
    send = DSP(srcip, dstip, srcport, dstport, srcmac, dstmac, data)
    send.dsp()
