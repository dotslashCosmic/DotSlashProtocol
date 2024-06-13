#DotSlashProtocol - A TCP/IP Fork
#Author: dotSlashCosmic
#TODO Add decompression from data

import socket, struct

def final_cs(c1, c2):
        final = c1 + c2
        return cs(final)
        
def cs(header):
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
    return result

def eth_addr(a):
  return ':'.join(['%02x' % (x & 0xff) for x in a])

def packet_receiver():
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    while True:
        packet = s.recvfrom(65565)
        eth_length = 14
        eth_header = packet[0][0:eth_length]
        eth = struct.unpack('!6s6sH', eth_header)
        eth_protocol = socket.ntohs(eth[2])
        if eth_protocol == 8:
            ip_header = packet[0][eth_length:32+eth_length]
            iph = struct.unpack('!BBHHHB3s4s4sHHBBHBBH', ip_header)
            data = packet[0][32+eth_length:-4]
            version = iph[0]
            ihl = iph[1]
            total_length = iph[2]
            identification = iph[3]
            fragment_offset = iph[4]
            ttl = iph[5]
            cluster_number = struct.unpack('!I', b'\xff' + iph[6])[0]
            s_addr = socket.inet_ntoa(iph[7])
            d_addr = socket.inet_ntoa(iph[8])
            source_port = iph[9]
            dest_port = iph[10]
            reserved = iph[11]
            protocol = iph[12]
            header_cs = iph[13]
            reserved2 = iph[14]
            data_size = iph[15]
            final_cs = str(struct.unpack('!I', packet[0][-4:])[0])
            if identification + reserved2 + protocol + version + ihl == 49389:
                print("\nPacket!\nID: DotSlashProtocol v1")
                header_cs = bytes([header_cs >> 8, header_cs & 0xFF])
                checksum1 = cs(header_cs)
                checksum2 = cs(packet[0][32+eth_length:-4])
                checksum3 = cs(packet[0][32+eth_length:])
                #checksum4 = convert 2/3 to \xhex, checksum c2+c3
                checksum_info = '\nCalculated Header Checksum: ' + str(checksum1) + '\nCalculated Data Checksum: ' + str(checksum2) + '\nCalculated Final Checksum: ' + str(checksum3)
                ip_info = 'Source MAC: ' + eth_addr(packet[0][6:12]) + '\nSource Address: ' + str(s_addr) + ':' + str(source_port) + '\nDestination MAC: ' + eth_addr(packet[0][0:6]) + '\nDestination Address: ' + str(d_addr) + ':' + str(dest_port) + '\nTotal Length: ' + str(total_length) + '\nFragment Offset: ' + str(fragment_offset) + '\nTTL: ' + str(ttl) + '\nCluster Number: ' + str(cluster_number) + '\nData Size: ' + str(data_size)
                print(ip_info + checksum_info)
                data = data.decode('latin-1')
                print('Data:', data)

if __name__ == '__main__':
    packet_receiver()
