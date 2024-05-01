#DotSlashProtocol - A TCP/IP Fork
#Author: dotSlashCosmic
import socket, struct

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
            version = iph[0]
            ihl = iph[1]
            total_length = iph[2]
            identification = iph[3]
            fragment_offset = iph[4]
            ttl = iph[5]
            cluster_number = struct.unpack('!I', b'\x00' + iph[6])[0]
            s_addr = socket.inet_ntoa(iph[7])
            d_addr = socket.inet_ntoa(iph[8])
            source_port = iph[9]
            dest_port = iph[10]
            reserved = iph[11]
            protocol = iph[12]
            header_checksum = iph[13]
            data_offset = iph[14]
            reserved2 = iph[15]
            data_size = iph[16]
            if identification == 49235 and reserved2 == 178:
                print("\nIdentification: DotSlashProtocol")
            else:
                print("\nIdentification: non-DSP")
            ip_info = 'Destination MAC: ' + eth_addr(packet[0][0:6]) + '\nSource MAC: ' + eth_addr(packet[0][6:12]) + '\nVersion: ' + str(version) + '\nIHL: ' + str(ihl) + '\nTotal Length: ' + str(total_length) + '\nFragment Offset: ' + str(fragment_offset) + '\nTTL: ' + str(ttl) + '\nCluster Number: ' + str(cluster_number) + '\nSource Address: ' + str(s_addr) + '\nDestination Address: ' + str(d_addr) + '\nSource Port: ' + str(source_port) + '\nDest Port: ' + str(dest_port) + '\nProtocol: ' + str(protocol) + '\nHeader Checksum: ' + str(header_checksum) + '\nData Offset: ' + str(data_offset) + '\nData Size: ' + str(data_size)
            data = packet[0][32+eth_length:]
            data_info = '\nData: ' + str(data)
            print(ip_info + data_info)
            
if __name__ == '__main__':
    packet_receiver()
