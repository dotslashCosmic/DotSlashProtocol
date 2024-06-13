DSP/DotSlashProtocol - A TCP/IP Fork

Based on [TUPacket](https://github.com/dotslashCosmic/TUPacket) by me :)
Usage: 
$ python dsp.py -dev "SrcMac@SrcIp:SrcPort>DstMac@DstIp:DstPort" -Ds 'Hello!'
$ python dsp.py -pck "DstMac@DstIp:DstPort" -Df 'file.php'
Only destination IP is required, the rest default if unused. (requires " @:>@: " for parsing)
Such as:
$ python dsp.py -dev "@:>@5.5.5.5:" -Ds 'Hello!'

WARNING!
When using -pck, it uses your actual MAC and public IP address.

Features: 
- Smaller footprint
- Packet logging
- Source IP/Mac/Port spoofing
- AES encryption + compression(On hold)
- Server to accept and read DSP packets
- Full local and public IPv4 integration
- Created HTTP fork for handling DSP traffic(TODO, soon)
- Larger payload per fragmentation(soon)
- TCP/UDP spoofing(soon)

Still under construction
Python =>3.10


Warning- Python interpreter may turn \x hex chars into their respective ASCII forms in the header prints- it's only visual.

(i.e. default source/destination ports show b'\x00P\x00P' when it is b'\x00\x50\x00\x50' - 2x 2 byte hexadecimal>decimal = ports 80 & 80)

