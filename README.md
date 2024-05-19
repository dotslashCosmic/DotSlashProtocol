DSP/DotSlashProtocol - A TCP/IP Fork

Based on [TUPacket](https://github.com/dotslashCosmic/TUPacket) by me :)

Features: 
- Smaller footprint
- Packet logging
- Source IP/Mac spoofing
- AES encryption + compression
- Server to accept and read DSP packets
- Full local and public IPv4 integration
- Created HTTP fork for handling DSP traffic(TODO, soon)
- Optional encryption(soon)
- Larger payload per fragmentation(soon)
- TCP/UDP spoofing(soon)

Still under construction

Warning- Python interpreter may turn \x hex chars into their respective ASCII forms in the header prints- it's only visual.

(i.e. default source/destination ports show b'\x00P\x00P' when it is b'\x00\x50\x00\x50' - 2x 2 byte hexadecimal>decimal = ports 80 & 80)

