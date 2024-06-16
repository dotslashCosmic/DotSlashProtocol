DSP/DotSlashProtocol - A TCP/IP Fork

Usage: 

$ python dsp.py -dev "SrcMac@SrcIp:SrcPort>DstMac@DstIp:DstPort" -Ds 'Hello!'

$ python dsp.py -pck "DstMac@DstIp:DstPort" -Df 'file.php'

Only destination IP is required, the rest default if unused. (requires " @:>@: " for parsing)
Such as:

$ python dsp.py -dev "@:>@5.5.5.5:" -Ds 'Hello!'

WARNING! 
When using -pck, it uses your actual MAC and public IP address.

Features: 
- Verification hashes via <a href=https://github.com/dotslashCosmic/DotSlashVerify>DotSlashVerify</a>
- Windows/Linux support
- Smaller footprint
- Packet logging
- Source IP/Mac/Port spoofing
- AES encryption + compression(On hold)
- Server to accept and read DSP packets
- Full local and public IPv4 integration
- Created HTTP fork for handling DSP traffic(TODO, soon)
- Larger payload per fragmentation(100kb vs 64kb for TCP)
- TCP/UDP spoofing(soon)

Screenshots: Windows/Linux

![Screenshot 2024-06-14 042208](https://github.com/dotslashCosmic/DotSlashProtocol/assets/91699202/6edc10f0-47c4-451d-9c58-a623b2fe07c4)
![Screenshot 2024-06-14 042953](https://github.com/dotslashCosmic/DotSlashProtocol/assets/91699202/9add41a9-0e19-4574-9975-10603ffa209a)

Still under construction
Python =>3.10

Warning- Python interpreter may turn \x hex chars into their respective ASCII forms in the header prints- it's only visual.

(i.e. default source/destination ports show b'\x00P\x00P' when it is b'\x00\x50\x00\x50' - 2x 2 byte hexadecimal>decimal = ports 80 & 80)

