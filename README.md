# Disclaimer
This script is for educational and testing purposes only. You can use it to design firewall rules and protect yourself against flood attacks which uses this method. Do not use it to denal other services.

## Python packages
- [Scapy Installation](http://www.secdev.org/projects/scapy/doc/installation.html)
- Hexdump `pip install hexdump`

## Usage
```
Usage: ipv4-esp-flood.py --target=IPv4 [-s] [-v]

Options:
  --version             show program's version number and exit
  -h, --help            show this help message and exit
  -t IPv4, --target=IPv4
                        IPv4 address of target
  -s, --spoofed         send spoofed source in packets
  -v, --verbose         print hexdumps of packets to stdout
  -o, --once            send packet only once
```
