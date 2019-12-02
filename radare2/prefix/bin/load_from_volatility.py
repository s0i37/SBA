#!/usr/bin/python
import r2pipe
from sys import argv
from os import path, listdir


if len(argv) < 2:
	print "%s vaddump/ [0xFROM] [0xTO]" % argv[0]
	exit()

r2 = r2pipe.open()
vaddump = argv[1]
from_addr = int( argv[2], 16 ) if len(argv) >= 3 else 0
to_addr = int( argv[3], 16 ) if len(argv) >= 4 else 0

pages = {}
for page_file in listdir(vaddump):
	page_path = path.join(vaddump, page_file)
	(virtual_from,virtual_to) = map( lambda x: int(x,16), page_file.split('.')[3].split('-') )
	pages[virtual_from] = page_path

addrs = pages.keys()
addrs.sort(); addrs.reverse()
for addr in addrs:	
	if (from_addr or to_addr) and (from_addr > addr or virtual_to > addr):
		continue
	r2.cmd( "on %s 0x%x" % (page_path, addr) )
	print "[+] 0x%08x - %s" % ( addr, path.basename(page_path) )
	
