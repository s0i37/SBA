#!/usr/bin/python2
import r2pipe
from sys import argv
from os import path, listdir


if len(argv) < 2:
	print "%s memdump/ [0xFROM] [0xTO]" % argv[0]
	exit()

r2 = r2pipe.open()
memdump = argv[1]
from_addr = int( argv[2], 16 ) if len(argv) >= 3 else 0
to_addr = int( argv[3], 16 ) if len(argv) >= 4 else 0

pages = {}
for page_file in listdir(memdump):
	try:
		page_path = path.join(memdump, page_file)
		address = int(page_file.split('=')[0], 16)
		perm = page_file.split('=')[1]
		pages[address] = page_path
	except Exception as e:
		pass

addrs = pages.keys()
addrs.sort(); addrs.reverse()
for addr in addrs:	
	if (from_addr or to_addr) and (from_addr > addr or virtual_to > addr):
		continue
	r2.cmd( "on %s 0x%x" % (pages[addr], addr) )
	print "[+] 0x%08x - %s" % ( addr, path.basename(pages[addr]) )
	
