#!/usr/bin/python
import r2pipe
from sys import argv

if len(argv) < 3:
	print "%s memdump.dmp memmap.txt [0xFROM] [0xTO]" % argv[0]
	exit()

r2 = r2pipe.open()
memdump = argv[1]
memmap = open( argv[2], "rb" )
from_addr = int( argv[3], 16 ) if len(argv) >= 4 else 0
to_addr = int( argv[4], 16 ) if len(argv) >= 5 else 0

r2.cmd("o %s" % memdump)
for file in r2.cmdj("oj"):
	if file["uri"] == memdump:
		break

for page in memmap:
	try:
		(virtual,physical,size,dump_file_offset) = map( lambda x: int(x, 16), page.split() )
		if (from_addr or to_addr) and (from_addr > virtual or virtual > to_addr):
			continue
		r2.cmd( "om %d %d %d %d" % ( file["fd"], virtual, size, dump_file_offset ) )
		print "[+] 0x%08x" % virtual
	except Exception as e:
		print "[!] " + str(e)
