#!/usr/bin/python2
import r2pipe
import struct

r2 = r2pipe.open()
size = '<Q' if r2.cmd('e asm.bits') == '64' else '<I'
block = r2.cmdj("bj")["blocksize"]
r2.cmd("fs search")
founds = len( r2.cmdj("fj") )
while block:
	ptr = struct.pack(size, int(r2.cmd("s"), 16)).encode('hex')
	r2.cmd("/x %s" % ptr)
	if len( r2.cmdj("fj") ) > founds:
		break
	r2.cmd("s+1")
