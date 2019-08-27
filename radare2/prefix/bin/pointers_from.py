#!/usr/bin/python2
import r2pipe

r2 = r2pipe.open()
size = int( r2.cmd('e asm.bits') ) / 8
block = r2.cmdj("bj")["blocksize"]
ea = int(r2.cmd("s"), 16)
r2.cmd("fs pointers")
i = 0
while block:
	ptr = r2.cmd("pv%d" % size)
	if not r2.cmd("*%s" % ptr) in ('0xffffffff','0xffffffffffffffff'):
		section = r2.cmdj("iSj. @%s" % ptr) or {"name":"","perm":""}
		flag_name = "ptr_%s_%d" % (section["name"],i)
		print "[+] f %s %d @0x%x" % (flag_name,size,ea)
		r2.cmd( "f %s %d" % (flag_name,size) )
		if section["name"].startswith("Memory_Section_"):
			r2.cmd("fc %s blue" % flag_name)
		elif section["perm"].find("x") != -1:
			r2.cmd("fc %s red" % flag_name)
		else:
			r2.cmd("fc %s green" % flag_name)
		r2.cmd("s+%d" % size)
		i += 1
		block -= size
		ea += size
	else:
		r2.cmd("s+1")
		block -= 1
		ea += 1