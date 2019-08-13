#!/usr/bin/python
import r2pipe

r2 = r2pipe.open()

for section in r2.cmdj("iSj"):
	dumpfile_name = "{vaddr}={perm}={section}".format( section=section["name"], vaddr="0x%08x"%section["vaddr"], perm=section["perm"] )
	r2.cmd("s {vaddr}; wtf {dumpfile} @$S!$SS".format( dumpfile=dumpfile_name, vaddr=section["vaddr"] ) )
	