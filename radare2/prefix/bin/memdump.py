#!/usr/bin/python
import r2pipe

r2 = r2pipe.open()

for section in r2.cmdj("iSj"):
	dumpfile_name = "{section}={vaddr}={perm}".format( section=section["name"], vaddr=hex(section["vaddr"]), perm=section["perm"] )
	r2.cmd("s {vaddr}; wtf {dumpfile} @$S!$SS".format( dumpfile=dumpfile_name, vaddr=section["vaddr"] ) )
	