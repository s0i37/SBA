#!/usr/bin/python
import r2pipe

r2 = r2pipe.open()

if r2.cmdj("iSj"):
	#minidump
	for section in r2.cmdj("iSj"):
		dumpfile_name = "{vaddr}={perm}={section}".format( section=section["name"], vaddr="0x%08x"%section["vaddr"], perm=section["perm"] )
		r2.cmd("s {vaddr}; wtf {dumpfile} @$S!$SS".format( dumpfile=dumpfile_name, vaddr=section["vaddr"] ) )
else:
	#corefile
	for page in r2.cmdj("omj"):
		dumpfile_name = "{vaddr}={perm}={page}".format( page=page["name"].replace('/','-'), vaddr="0x%08x"%page["from"], perm=page["perm"] )
		r2.cmd("wtf {dumpfile} @{vaddr}!{len}".format( dumpfile=dumpfile_name, vaddr=page["from"], len=(page["to"]-page["from"]) ) )
