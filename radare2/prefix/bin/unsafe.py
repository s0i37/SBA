#!/usr/bin/python
import r2pipe
from colorama import Fore

UNSAFE=[
	"alloca",
	"scanf",
	"wscanf",
	"sscanf",
	"swscanf",
	"vscanf",
	"vsscanf",
	"strlen",
	"wcslen",
	"strtok",
	"strtok_r",
	"wcstok",
	"strcat",
	"strncat",
	"wcscat",
	"wcsncat",
	"strcpy",
	"strncpy",
	"wcscpy",
	"wcsncpy",
	"memcpy",
	"wmemcpy",
	"stpcpy",
	"stpncpy",
	"wcpcpy",
	"wcpncpy",
	"memmove",
	"wmemmove",
	"memcmp",
	"wmemcmp",
	"memset",
	"wmemset",
	"gets",
	"sprintf",
	"vsprintf",
	"swprintf",
	"vswprintf",
	"snprintf",
	"vsnprintf",
	"realpath",
	"getwd",
	"wctomb",
	"wcrtomb",
	"wcstombs",
	"wcsrtombs",
	"wcsnrtombs",
]

MAX_DEEP = 100
r2 = r2pipe.open()

known_subs = set()
def walk_up(sub, deep=0):
	global known_subs
	if deep == 0:
		known_subs = set()
	for xref in r2.cmdj( 'axtj {sub}'.format(sub=sub) ):
		if xref["type"].lower() == "call":
			addr = xref.get("fcn_addr")
			_sub = xref.get("fcn_name")
			if not _sub or sub == _sub:
				continue
			if _sub in known_subs or deep >= MAX_DEEP:
				continue
			known_subs.add(_sub)
			if _sub == current_sub:
				break
			deep = walk_up(_sub, deep+1)
	return deep if deep < 100 else 0

current_sub = r2.cmd("afn")
print "func\taddress\txrefs\thow_far"
for unsafe in UNSAFE:
	line = r2.cmd( "ii~{func}$".format(func=unsafe) )
	if line:
		addr = int(line.split()[1], 16)
		xrefs = r2.cmdj( "axtj @{addr}".format(addr=addr) )
		for xref in xrefs:
			if "fcn_addr" in xref:
				deep = walk_up( xref["fcn_addr"] )
				if deep:
					print Fore.RED + "{func}\t{addr}\t{xrefs}\t{deep}".format(func=unsafe, addr=hex(addr), xrefs=len(xrefs), deep=deep) + Fore.RESET
				else:
					print Fore.LIGHTRED_EX + "{func}\t{addr}\t{xrefs}\t-".format(func=unsafe, addr=hex(addr), xrefs=len(xrefs)) + Fore.RESET
	else:
		print Fore.LIGHTBLACK_EX + "{func}\t-\t-\t-".format(func=unsafe) + Fore.RESET
