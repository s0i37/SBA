import pefile
from sys import argv

if len(argv) < 2:
	print "%s module.dll [0xOFFSET]"
	exit()

module_name = argv[1]
pe = pefile.PE(module_name)
base = int( argv[2], 16 ) if len(argv) > 2 else pe.OPTIONAL_HEADER.ImageBase

for sym in pe.DIRECTORY_ENTRY_EXPORT.symbols:
	print "0x%x %s" % ( base + sym.address, sym.name )