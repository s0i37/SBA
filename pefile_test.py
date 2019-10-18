import pefile
from sys import argv

if len(argv) < 2:
	print "%s module.dll [0xOFFSET]"
	exit()

module_name = argv[1]
pe = pefile.PE(module_name)
#bytes = pe.section[index].get_data()
base = int( argv[2], 16 ) if len(argv) > 2 else pe.OPTIONAL_HEADER.ImageBase

for sym in pe.DIRECTORY_ENTRY_EXPORT.symbols:
	print "0x%x %s" % ( base + sym.address, sym.name )

for section in pe.sections:
	print "%s 0x%x" % ( section.Name.strip(), pe.OPTIONAL_HEADER.ImageBase + section.VirtualAddress )
	#print section
	if section.IMAGE_SCN_MEM_EXECUTE:
		opcodes = section.get_data()
		offset = section.PointerToRawData + opcodes.find("\x90\x90\x90\x90\x90\x90\x90")
		pe.set_bytes_at_offset(offset, bytes(_bytes))
		pe.write("_%s" % module_name)
