from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection
import lief
from capstone import *
from sys import argv

def enum_sections(elf):
	for section in elf.iter_sections():
		print "0x%x %s" % (section['sh_addr'], section.name)
		if isinstance(section, RelocationSection):
			symbol_table = elf.get_section(section['sh_link'])
			for relocation in section.iter_relocations():
				symbol = symbol_table.get_symbol(relocation['r_info_sym'])
				print '0x%x \t %s' % (relocation['r_offset'], symbol.name)

def disas(elf):
	code = elf.get_section_by_name('.text')
	ops = code.data()
	addr = code['sh_addr']
	md = Cs(CS_ARCH_X86, CS_MODE_64)
	for i in md.disasm(ops, addr):        
		print '0x%X:\t%s\t%s' % (i.address, i.mnemonic, i.op_str)


elf = ELFFile( open(argv[1], "rb") )
enum_sections(elf)

elf = lief.parse( argv[1] )
elf.has_nx
elf.is_pie
elf.header.entrypoint
for section in elf.sections:
	print "%s %d" % (section.name, section.size)
bytes( elf.get_section('.text').content )

elf.patch_address(0x115D, bytearray(b"\x90\x90"))
elf.write("/tmp/patched")

section = lief.ELF.Section(".newsection", lief.ELF.SECTION_TYPES.PROGBITS)
section += lief.ELF.SECTION_FLAGS.EXECINSTR
section += lief.ELF.SECTION_FLAGS.ALLOC
section.content = bytearray("\x90"*16)  
elf.add(section, loaded=True)
elf.write("/tmp/patched2")

elf.remove_section('.newsection')
elf.write("/tmp/patched3")
