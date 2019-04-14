from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection
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
