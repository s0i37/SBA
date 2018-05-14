from unicorn import *
from unicorn.x86_const import *
from capstone import *


def code_exec(uc, address, size, user_data):
	opcode = mu.mem_read(address, size)
	instr = md.disasm(opcode, 0).next()
	print "exec: %s %s" % (instr.mnemonic, instr.op_str)

def mem_access(uc, access, address, size, value, user_data):
	if access in (UC_MEM_WRITE, UC_MEM_WRITE_UNMAPPED):
		print "writ: 0x%X ->(%d) 0x%x" % (value, size, address)
	else:
		print "read: 0x%X <-(%d) 0x%x" % (value, size, address)

def mem_add_page(uc, access, address, size, value, user_data):
	#print "+ 0x%08x" % address
	mu.mem_map(address & 0xfffff000, 4096)


mu = Uc(UC_ARCH_X86, UC_MODE_32)
mu.mem_map(0x401000, 4096)
mu.reg_write(UC_X86_REG_ESP, 0x403500)

md = Cs(CS_ARCH_X86, CS_MODE_32)

mu.hook_add(UC_HOOK_MEM_WRITE, mem_access)
mu.hook_add(UC_HOOK_MEM_WRITE_UNMAPPED, mem_add_page)

mu.hook_add(UC_HOOK_MEM_READ, mem_access)
mu.hook_add(UC_HOOK_MEM_READ_UNMAPPED, mem_add_page)

mu.hook_add(UC_HOOK_CODE, code_exec)

try:
	mu.mem_write(0x401000, "\x55\x90")
	mu.emu_start(0x401000, 0x401002)
except:
	pass

try:
	mu.mem_write(0x401000, "b90a000000be00304000bf00504000f3a5".decode('hex'))
	mu.emu_start(0x401000, len("b90a000000be00304000bf00504000f3a5".decode('hex')) )
except:
	pass