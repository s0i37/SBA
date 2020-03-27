#!/usr/bin/python3
from unicorn import *
from unicorn.x86_const import *
import r2pipe
from colorama import Fore, Back
from sys import argv

r2 = r2pipe.open()
symbols = r2.cmdj("fj")

def get_symbol(addr):
	out = ''
	for symbol in symbols:
		if symbol["offset"] <= addr <= symbol["offset"] + symbol["size"]:
			out = symbol["name"]
			if addr > symbol["offset"]:
				out += '+%d' % (addr - symbol["offset"])
			break
	return out

def get_perm_code(perm_str):
	code = 0
	return 7
	if perm_str.find('r') != -1:
		code += 4
	if perm_str.find('w') != -1:
		code += 2
	if perm_str.find('x') != -1:
		code += 1
	return code

def load_pages():
	if r2.cmdj("dmj"):	# dynamic mode
		for page in r2.cmdj("dmj"):
			r2.cmd("pr {size}@{offset} > /tmp/page.bin".format(size=page['addr_end']-page['addr'], offset=page['addr']))
			with open("/tmp/page.bin", "rb") as memory:
				mu.mem_map(page['addr'], page['addr_end']-page['addr'])
				mu.mem_write(page['addr'], memory.read())
				mu.mem_protect(page['addr'], page['addr_end']-page['addr'], perms=get_perm_code(page['perm']))
				print( Fore.BLUE + "[*] load {vaddr} {perm} {name}".format(vaddr=hex(page['addr']), perm=page['perm'], name=page['name']) + Fore.RESET )
				
	else:				# static mode
		for page in r2.cmdj("omj"):
			r2.cmd("pr {size}@{offset} > /tmp/page.bin".format(size=page['to']-page['from'], offset=page['from']))
			with open("/tmp/page.bin", "rb") as memory:
				try:
					mu.mem_map(page['from'], page['to']-page['from'])
					mu.mem_write(page['from'], memory.read())
					mu.mem_protect(page['from'], page['to']-page['from'], perms=get_perm_code(page['perm']))
					print( Fore.BLUE + "[*] load {vaddr} {perm} {name}".format(vaddr=hex(page['from']), perm=page['perm'], name=page['name']) + Fore.RESET )
				except:
					print( Fore.LIGHTBLACK_EX + "[-] error {vaddr} {perm} {name}".format(vaddr=hex(page['from']), perm=page['perm'], name=page['name']) + Fore.RESET )

def code_exec(uc, address, size, user_data):
	opcode = mu.mem_read(address, size)
	symbol = get_symbol(address)
	print(Fore.LIGHTCYAN_EX + "(%s)0x%x: %s" % (symbol, address, r2.cmdj("aoj @ {address}".format(address=address))[0]["disasm"]) + Fore.RESET)

def mem_access(uc, access, address, size, value, user_data):
	symbol = get_symbol(address)
	if access in (UC_MEM_WRITE, UC_MEM_WRITE_UNMAPPED):
		print(Fore.LIGHTGREEN_EX + "*(%s)0x%x <- 0x%X" % (symbol, address, value) + Fore.RESET)
	else:
		print(Fore.GREEN + "*(%s)0x%x -> 0x%X" % (symbol, address, value) + Fore.RESET)

def access_violation(uc, access, address, size, value, user_data):
	print(Back.RED + "[!] ACCESS VIOLATION 0x%x" % address + Back.RESET)

def emulation(step_count):
	regs = r2.cmdj("arj")
	load_pages()
	if env["asm.arch"] == "x86" and env["asm.bits"] == 32:
		mu.reg_write(UC_X86_REG_EAX, regs['eax'])
		mu.reg_write(UC_X86_REG_ECX, regs['ecx'])
		mu.reg_write(UC_X86_REG_EDX, regs['edx'])
		mu.reg_write(UC_X86_REG_EBX, regs['ebx'])
		mu.reg_write(UC_X86_REG_ESP, regs['esp'])
		mu.reg_write(UC_X86_REG_EBP, regs['ebp'])
		mu.reg_write(UC_X86_REG_ESI, regs['esi'])
		mu.reg_write(UC_X86_REG_EDI, regs['edi'])
		mu.reg_write(UC_X86_REG_EIP, regs['eip'])
		mu.reg_write(UC_X86_REG_EFLAGS, regs['eflags'])
	if env["asm.arch"] == "x86" and env["asm.bits"] == 64:
		mu.reg_write(UC_X86_REG_RAX, regs['rax'])
		mu.reg_write(UC_X86_REG_RCX, regs['rcx'])
		mu.reg_write(UC_X86_REG_RDX, regs['rdx'])
		mu.reg_write(UC_X86_REG_RBX, regs['rbx'])
		mu.reg_write(UC_X86_REG_RSP, regs['rsp'])
		mu.reg_write(UC_X86_REG_RBP, regs['rbp'])
		mu.reg_write(UC_X86_REG_RSI, regs['rsi'])
		mu.reg_write(UC_X86_REG_RDI, regs['rdi'])
		mu.reg_write(UC_X86_REG_RIP, regs['rip'])
		mu.reg_write(UC_X86_REG_EFLAGS, regs['rflags'])

	pc = int(r2.cmdj("?j $O")["uint64"])

	mu.hook_add(UC_HOOK_MEM_WRITE_UNMAPPED, access_violation)
	mu.hook_add(UC_HOOK_MEM_WRITE, mem_access)

	mu.hook_add(UC_HOOK_MEM_READ_UNMAPPED, access_violation)
	mu.hook_add(UC_HOOK_MEM_READ, mem_access)

	mu.hook_add(UC_HOOK_CODE, code_exec)

	while True:
		try:
			for i in range(step_count):
				if env["asm.arch"] == "x86" and env["asm.bits"] == 64:
					mu.emu_start(mu.reg_read(UC_X86_REG_RIP), 0, 0, 1)
				elif env["asm.arch"] == "x86" and env["asm.bits"] == 32:
					mu.emu_start(mu.reg_read(UC_X86_REG_EIP), 0, 0, 1)
			if input():
				break
		except UcError as e:
			if input():
				break


env = r2.cmdj("ej")
if env["asm.arch"] == "x86" and env["asm.bits"] == 64:
	mu = Uc(UC_ARCH_X86, UC_MODE_64)
elif env["asm.arch"] == "x86" and env["asm.bits"] == 32:
	mu = Uc(UC_ARCH_X86, UC_MODE_32)
if len(argv) > 1:
	step_count = int(argv[1])
else:
	step_count = 1
emulation(step_count)
