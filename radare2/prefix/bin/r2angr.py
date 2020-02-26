#!/usr/bin/python3
import angr
import r2pipe
from colorama import Fore, Back
import logging
logging.getLogger('angr').setLevel('CRITICAL')

r2 = r2pipe.open()

def is_memory_loaded(state, addr):
	return False if state.memory.load(addr, disable_actions=True, inspect=False).uninitialized else True

def get_perm_code(perm_str):
	code = 0
	if perm_str.find('r') != -1:
		code += 4
	if perm_str.find('w') != -1:
		code += 2
	if perm_str.find('x') != -1:
		code += 1
	return code

def load_page(state, addr):
	for page in r2.cmdj("omj"):
		if page['from'] <= addr < page['to']:
			r2.cmd("pr {size}@{offset} > /tmp/page.bin".format(size=page['to']-page['from'], offset=page['from']))
			with open("/tmp/page.bin", "rb") as memory:
				state.memory.store(page['from'], memory.read(), disable_actions=True, inspect=False)
				state.memory.permissions( page['from'], get_perm_code(page['perm']) )
				print( Fore.BLUE + "[*] load {vaddr}".format(vaddr=hex(page['from'])) + Fore.RESET )
			return True
	return False

def taint_mem(state, rip, mem_addr, mem_size):
	mem = state.memory.load(mem_addr, mem_size, disable_actions=True, inspect=False)
	mem_addr = state.se.eval(mem_addr)
	if mem.symbolic:
		r2.cmd("ecHi yellow @{offset}".format(offset=rip))
		r2.cmd('"CCu [taint]{comment}"@{offset}'.format(comment="0x%x = %s"%(mem_addr,str(mem)), offset=rip))
		print( Fore.LIGHTYELLOW_EX + "[taint] 0x%x: 0x%x = %s" % (rip, mem_addr, str(mem)) + Fore.RESET )

def taint_reg(state, rip, reg_name, reg_value):
	if reg_value.symbolic:
		r2.cmd("ecHi yellow @{offset}".format(offset=rip))
		r2.cmd('"CCu [taint]{comment}"@{offset}'.format(comment=reg_name, offset=rip))
		print( Fore.LIGHTYELLOW_EX + "[taint] 0x%x: %s" % (rip, reg_name) + Fore.RESET )

def mem_read_before(state):
	addr = state.se.eval(state.inspect.mem_read_address)
	if not is_memory_loaded(state, addr):
		if not load_page(state, addr):
			print(Back.RED + "[-] {addr} not mapped".format(addr=addr) + Back.RESET)

def mem_write_before(state):
	addr = state.se.eval(state.inspect.mem_write_address)
	if not is_memory_loaded(state, addr):
		if not load_page(state, addr):
			print(Back.RED + "[-] {addr} not mapped".format(addr=addr) + Back.RESET)

def mem_read_after(state):
	exec_addr = state.scratch.ins_addr
	mem_addr = state.se.eval(state.inspect.mem_read_address)
	mem_value = state.se.eval(state.inspect.mem_read_expr)
	mem_size = state.inspect.mem_read_length
	print( Fore.GREEN + "0x%x: *0x%x -> 0x%X" % (exec_addr, mem_addr, mem_value ) + Fore.RESET )
	taint_mem(state, exec_addr, state.inspect.mem_read_address, mem_size)

def mem_write_after(state):
	exec_addr = state.scratch.ins_addr
	mem_addr = state.se.eval(state.inspect.mem_write_address)
	mem_value = state.se.eval(state.inspect.mem_write_expr)
	mem_size = state.inspect.mem_write_length
	print( Fore.LIGHTGREEN_EX + "0x%x: *0x%x <- 0x%X" % (exec_addr, mem_addr, mem_value ) + Fore.RESET )
	taint_mem(state, exec_addr, state.inspect.mem_write_address, mem_size)

def reg_read_after(state):
	exec_addr = state.scratch.ins_addr or 0
	reg_name = project.arch.register_names[state.se.eval(state.inspect.reg_read_offset)]
	reg_value = state.se.eval(state.inspect.reg_read_expr)
	reg_size = state.inspect.reg_read_length
	#print( "[read] 0x%x: %s=%X" % (exec_addr, reg_name, reg_value) )
	taint_reg(state, exec_addr, reg_name, state.inspect.reg_read_expr)

def reg_write_after(state):
	exec_addr = state.scratch.ins_addr or 0
	reg_name = project.arch.register_names[state.se.eval(state.inspect.reg_write_offset)]
	reg_value = state.se.eval(state.inspect.reg_write_expr)
	reg_size = state.inspect.reg_write_length
	#print( "[write] 0x%x: %s=%X" % (exec_addr, reg_name, reg_value) )
	taint_reg(state, exec_addr, reg_name, state.inspect.reg_write_expr)

def _exec(state):
	exec_addr = state.scratch.ins_addr
	print( Fore.LIGHTCYAN_EX + "0x%x: %s" % (exec_addr, r2.cmdj("aoj @ {address}".format(address=exec_addr))[0]["disasm"]) + Fore.RESET )


def symbolic_execute():
	state = project.factory.entry_state(mode='symbolic')

	state.inspect.b('instruction', when=angr.BP_AFTER, action=_exec)
	state.inspect.b('mem_read', when=angr.BP_BEFORE, action=mem_read_before)
	state.inspect.b('mem_read', when=angr.BP_AFTER, action=mem_read_after)
	state.inspect.b('mem_write', when=angr.BP_BEFORE, action=mem_write_before)
	state.inspect.b('mem_write', when=angr.BP_AFTER, action=mem_write_after)
	state.inspect.b('reg_read', when=angr.BP_AFTER, action=reg_read_after)
	state.inspect.b('reg_write', when=angr.BP_AFTER, action=reg_write_after)

	for (reg,value) in r2.cmdj("arj").items():
		setattr(state.regs, reg, value)
	load_page(state, int(r2.cmdj("?j $O")["uint64"]))
	
	r2.cmd("fs symbolic")
	for symbolic in r2.cmdj("fj"):
		sym_data = state.solver.BVS(symbolic["name"], 8*symbolic["size"])
		state.memory.store(symbolic["offset"], sym_data, disable_actions=True, inspect=False)
		if not is_memory_loaded(state, symbolic["offset"]):
			load_page(state, symbolic["offset"])
	r2.cmd("fs *")

	sm = project.factory.simgr(state, save_unconstrained=False)

	basic_blocks = set()


	while sm.active:
		print(sm.active)
		sm.step()

		if input():
			break
		#if sm.active and 0x555555555000 > sm.active[0].addr > 0x555555556000:
		#	break
		
		for path in sm.active: 		# for SimState in SimulationManager
			if not path.addr in basic_blocks: # anti-loop
				basic_blocks.add(path.addr)
				if path.satisfiable():
					input_data = path.se.eval(sym_data, cast_to=bytes)
					r2.cmd('"CCu [symbolic]{solve}"@{offset}'.format(solve=repr(input_data), offset=path.addr))
					print( Back.GREEN + "[+] 0x%x %s" % (path.addr, input_data) + Back.RESET )

	
	print("covered basic blocks:")
	for basic_block in basic_blocks:
		print("0x%x" % basic_block)
	


env = r2.cmdj("ej")
if env["asm.arch"] == "x86" and env["asm.bits"] == 64:
	project = angr.load_shellcode("\x00".encode(), 'x86_64', start_offset=0, load_address=0, support_selfmodifying_code=True)
elif env["asm.arch"] == "x86" and env["asm.bits"] == 32:
	project = angr.load_shellcode("\x00".encode(), 'x86', start_offset=0, load_address=0, support_selfmodifying_code=True)

symbolic_execute()
