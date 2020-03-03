#!/usr/bin/python3
import angr
import sys
import os
import logging
logging.getLogger('angr').setLevel('CRITICAL')


memory_dir = sys.argv[1]

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
	global memory_dir
	for page in os.listdir(memory_dir):
		page_addr = int( page.split("=")[0], 16 )
		page_perm = page.split("=")[1]
		page_size = os.stat( os.path.join(memory_dir, page) ).st_size
		if page_addr <= addr < page_addr+page_size:
			with open(os.path.join(memory_dir, page), "rb") as memory:
				state.memory.store(page_addr, memory.read(), disable_actions=True, inspect=False)
				state.memory.permissions( page_addr, get_perm_code(page_perm) )
				print( "[*] {vaddr} {page}".format(vaddr=hex(addr), page=page) )
			return True
	return False

def check_page(state, addr):
	if not is_memory_loaded(state, addr):
		if not load_page(state, addr):
			print("[-] {addr} not mapped".format(addr=hex(addr)))

def taint_mem(state, rip, mem_addr, mem_size):
	mem = state.memory.load(mem_addr, mem_size, disable_actions=True, inspect=False)
	mem_addr = state.se.eval(mem_addr)
	if mem.symbolic:
		print( "[taint] 0x%x: 0x%x = %s" % (rip, mem_addr, str(mem)) )

def taint_reg(state, rip, reg_name, reg_value):
	#reg = state.memory.load(reg_value, disable_actions=True, inspect=False)
	if reg_value.symbolic:
		print( "[taint] 0x%x: %s" % (rip, reg_name) )

def mem_read_before(state):
	addr = state.se.eval(state.inspect.mem_read_address)
	check_page(state, addr)

def mem_write_before(state):
	addr = state.se.eval(state.inspect.mem_write_address)
	check_page(state, addr)

def mem_read_after(state):
	exec_addr = state.scratch.ins_addr
	mem_addr = state.se.eval(state.inspect.mem_read_address)
	mem_value = state.se.eval(state.inspect.mem_read_expr)
	mem_size = state.inspect.mem_read_length
	print( "[read] 0x%x: *0x%x -> %X" % (exec_addr, mem_addr, mem_value ) )
	taint_mem(state, exec_addr, state.inspect.mem_read_address, mem_size)
	#import ipdb; ipdb.set_trace()

def mem_write_after(state):
	exec_addr = state.scratch.ins_addr
	mem_addr = state.se.eval(state.inspect.mem_write_address)
	mem_value = state.se.eval(state.inspect.mem_write_expr)
	mem_size = state.inspect.mem_write_length
	print( "[write] 0x%x: *0x%x <- %X" % (exec_addr, mem_addr, mem_value ) )
	taint_mem(state, exec_addr, state.inspect.mem_write_address, mem_size)

def reg_read_after(state):
	exec_addr = state.scratch.ins_addr or 0
	reg_name = project.arch.register_names[state.se.eval(state.inspect.reg_read_offset)]
	reg_value = state.se.eval(state.inspect.reg_read_expr)
	reg_size = state.inspect.reg_read_length
	print( "[read] 0x%x: %s=%X" % (exec_addr, reg_name, reg_value) )
	taint_reg(state, exec_addr, reg_name, state.inspect.reg_read_expr)

def reg_write_after(state):
	exec_addr = state.scratch.ins_addr or 0
	reg_name = project.arch.register_names[state.se.eval(state.inspect.reg_write_offset)]
	reg_value = state.se.eval(state.inspect.reg_write_expr)
	reg_size = state.inspect.reg_write_length
	print( "[write] 0x%x: %s=%X" % (exec_addr, reg_name, reg_value) )
	taint_reg(state, exec_addr, reg_name, state.inspect.reg_write_expr)

def _exec(state):
	exec_addr = state.scratch.ins_addr
	print( "[exec] 0x%x" % exec_addr )


def symbolic_execute():
	state = project.factory.entry_state(mode='symbolic')

	state.inspect.b('mem_read', when=angr.BP_BEFORE, action=mem_read_before)
	state.inspect.b('mem_read', when=angr.BP_AFTER, action=mem_read_after)
	state.inspect.b('mem_write', when=angr.BP_BEFORE, action=mem_write_before)
	state.inspect.b('mem_write', when=angr.BP_AFTER, action=mem_write_after)
	state.inspect.b('reg_read', when=angr.BP_AFTER, action=reg_read_after)
	state.inspect.b('reg_write', when=angr.BP_AFTER, action=reg_write_after)
	state.inspect.b('instruction', when=angr.BP_AFTER, action=_exec)

	load_page(state, 0x555555555000)
	load_page(state, 0x555555556000)

	state.regs.rax = 0x555555556004
	state.regs.rbx = 0x00000000
	state.regs.rcx = 0x7ffff7fa3718
	state.regs.rdx = 0x7fffffffe1e8
	state.regs.rsi = 0x7fffffffe1d8
	state.regs.rdi = 0x555555556004
	state.regs.r8 = 0x7ffff7fa5a50
	state.regs.r9 = 0x7ffff7fe3780
	state.regs.r10 = 0x00000007
	state.regs.r11 = 0x00000002
	state.regs.r12 = 0x555555555040
	state.regs.r13 = 0x7fffffffe1d0
	state.regs.r14 = 0x00000000
	state.regs.r15 = 0x00000000
	state.regs.rip = 0x555555555186
	state.regs.rbp = 0x7fffffffe0f0
	state.regs.rflags = 0x00000202
	state.regs.rsp = 0x7fffffffe0e0
	sym_data = state.solver.BVS('input', 8*9)
	state.memory.store(0x555555556004, sym_data, disable_actions=True, inspect=False)

	sm = project.factory.simgr(state, save_unconstrained=False)  # SimState -> SimulationManager
	#sm.use_technique(angr.exploration_techniques.DFS()) 	# deep search

	basic_blocks = set()

	while sm.active:
		check_page(sm.active[0], sm.active[0].addr)
		print(sm.active)
		sm.step()
		if sm.active and 0x555555555000 > sm.active[0].addr > 0x555555556000:
			break
		
		for path in sm.active: 		# for SimState in SimulationManager
			if not path.addr in basic_blocks: # anti-loop
				basic_blocks.add(path.addr)
				if path.satisfiable():
					input_data = path.se.eval(sym_data, cast_to=bytes)
					print( "[+] 0x%x %s" % (path.addr, input_data) )

	print("covered basic blocks:")
	for basic_block in basic_blocks:
		print("0x%x" % basic_block)

'''
@proj.hook(0x75bfceae)
def LocalAlloc(state):
	uFlag = state.mem[state.regs.esp+4].int32_t.concrete
	uBytes = state.mem[state.regs.esp+8].int32_t.concrete
	print "LocalAlloc(uFlag=0x%08x, uBytes=0x%08x)" % (uFlag, uBytes)
	state.memory.store( 0x20000000, state.solver.BVV("\x00"*uBytes, uBytes*8) )
	state.regs.eax = 0x20000000
	state.regs.eip = state.mem[state.regs.esp].int32_t.concrete
	state.regs.esp = state.se.eval(state.regs.esp)-12
	print "eax=0x%08x, ret=0x%08x" % ( state.se.eval(state.regs.eax), state.se.eval(state.regs.eip) )
'''

#project = angr.load_shellcode("\x00".encode(), 'i686', start_offset=0, load_address=0, support_selfmodifying_code=True)
project = angr.load_shellcode("\x00".encode(), 'x86_64', start_offset=0, load_address=0, support_selfmodifying_code=True)
symbolic_execute()
