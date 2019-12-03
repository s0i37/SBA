#!/usr/bin/python3
import angr
from sys import argv
from os import listdir,stat,path
import logging
logging.getLogger('angr').setLevel('CRITICAL')


memory_map = []
memory_dir = argv[1]

def is_memory_loaded(addr):
	global memory_map
	for page in memory_map:
		if page[0] <= addr < page[1]:
			return True
	return False

def get_perm_code(perm_str):
	code = 0
	if perm_str.find('r') != -1:
		code += 4
	if perm_str.find('w') != -1:
		code += 2
	if perm_str.find('x') != -1:
		code += 1
	return code

def load_page(addr):
	global memory_map, memory_dir
	for page in listdir(memory_dir):
		page_addr = int( page.split("=")[0], 16 )
		page_perm = page.split("=")[1]
		page_size = stat( path.join(memory_dir, page) ).st_size
		if page_addr <= addr < page_addr+page_size:
			memory_map.append( (page_addr, page_addr+page_size) )
			memory = open(path.join(memory_dir, page), "rb").read()
			state.memory.store(page_addr, memory, disable_actions=True, inspect=False)
			state.memory.permissions( page_addr, get_perm_code(page_perm) )
			print( "[*] {vaddr} {page}".format(vaddr=hex(addr), page=page) )
			break

def taint_mem(loader, rip, mem_addr, mem_size):
	mem = loader(mem_addr, mem_size, disable_actions=True, inspect=False)
	mem_addr = state.se.eval(mem_addr)
	if mem.symbolic:
		print( "[taint] 0x%x: 0x%x = %s" % (rip, mem_addr, str(mem)) )

def taint_reg(loader, rip, reg_name, reg_value):
	#reg = loader(reg_value, disable_actions=True, inspect=False)
	if reg_value.symbolic:
		print( "[taint] 0x%x: %s" % (rip, reg_name) )


def mem_read_before(state):
	addr = state.se.eval(state.inspect.mem_read_address)
	if not is_memory_loaded(addr):
		load_page(addr)

def mem_write_before(state):
	addr = state.se.eval(state.inspect.mem_write_address)
	if not is_memory_loaded(addr):
		load_page(addr)

def mem_read_after(state):
	exec_addr = state.scratch.ins_addr
	mem_addr = state.se.eval(state.inspect.mem_read_address)
	mem_value = state.se.eval(state.inspect.mem_read_expr)
	mem_size = state.inspect.mem_read_length
	print( "[read] 0x%x: *0x%x -> %X" % (exec_addr, mem_addr, mem_value ) )
	taint_mem(state.memory.load, exec_addr, state.inspect.mem_read_address, mem_size)

def mem_write_after(state):
	exec_addr = state.scratch.ins_addr
	mem_addr = state.se.eval(state.inspect.mem_write_address)
	mem_value = state.se.eval(state.inspect.mem_write_expr)
	mem_size = state.inspect.mem_write_length
	print( "[write] 0x%x: *0x%x <- %X" % (exec_addr, mem_addr, mem_value ) )
	taint_mem(state.memory.load, exec_addr, state.inspect.mem_write_address, mem_size)

def reg_read_after(state):
	exec_addr = state.scratch.ins_addr
	reg_name = project.arch.register_names[state.inspect.reg_read_offset]
	reg_value = state.se.eval(state.inspect.reg_read_expr)
	reg_size = state.inspect.reg_read_length
	print( "[read] 0x%x: %s=%X" % (exec_addr, reg_name, reg_value) )
	taint_reg(state.registers.load, exec_addr, reg_name, state.inspect.reg_read_expr)

def reg_write_after(state):
	exec_addr = state.scratch.ins_addr
	reg_name = project.arch.register_names[state.inspect.reg_write_offset]
	reg_value = state.se.eval(state.inspect.reg_write_expr)
	reg_size = state.inspect.reg_write_length
	print( "[write] 0x%x: %s=%X" % (exec_addr, reg_name, reg_value) )
	taint_reg(state.registers.load, exec_addr, reg_name, state.inspect.reg_write_expr)

def _exec(state):
	exec_addr = state.scratch.ins_addr
	print( "[exec] 0x%x" % exec_addr )
	'''
	if exec_addr == 0x555555555151:
		print( state.memory.load(0x7fffffffe1cf,1) )
	elif exec_addr == 0x55555555521d:
		print( state.memory.load(0x7fffffffe1cf,1) )
	'''

#project = angr.load_shellcode("\x00".encode(), 'i686', start_offset=0, load_address=0)
project = angr.load_shellcode("\x00".encode(), 'x86_64', start_offset=0, load_address=0)
state = project.factory.entry_state(mode='symbolic')

state.inspect.b('mem_read', when=angr.BP_BEFORE, action=mem_read_before)
state.inspect.b('mem_read', when=angr.BP_AFTER, action=mem_read_after)
state.inspect.b('mem_write', when=angr.BP_BEFORE, action=mem_write_before)
state.inspect.b('mem_write', when=angr.BP_AFTER, action=mem_write_after)
state.inspect.b('reg_read', when=angr.BP_AFTER, action=reg_read_after)
state.inspect.b('reg_write', when=angr.BP_AFTER, action=reg_write_after)
state.inspect.b('instruction', when=angr.BP_AFTER, action=_exec)

load_page(0x555555555000)
load_page(0x7ffffffde000)
load_page(0x555555558000)

state.regs.rax = 0x7fffffffe1e2
state.regs.rbx = 0x00000000
state.regs.rcx = 0x7ffff7f8da00
state.regs.rdx = 0x7ffff7f90590
state.regs.rsi = 0x6f69757974726577
state.regs.rdi = 0x7fffffffe1e2
state.regs.r8 = 0x7fffffffe1e2
state.regs.r9 = 0x00000000
state.regs.r10 = 0x00000410
state.regs.r11 = 0x00000246
state.regs.r12 = 0x555555555060
state.regs.r13 = 0x7fffffffe2d0
state.regs.r14 = 0x00000000
state.regs.r15 = 0x00000000
state.regs.rip = 0x555555555149
state.regs.rbp = 0x7fffffffe1d0
state.regs.rflags = 0x3278302b00000246
state.regs.rsp = 0x7fffffffe1d0
sym_data = state.solver.BVS('input', 8*9)
state.memory.store(0x7fffffffe1e2, sym_data, disable_actions=True, inspect=False)

sm = project.factory.simgr(state, save_unconstrained=True)  # SimState -> SimulationManager
#sm.use_technique(angr.exploration_techniques.DFS()) 	# deep search

basic_blocks = set()


while sm.active and not sm.unconstrained:
	sm.step() # basic block exec
	if sm.active and 0x555555555000 > sm.active[0].addr > 0x555555556000:
		break
	#continue
	#print( "[*] 0x%x %s" % ( sm.active[0].addr, str(sm.stashes['active']) ) )
	for path in sm.active: 		# for SimState in SimulationManager
		if not path.addr in basic_blocks: # anti-loop
			basic_blocks.add(path.addr)
			if path.satisfiable():
				input_data = path.se.eval(sym_data, cast_to=bytes)
				print( "[+] 0x%x %s" % (path.addr, input_data) )

print("covered basic blocks:")
for basic_block in basic_blocks:
	print("0x%x" % basic_block)
