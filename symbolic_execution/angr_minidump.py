#!/usr/bin/python3
import angr
from sys import argv
from os import listdir,path
import logging
logging.getLogger('angr').setLevel('CRITICAL')


def get_perm_code(perm_str):
	code = 0
	if perm_str.find('r') != -1:
		code += 4
	if perm_str.find('w') != -1:
		code += 2
	if perm_str.find('x') != -1:
		code += 1
	return code

project = angr.load_shellcode("\x90".encode(), 'i686', start_offset=0, load_address=0)
state = project.factory.entry_state()

for page in listdir( argv[1] ):
	page_name,vaddr,perm = page.split('=')
	with open( path.join(argv[1], page), 'rb' ) as f:
		memory = f.read()
		print( "0x%08x: %s %dB" % (int(vaddr,16), page, len(memory)) )
		state.memory.store(int(vaddr,16), memory)
		state.memory.permissions(int(vaddr,16), get_perm_code(perm))

state.regs.eax=            0xf
state.regs.ecx=            0x2b4790
state.regs.edx=            0x0
state.regs.ebx=            0x6706cc
state.regs.esp=            0x2cbfdac
state.regs.ebp=            0x2cbfdcc
state.regs.esi=            0x2271350
state.regs.edi=            0x2cbfe58
state.regs.eip=            0x666131
sym_data = state.solver.BVS('', 8*14)
state.memory.store(0x02186848, sym_data)

sm = project.factory.simgr(state, save_unconstrained=True)  # SimState -> SimulationManager

basic_blocks = set()

while sm.active and not sm.unconstrained:
	sm.step()
	if 0x666131 > sm.one_active.addr > 0x8ec000:
		break
	print( "[*] 0x%x %s" % ( sm.one_active.addr, str(sm.stashes['active']) ) )
	for path in sm.active: 		# for SimState in SimulationManager
		if not path.addr in basic_blocks:
			basic_blocks.add(path.addr)
			if path.satisfiable():
				input_data = path.se.eval( sym_data, cast_to=bytes )#.hex()
				print( "[+] 0x%x %s" % (path.addr, input_data.decode()) )