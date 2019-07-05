#!/usr/bin/python3
import angr
from sys import argv
import logging
logging.getLogger('angr').setLevel('CRITICAL')


corefile = argv[1]
project = angr.Project(corefile, load_options={'main_opts': {'backend': 'elfcore'} } )
state = project.factory.entry_state()
#import pdb;pdb.set_trace()

state.regs.rax=            0x7fffffffe2c2
state.regs.rbx=            0x0
state.regs.rcx=            0x7ffff7f7ba00
state.regs.rdx=            0x7ffff7f7d8d0
state.regs.rsi=            0x4141414141414141
state.regs.rdi=            0x7fffffffe2c3
state.regs.rbp=            0x7fffffffe2d0
state.regs.rsp=            0x7fffffffe2c0
state.regs.r8 =            0x55555555926a
state.regs.r9 =            0x0
state.regs.r10=            0x7ffff7f82500
state.regs.r11=            0x246
state.regs.r12=            0x555555555060
state.regs.r13=            0x7fffffffe3b0
state.regs.r14=            0x0
state.regs.r15=            0x0
state.regs.rip=            0x55555555522f
sym_data = state.solver.BVS('', 8*10)
state.memory.store(0x00007fffffffe2c2, sym_data)

sm = project.factory.simgr(state, save_unconstrained=True)  # SimState -> SimulationManager
#sm.use_technique(angr.exploration_techniques.DFS())

basic_blocks = set()

while sm.active and not sm.unconstrained:
	sm.step()
	if sm.one_active.addr > 0x555555558fff:
		break
	print( "[*] 0x%x %s" % ( sm.one_active.addr, str(sm.stashes['active']) ) )
	for path in sm.active: 		# for SimState in SimulationManager
		if not path.addr in basic_blocks:
			basic_blocks.add(path.addr)
			if path.satisfiable():
				input_data = path.se.eval( sym_data, cast_to=bytes )#.hex()
				print( "[+] 0x%x %s" % (path.addr, input_data.decode()) )
	#input()
