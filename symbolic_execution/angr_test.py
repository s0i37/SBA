import angr
from sys import argv

from capstone import *
from capstone.x86 import *

md = Cs(CS_ARCH_X86, CS_MODE_64)

binary = argv[1]
#https://github.com/axt/angr-utils/blob/master/angrutils/pp.py

def dump_mem(state, addr, size):
	step = 16
	for addr in xrange(addr, addr+size, step):
		print "0x%x  :" % addr,
		bytes_symbolic = state.memory.load( addr, step )
		bytes = state.se.eval(bytes_symbolic, cast_to=str)
		for byte in bytes:
			print "%02X" % ord(byte),
		print ""

def dump_regs(state):
	print "RAX: %016X" % state.regs.rax.args[0]
	print "RCX: %016X" % state.se.eval( state.regs.rcx )
	print "RDX: %016X" % state.se.eval( state.regs.rdx )
	print "RBX: %016X" % state.se.eval( state.regs.rbx )
	print "RBP: %016X" % state.se.eval( state.regs.rbp )
	print "RSP: %016X" % state.se.eval( state.regs.rsp )
	print "RSI: %016X" % state.se.eval( state.regs.rsi )
	print "RDI: %016X" % state.se.eval( state.regs.rdi )
	print "RIP: %016X" % state.se.eval( state.regs.rip )

def disas(state):
	rip = state.se.eval( state.regs.rip )
	bytes_symbolic = state.memory.load( rip, 20 )
	bytes = state.se.eval(bytes_symbolic, cast_to=str)
	for instr in md.disasm( bytes, rip ):
		print "0x%x: %s %s" % (instr.address, instr.mnemonic, instr.op_str)
		break

def mem_read(state):
	print "[read] 0x%x: *0x%x -> 0x%X" % ( state.se.eval(state.regs.rip), state.se.eval(state.inspect.mem_read_address), state.se.eval(state.inspect.mem_read_expr) )
	if 1 and state.se.eval(state.regs.rip) in (0x40067d, 0x40068b):
		_state = state.copy()
		_state.add_constraints( _state.inspect.mem_read_address == 0x4000 )
		if _state.satisfiable():
			print 'read by 0x4000 satisfiable'
			print _state.se.eval( sym_data, cast_to=str ).encode('hex')
		else:
			print 'read by 0x4000 non-satisfiable'

def mem_write(state):
	print "[write] 0x%x: *0x%x <- 0x%X" % ( state.se.eval(state.regs.rip), state.se.eval(state.inspect.mem_write_address), state.se.eval(state.inspect.mem_write_expr) )

def _exec(state):
	print "[exec] 0x%x" % state.se.eval( state.regs.rip )
	#dump_regs(state)
	#disas(state)

def step(sm):
	print "[step] %s" % str( sm )

def correct(state):
		return 0x400675 == state.se.eval( state.regs.rip )

def wrong(state):
	 	return state.se.eval( state.regs.rip ) >= 0x40068e

project = angr.Project(binary, load_options={'auto_load_libs':False, 'main_opts': {'custom_base_addr':0x400000, 'custom_arch': 'x64'} } )
#state = project.factory.blank_state(addr=0x400660)
#path = project.factory.path(state)
#pg = project.factory.path_group(save_unconstrained=True)  # SimulationManager

#state = project.factory.blank_state(addr=0x400660, add_options={angr.options.CGC_ZERO_FILL_UNCONSTRAINED_MEMORY,
#                                                  angr.options.CONSTRAINT_TRACKING_IN_SOLVER })  # SimState

state = project.factory.entry_state( mode='symbolic', add_options={
													angr.options.CGC_ZERO_FILL_UNCONSTRAINED_MEMORY,
                                            		angr.options.CONSTRAINT_TRACKING_IN_SOLVER,
                                            		"SYMBOLIC_WRITE_ADDRESSES",
                                            		angr.options.LAZY_SOLVES
                                            	}
                                    )


#state.inspect.b('mem_read', when=angr.BP_AFTER, action=angr.BP_IPYTHON)
#state.inspect.b('mem_write', when=angr.BP_AFTER, action=mem_write)
state.inspect.b('instruction', when=angr.BP_AFTER, action=_exec)

#state.mem[0x1000].uint64_t = state.regs.rdx
#state.mem[0x1000].uint32_t = 0x41414141
#state.stack_push( state.se.BVS('int{}'.format(i), 4*8) )

sym_data = state.solver.BVS('', 128)  # symbolic data
#sym_data = state.solver.BVV(0x1337133789abcdef0123456789abcdef, 128)  # const
#state.memory.store( 0x5100, state.solver.BVV( "aaaa", 4*8 ) )
state.memory.store( 0x4000, sym_data )
#state.stack_push(sym_data)
state.mem[0x5100].uint64_t = 0xFFFFFFFFFFFFFFFF    # like a BVV
state.regs.rdi = 0x4000
state.regs.rsp = 0x5100
state.regs.rip = 0x4006b0

#proj.factory.block(0x0804873c).capstone.pp()
#proj.factory.block(0x0804873c).vex.pp()

sm = project.factory.simgr(state, save_unconstrained=True)  # SimulationManager
sm.use_technique(angr.exploration_techniques.DFS())
'''
#sm.explore( step_func=step )
sm.explore( find=0x400675, avoid=0x400688 )
#sm.explore( find=lambda st: st.se.eval(st.regs.rip) == 0x400675 )

print sm.stashes['found'][0].se.eval( sym_data, cast_to=str ).encode('hex')
#dump_mem( sm.stashes['found'][0] , 0x4000, 0x50 )
'''

@project.hook(0x400560)
def puts(state):
	state.regs.rip = state.mem[state.regs.rsp].int64_t.concrete
	arg0 = state.se.eval(state.regs.rdi)
	print "puts(0x%lx)" % arg0

i = 1
branches = []
basic_blocks = set()
#sm.run()
while sm.active and not sm.unconstrained:
#while len(sm.unconstrained)==0:
	print "step: %d" % i
	sm.step()
	print sm.stashes['active']
	for path in sm.active:
		if 0x4006b0 <= path.addr <= 0x4006f0:
			if not path.addr in basic_blocks:
				branches.append(path)					# state
				basic_blocks.add(path.addr)
	i += 1

for branch in branches:
	print "branch 0x%x:" % branch.addr
	if branch.satisfiable():
		print branch.se.eval( sym_data, cast_to=str ).encode('hex')


#s1 = sm.active[0]
#if s1.satisfiable():
#	dump_mem( s1, 0x4000, 0x40 )

#print sm.active
#print sm.unconstrained
#print sm.deadended
#print sm.errored
#print sm.found