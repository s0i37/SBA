import angr
from capstone import *
from capstone.x86 import *
import io
import os
from struct import unpack

def load_memory( state, dump_dir = './memory/' ):
	for dumpfile in os.listdir(dump_dir):
		try:
			low = int(dumpfile, 16)
			with open( os.path.join(dump_dir, dumpfile), "rb") as d:
				memory = d.read()
				print "[*] loading 0x%08x - 0x%08x" % ( low, low + len(memory) )
				state.memory.store( low, state.solver.BVV( memory, len(memory)*8 ) )
		except Exception as e:
			print str(e)
			break
		
def mem_read(state):
	print "[read] 0x%x: *0x%x -> 0x%X" % ( state.se.eval(state.regs.eip), state.se.eval(state.inspect.mem_read_address), state.se.eval(state.inspect.mem_read_expr) )
	if 0 and state.se.eval(state.regs.eip) in (0x40067d, 0x40068b):
		_state = state.copy()
		_state.add_constraints( _state.inspect.mem_read_address == 0x4000 )
		if _state.satisfiable():
			print 'satisfiable'
			print _state.se.eval( sym_data, cast_to=str ).encode('hex')
		else:
			print 'non-satisfiable'

def mem_write(state):
	print "[write] 0x%x: *0x%x <- 0x%X" % ( state.se.eval(state.regs.eip), state.se.eval(state.inspect.mem_write_address), state.se.eval(state.inspect.mem_write_expr) )

def _exec(state):
	print "[exec] 0x%x" % state.se.eval( state.regs.eip )

md = Cs(CS_ARCH_X86, CS_MODE_32)

proj = angr.Project( io.BytesIO("\x90\x90\x90\x90"),
					load_options={'auto_load_libs': False,
					 				"main_opts": {
					 					'backend': 'blob',
					 					'custom_base_addr': 0x13e0000,
					 					'custom_arch': 'x86'
					 				} 
					 			} 
					 )
state = proj.factory.entry_state(mode='symbolic', add_options={
													angr.options.CGC_ZERO_FILL_UNCONSTRAINED_MEMORY,
                                            		angr.options.CONSTRAINT_TRACKING_IN_SOLVER,
                                            		"SYMBOLIC_WRITE_ADDRESSES",
                                            		angr.options.LAZY_SOLVES,
                                            		#"BYPASS_UNSUPPORTED_SYSCALL"
                                            	})

load_memory(state)
sym_data = state.solver.BVS('A'*0x40, 0x40)
state.memory.store(0x014a5fc0, sym_data)

state.regs.eax = 0x0000003a
state.regs.ecx = 0x014a5fc0
state.regs.edx = 0x02bf4fb0
state.regs.ebx = 0x02d12ff8
state.regs.esp = 0x0332fed8
state.regs.ebp = 0x75bf18aa
state.regs.esi = 0x00000000
state.regs.edi = 0x00000120
state.regs.eip = 0x00405f19
state.regs.eflags = 0x00000246

#state.inspect.b('mem_read', when=angr.BP_AFTER, action=mem_read)
#state.inspect.b('mem_write', when=angr.BP_AFTER, action=mem_write)
state.inspect.b('instruction', when=angr.BP_AFTER, action=_exec)

sm = proj.factory.simgr(state, save_unconstrained=True)

#print state.memory.load( 0x00405f19, 10 )

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

#@proj.hook(0x777172a0)
#def EnterCriticalSection(state):
#	pass

def discover_path(sm):
	i = 1
	branches = []
	basic_blocks = set()
	try:
		while sm.active and not sm.unconstrained:
		#while len(sm.unconstrained)==0:
			print "step: %d" % i
			sm.step()
			#import pdb; pdb.set_trace()
			print sm.active
			for path in sm.active:
				if not path.addr in basic_blocks:
					branches.append(path)					# state
					basic_blocks.add(path.addr)
			i += 1
	except Exception as e:
		print str(e)
	return branches

branches = discover_path(sm)
print "deep %d" % len(branches)

for branch in branches:
	print "branch 0x%x:" % branch.addr,
	if branch.satisfiable():
		print "satisfiable"
		print branch.se.eval(sym_data, cast_to=str).encode('hex')
	else:
		print "unsatisfable"
