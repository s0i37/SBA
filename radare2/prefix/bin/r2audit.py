#!/usr/bin/python
import r2pipe
import angr
import io
import pydot

r2 = r2pipe.open()
func_start = int( r2.cmd('?v $FB'), 16 )
func_end = int( r2.cmd('?v $FE'), 16 )
func_code = ''.join( map( lambda b: chr(b), r2.cmdj("pcj $FS") ) )

proj = angr.Project( io.BytesIO(func_code),
					load_options={'auto_load_libs': False,
					 				"main_opts": {
					 					'backend': 'blob',
					 					'custom_base_addr': func_start,
					 					'custom_arch': 'x86'
					 				} 
					 			} 
					 )
state = proj.factory.entry_state(mode='symbolic', add_options={
													#angr.options.CGC_ZERO_FILL_UNCONSTRAINED_MEMORY,
                                            		#angr.options.CONSTRAINT_TRACKING_IN_SOLVER,
                                            		#"SYMBOLIC_WRITE_ADDRESSES",
                                            		angr.options.SYMBOLIC_INITIAL_VALUES,
                                            		#angr.options.LAZY_SOLVES,
                                            		#angr.options.UNICORN,
                                            		#"BYPASS_UNSUPPORTED_SYSCALL",
                                            		"CALLLESS"
                                            	})

def on_exec(state):
	print "[exec] 0x%x" % state.scratch.ins_addr

def on_memread(state):
	eip = state.scratch.ins_addr
	mem_read_addr = state.se.eval(state.inspect.mem_read_address)
	mem_read_value = state.se.eval(state.inspect.mem_read_expr)
	print "[read] 0x%x: *0x%x -> 0x%X" % ( eip, mem_read_addr, mem_read_value )

def on_memwrite(state):
	eip = state.scratch.ins_addr
	mem_write_addr = state.se.eval(state.inspect.mem_write_address)
	mem_write_value = state.se.eval(state.inspect.mem_write_expr)
	print "[write] 0x%x: *0x%x <- 0x%X" % ( eip, mem_write_addr, mem_write_value )

def on_regread(state):
	reg = state.inspect.reg_read_expr
	print "[read] %s" % reg

state.inspect.b('instruction', when=angr.BP_AFTER, action=on_exec)
#state.inspect.b('mem_read', when=angr.BP_AFTER, action=on_memread)
#state.inspect.b('mem_write', when=angr.BP_AFTER, action=on_memwrite)
#state.inspect.b('reg_read', when=angr.BP_AFTER, action=on_regread)


sym_data = state.solver.BVS('', 0x100)
state.memory.store(0x00178000, sym_data)

state.regs.esp = 0x00178000
state.regs.ebp = 0x00178000
state.regs.eip = func_start

sm = proj.factory.simgr(state, save_unconstrained=True)  # SimulationManager
sm.use_technique(angr.exploration_techniques.DFS())

covered_basic_blocks = set()

def draw_cover(covered_basic_blocks):
	graph = pydot.Dot(graph_type='graph')
	for bb in r2.cmdj("afbj"):
		fillcolor = ('green','black') if bb["addr"] in covered_basic_blocks else ('black','white')
		graph.add_node( pydot.Node( hex( bb["addr"] ), style="filled", fillcolor=fillcolor[0], fontcolor=fillcolor[1] ) )
	for bb in r2.cmdj("afbj"):
		if bb.get("fail"):
			graph.add_edge( pydot.Edge( hex( bb["addr"] ) , hex( bb["fail"] ) ) )
		if bb.get("jump"):
			graph.add_edge( pydot.Edge( hex( bb["addr"] ) , hex( bb["jump"] ) ) )
	graph.write_png('bb.png')

def discover(sm):
	alternative_paths = set()
	while sm.active and not sm.unconstrained and not sm.active[0].addr in covered_basic_blocks:
		try:
			basic_block = sm.active[0].addr
			#print "0x%x" % basic_block
			proj.factory.block(basic_block).capstone.pp()
			covered_basic_blocks.add(basic_block)
		except:
			pass
		sm.step()
		draw_cover(covered_basic_blocks)
		alternative_paths.update( sm.stashes['deferred'] )
		#print sm.stashes
	for path in alternative_paths:
		sm = proj.factory.simgr(path, save_unconstrained=True)
		sm.use_technique(angr.exploration_techniques.DFS())
		discover(sm)

discover(sm)
#import pdb; pdb.set_trace()
