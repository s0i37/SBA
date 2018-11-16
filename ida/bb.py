from os.path import abspath,dirname
from pickle import dumps,loads

#if IDA
try:
	from idaapi import *
	from idautils import *
	from idc import *
	EA = ScreenEA()
	is_ida = True
except:
	EA=0
	is_ida = False

if not 'functions' in globals(): functions = {}
if not 'dlls' in globals(): dlls = {}
if not 'relative_addrs' in globals(): relative_addrs = {}
if not 'basic_blocks' in globals(): basic_blocks = {}
if not 'code_trace' in globals(): code_trace = {}
if not 'breakpoints' in globals(): breakpoints = []
if not 'processed_breakpoints' in globals(): processed_breakpoints = set()
if not 'old_breakpoints' in globals(): old_breakpoints = []
if not 'hook' in globals(): hook = ''
if not 'i' in globals(): i = 0
code_coverage_tag = ''
cwd = dirname( abspath( __file__ ) )

class DbgHook(DBG_Hooks):
	def __init__(self):
		DBG_Hooks.__init__(self)
	def dbg_process_start(self, pid, tid, ea, name, base, size):
		return
	def dbg_process_exit(self, pid, tid, ea, code):
		return
	def dbg_library_load(self, pid, tid, ea, name, base, size):
		return
	def dbg_bpt(self, tid, ea):
		global functions, processed_breakpoints, code_coverage_tag, basic_blocks, code_trace, i
		
		#functions[ ea ]['contexts'].append( { 'eax': GetRegValue('EAX') } )
		
		#processed_breakpoints.add( ea )
		#set_suffix_function( ea, code_coverage_tag )
		#del_bpx( ea )
		
		#highlight_bb(ea, functions[ea]['end_ea'], 0x00FF00)
		#highlight_ea(ea, 0x00FF00)
		i += 1
		for function,bb in basic_blocks.items():
			if ea in bb:
				break
		if len( code_trace[function] ) == 1:
			if ea == function and code_trace[function][0] != {}:
				code_trace[function].append( {} )
			else:
				code_trace[function][0].update( { ea: (GetRegValue('EAX'),GetRegValue('ECX'),GetRegValue('EDX'),GetRegValue('EBX'),GetRegValue('EBP'),GetRegValue('ESP'),GetRegValue('ESI'),GetRegValue('EDI')) } )
		if len( code_trace[function] ) == 2:
			if ea == function:
				code_trace[function][1] = {}
			code_trace[function][1].update( { ea: (GetRegValue('EAX'),GetRegValue('ECX'),GetRegValue('EDX'),GetRegValue('EBX'),GetRegValue('EBP'),GetRegValue('ESP'),GetRegValue('ESI'),GetRegValue('EDI')) } )
		print "int 3 0x%08x" % ( ea )
		return


#export
def save_file( data={}, filename='' ):
	if not filename:
		filename = '%s_BB.db' % ( GetFunctionName(EA) )
	file_path = '%s/../%s' % ( cwd, filename )
	with open(file_path, 'wb') as f:
		f.write( dumps(data) )
	print "saved into %s" % file_path
	return file_path

def get_segment( ea=EA ):
	addr = FirstSeg()
	if SegStart(addr) <= ea <= SegEnd(addr):
		return { 'start': SegStart(addr), 'end': SegEnd(addr) }
	while True:
		addr = NextSeg(addr)
		#print SegName(addr).lower()
		if addr == BADADDR:
			break
		if SegStart(addr) <= ea <= SegEnd(addr):
			return { 'start': SegStart(addr), 'end': SegEnd(addr) }

def get_modules():
	addr = GetFirstModule()
	i = 100
	modules = {}
	while addr and i > 0:
		i -= 1
		modules[ GetModuleName(addr).lower() ] = { 'start': int(addr), 'end': int(addr+GetModuleSize(addr)) }
		addr = GetNextModule(addr)
	return modules
dlls = get_modules()

def prompt( text='', default='' ):
	return idc.AskStr(default, text)

def get_function( ea=EA ):
	return get_func(ea).startEA

def get_function_name( ea=EA ):
	return GetFunctionName(ea)

def rename_function( ea=EA, name='' ):
	MakeName( get_function(ea), name )

def set_suffix_function( ea=EA, suffix='' ):
	MakeName( get_function(ea), 'SUB' + get_function_name(ea)[3:] + suffix )

def get_subs( segment={} ):
	functions = {}
	for sub in Functions( segment['start'], segment['end'] ):
		functions[ sub ] = { 'contexts': [] }
	return functions

def get_bb( ea=EA ):
	basic_blocks = {}
	try:
		for bb in FlowChart( get_func(ea) ):
			basic_blocks[ bb.startEA ] = { 'start_ea': bb.startEA, 'end_ea': bb.endEA, 'contexts': [] }
	except:
		pass
	return basic_blocks

def get_basic_blocks( relative_addrs={} ):
	# relative_addrs = { 0x400000: set( 0x401000, 0x401050, ), }
	basic_blocks = {}
	print 'NOTICE: ' + ', '.join( relative_addrs.keys() ) + ' need ANALYZE MODULE!'
	for dll_name,functions in relative_addrs.items():
		dll_base = dlls[ dll_name.lower() ]['start']
		for function in functions:
			function_addr = get_function( dll_base+function )
			print dll_name + ' ' + hex( function_addr )
			for bb in get_bb( function_addr ):
				try:	basic_blocks[ function_addr ].add( bb )
				except:	basic_blocks.update( { function_addr : set([ bb ]) } )
	return basic_blocks
	# basic_blocks = { 0x401000: set( 0x401005, 0x40100a, ), }

#processing (pydbg)
def on_bp(dbg):
	global basic_blocks
	eax, ecx, edx, ebx = dbg.context.Eax, dbg.context.Ecx, dbg.context.Edx, dbg.context.Ebx
	esi, edi, esp, ebp = dbg.context.Esi, dbg.context.Edi, dbg.context.Ebp, dbg.context.Esp
	try:	basic_blocks[ dbg.context.Eip ]['contexts'].append( {'eax':eax, 'ecx':ecx, 'edx':edx, 'ebx': ebx, \
												'esi':esi, 'edi':edi, 'ebp': ebp, 'esp':esp} )
	except:	pass

#processing (ida)
def set_bpx(addr):
	add_bpt(addr, 1, BPT_SOFT)
	SetBptAttr(addr, BPTATTR_FLAGS, BPT_ENABLED)

def del_bpx(addr):
	print 'del bpx 0x%08x' % addr
	del_bpt(addr)

def set_bpx_on_basic_blocks( basic_blocks={} ):
	# basic_blocks = { 0x401000: set( 0x401005, 0x40100a, ), }
	count = 0
	for _,bbs in basic_blocks.items():
		for bb in bbs:
			set_bpx( bb )
			count += 1
	return count

#import
def load_file( file ):
	obj = object()
	with open( file, 'rb' ) as f:
		obj = loads( f.read() )
	return obj

def highlight_ea( ea, color ):
	SetColor(ea, CIC_ITEM, color)

def highlight_bb( start_ea, end_ea, color ):
	for ea in range( start_ea, end_ea ):
		SetColor(ea, CIC_ITEM, color)

def paint_code_trace( code_trace={} ):
	for (function,contexts) in code_trace.items():
		bb = get_bb( function )
		for (basic_block, context) in contexts[0].items():
			highlight_bb( bb[ basic_block ]['start_ea'], bb[ basic_block ]['end_ea'], 0x00FF00 )

#save_file( relative_addrs, 'backtrace_ie_mshtml.db' )
if is_ida:
	#file_path = save_file( get_bb() )
	#save_file( get_subs( get_segment() ), 'bws_func.db' )
	
	'''
	for (dll,addr_range) in dlls.items():
		if addr_range['start'] <= EA <= addr_range['end']:
			try:	relative_addrs[ dll ].add( get_function() - addr_range['start'] )
			except:	relative_addrs[ dll ] = set([ get_function() - addr_range['start'] ])
			break
	print relative_addrs
	'''
	'''
	relative_addrs = load_file('/users/soier/desktop/backtrace_ie_mshtml.db')
	basic_blocks = get_basic_blocks( relative_addrs )
	print 'set %d bpx' % set_bpx_on_basic_blocks( basic_blocks )
	code_trace = { func: list([ {} ]) for func in basic_blocks.keys() }
	print basic_blocks
	print code_trace
	'''
	'''
	code_coverage_tag = prompt( 'specify function coverage tag', '___always_call' )
	limit = int( prompt( 'max bpx', '2000' ) )
	#basic_blocks = get_bb()
	functions = get_subs( get_segment() )
	breakpoints = functions.keys()
	if limit >= 0:
		breakpoints = list(set(breakpoints) - set(old_breakpoints))[:limit]
		old_breakpoints += breakpoints
	else:
		old_breakpoints = []
	bpx_count = 0
	for ea in set(breakpoints) - processed_breakpoints:
		set_bpx( ea )
		bpx_count+=1
	print 'bpx count: %d' % bpx_count
	'''
	'''
	if hook:
		hook.unhook()
	hook = DbgHook()
	hook.hook()
	'''
paint_code_trace( code_trace )

if old_breakpoints:
	print 'old breakpoints %d' % len( old_breakpoints )
if processed_breakpoints:
	print 'processed breakpoints %d' % len( processed_breakpoints )