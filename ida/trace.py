RED = 0x8888ff
GREEN = 0xaaffaa
GREEN_DARK = 0x22aa22
CYAN = 0xdddd00
BLUE = 0xffaaaa
YELLOW = 0x00ffff
GREY = 0xbbbbbb
WHITE = 0xffffff

TRACE1 = 'z:/root/trace-crash.txt'
TRACE2 = 'z:/root/trace-norm.txt'

def colorize_trace(addrs_file, color, prefix=''):
	function_names = []
	commented = set()
	instructions = set()
	with open( addrs_file, "rb") as f:
		for line in f:
			try:
				eip = int( line.split(':')[1], 16)
				#comment = line.split(';')[1].strip()
				comment = None

				function_name = GetFunctionName(eip)
				if not function_name in function_names:
					function_names.append(function_name)
				SetColor( eip, CIC_ITEM, color )
				
				if comment:
					if not eip in commented:
						set_cmt( eip, comment, 0 )
						commented.add(eip)
					else:
						#set_cmt( eip, GetCommentEx(eip, 0) + '\n' + comment, 0 )
						pass
				instructions.add(eip)
			except Exception as e:
				#print str(e)
				pass

	if prefix:
		num = 0
		new_function_names = []
		for function_name in function_names:
			try:
				new_function_name = "{prefix}_{num}_{func}".format( prefix=prefix, num=num, func=function_name )
				MakeName( LocByName(function_name), new_function_name )
				new_function_names.append(new_function_name)
			except:
				pass
			num += 1
		function_names = new_function_names

	return instructions

def print_diff_trace(trace1, trace2):
	functions_diff = set()
	print 'diff instr:'
	for instr in trace1-trace2:
		print hex(instr)
		functions_diff.add( GetFunctionName(instr) )

	print 'diff functions:'
	for function_diff in functions_diff:
		print function_diff


#colorize_trace( TRACE, color=GREEN, prefix='cov_' )
trace1 = colorize_trace( TRACE1, color=RED )
trace2 = colorize_trace( TRACE2, color=GREEN )
print_diff_trace(trace1, trace2)

