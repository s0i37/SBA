def get_basic_block(ea):
	function = get_func(ea)
	for block in FlowChart(function):
		if block.startEA <= ea < block.endEA:
			return block

def gen_called_functions(coverfile):
	function_names = set()
	module_id = None
	with open(coverfile) as f:
		for line in f:
			try:
				if line.startswith(' '):
					if line.find('WinRAR.exe') != -1:
						module_id = line.split(', ')[0].strip()
				elif line.startswith('module') and line.find(' %s]'%module_id) != -1:
					parts = filter( lambda p: p!= '', line.split(' ') )
					eip = int( parts[2][:-1], 16)
					
					bb = get_basic_block(eip)
					ea = bb.startEA
					while ea < bb.endEA:
						for addr in CodeRefsFrom(ea,flow=0):
							if SegName(addr) == '.idata':
								function_names.add( GetDisasm(addr) )
						ea = NextHead(ea)
			except Exception as e:
				print str(e)
				pass
	return function_names

for call in gen_called_functions(AskFile(0, "*", "specify drcov file")):
	print call
