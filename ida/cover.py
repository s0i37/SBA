from os import path,listdir

RED = 0x8888ff
RED_DARK = 0x000044
GREEN = 0xaaffaa
GREEN_DARK = 0x004400
CYAN = 0xdddd00
CYAN_DARK = 0x444400
BLUE = 0xffaaaa
YELLOW = 0x00ffff
GREY = 0xbbbbbb
WHITE = 0xffffff

def get_basic_block(ea):
	function = get_func(ea)
	for block in FlowChart(function):
		if block.startEA <= ea < block.endEA:
			return block

def get_coverage(coverfile):
	coverage = {}
	functions = []
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
					function = get_func(eip).startEA
					if not function in functions:
						functions.append(function)
						coverage[function] = [eip]
					bb = get_basic_block(eip)
					ea = bb.startEA
					while ea < bb.endEA:
						coverage[function].append(ea)
						ea = NextHead(ea)
			except Exception as e:
				#print str(e)
				pass
	return coverage

def rename_function(function, prefix):
	function_name = GetFunctionName(function)
	if function_name.find(prefix) != -1:
		return function_name
	function_name = "{prefix}{func}".format( prefix=prefix, func=function_name )
	MakeName( function, function_name )
	return function_name

colors = [0x300000,0x003000,0x000030,0x600000,0x006000,0x000060,0x900000,0x009000,0x000090,0xc00000,0x00c000,0x0000c0,0xf00000,0x00f000,0x0000f0]
def get_color():
	return colors.pop(0)

known_coverage = {}
def save_coverage(coverage):
	global known_coverage
	for function in coverage.keys():
		if not function in known_coverage.keys():
			known_coverage[function] = coverage[function]
		else:
			for ea in coverage[function]:
				if not ea in known_coverage[function]:
					known_coverage[function].append(ea)

root = 'Z:/var/pub/winrar_fuzz/coverages/'
coverfiles = listdir(root)
coverfiles.sort()

stats = []
cov_num = 0

for coverfile in coverfiles:
	print "[*] %s" % coverfile
	new_funcs = 0
	new_insts = 0
	color = get_color()
	new_coverage = get_coverage(path.join(root,coverfile))
	for function in new_coverage.keys():
		if not function in known_coverage.keys():
			if known_coverage:
				print "[+] function 0x%x" % function
				rename_function(function, 'new%d_'%cov_num)
				new_funcs += 1
			else:
				rename_function(function, 'cov_')
		for ea in new_coverage[function]:
			if not ea in known_coverage.get(function,[]):
				if known_coverage:
					print "[+] 0x%x" % ea
					new_insts += 1
				SetColor(ea, CIC_ITEM, color)
	save_coverage(new_coverage)
	cov_num += 1
	stats.append( "%s: new %d functions, new %d instructions" % (coverfile, new_funcs, new_insts) )

for stat in stats:
	print stat
