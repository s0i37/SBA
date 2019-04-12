from os import path,environ,pathsep,listdir
import pydot
environ['PATH'] += pathsep + 'C:\\Program Files (x86)\\Graphviz2.38\\bin'

def get_external_calls(ea):
	external_calls = {}
	function = get_func(ea)
	for block in FlowChart(function):
		if block.startEA <= ea < block.endEA:
			break
	ea = block.startEA
	while ea < block.endEA:
		for addr in CodeRefsFrom(ea,flow=0):
			if SegName(addr) == '.idata':
				external_calls[ea] = GetDisasm(addr)
		ea = NextHead(ea)
	return external_calls

cover_num = 0
functions = {}
def gen_functions_flow(coverfile):
	global cover_num, functions
	module_id = None
	prev_function_name = ''
	with open(coverfile) as f:
		for line in f:
			try:
				if line.startswith(' '):
					if line.find('WinRAR.exe') != -1:
						module_id = line.split(', ')[0].strip()
				elif line.startswith('module') and line.find(' %s]'%module_id) != -1:
					parts = filter( lambda p: p!= '', line.split(' ') )
					eip = int( parts[2][:-1], 16)
					function_name = GetFunctionName(eip)
					if not function_name in functions.keys():
						functions[function_name] = []
						print function_name[:20]
						if cover_num > 0:
							colors = ("#000000","#ffffff")
						else:
							colors = ("#ffffff","#000000")
						graph.add_node( pydot.Node( str( LocByName(function_name) ), label=function_name[:20], style="filled", fillcolor=colors[0], fontcolor=colors[1] ) )
					
					if function_name != prev_function_name:
						if not prev_function_name in functions[function_name]:
							print "%s -> %s" % (function_name[:20], prev_function_name[:20])
							graph.add_edge( pydot.Edge( str( LocByName(function_name) ), str( LocByName(prev_function_name) ) ) )
							functions[function_name].append(prev_function_name)

					external_calls = get_external_calls(eip)
					for ea,call in external_calls.items():
						if not call in functions[function_name]:
							graph.add_node( pydot.Node( str(ea), label=call, style="filled", fillcolor='#FF00DC' ) )
							graph.add_edge( pydot.Edge( str( LocByName(function_name) ), str(ea) ) )
							functions[function_name].append(call)
					
					prev_function_name = function_name
			except Exception as e:
				print str(e) + function_name[:20]
				pass
	cover_num += 1

root = 'Z:/var/pub/winrar_fuzz/coverages/'
coverfiles = listdir(root)
coverfiles.sort()
graph = pydot.Dot(graph_type='digraph')

for coverfile in coverfiles:
	print coverfile
	gen_functions_flow(path.join(root,coverfile))
graph.write_dot('functions_flow.dot')
