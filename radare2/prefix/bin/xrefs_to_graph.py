#!/usr/bin/python
import r2pipe
try:
	pydot = __import__('pydot')
	import os
except:
	pydot = False

subs = range(100)
r2 = r2pipe.open()

if pydot:
	graph = pydot.Dot(graph_type='graph')

def get_node_color(sub):
	if sub.find('imp.') != -1:
		return 'yellow','black'
	elif sub.find('sym.') != -1:
		return 'green','black'
	else:
		return 'black','white'

def subs_walk(sub, deep):
	for xref in r2.cmdj( 'axtj {sub}'.format(sub=sub) ):
		if xref["type"] == "call":
			addr = xref["fcn_addr"]
			_sub = xref["fcn_name"]
			subs[deep] = (sub,addr)
			print "%s%s" % (" "*deep, _sub)
			if graph:
				graph.add_edge( pydot.Edge( sub, _sub ) )
				graph.add_node( pydot.Node( _sub, style="filled", fillcolor=get_node_color(_sub)[0], fontcolor=get_node_color(_sub)[1] ) )
			subs_walk(_sub, deep+1)

sub = r2.cmd('afn')
print sub
subs_walk(sub, 1)

if graph:
	graph.write_png('xrefs_to_graph.png')
	os.system('xdg-open xrefs_to_graph.png 1> /dev/null 2> /dev/null')
	os.unlink('xrefs_to_graph.png')