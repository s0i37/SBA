#!/usr/bin/python
import r2pipe
from sys import argv
try:
	pydot = __import__('pydot')
	import os
except:
	pydot = False

r2 = r2pipe.open()
known_subs = set()
MAX_DEEP = int( argv[1] ) if len(argv) > 1 else 0xffffffff
if pydot:
	graph = pydot.Dot(graph_type='digraph')

def get_node_color(sub):
	if sub.find('imp.') != -1:
		return 'yellow','black'
	elif sub.find('sym.') != -1:
		return 'green','black'
	else:
		return 'black','white'

def subs_walk(sub, deep):
	subs = set()
	for xref in r2.cmdj( "afxj @ {sub}".format(sub=sub) ):
		if xref["type"] == "call":
			addr = xref["to"]
			_sub = r2.cmd( "afn @ {addr}".format(addr=addr) ).split('\n')[0] or r2.cmd( "fd @ {addr}".format(addr=addr) ) or "0x%08x" % addr
			if sub == _sub:
				continue
			subs.add( _sub )

	for _sub in subs:
		print "%s%s" % (" "*deep, _sub)
		if pydot:
			r2.cmd( "agn {sub}".format( sub=_sub ) )
			graph.add_node( pydot.Node( _sub, style="filled", fillcolor=get_node_color(_sub)[0], fontcolor=get_node_color(_sub)[1] ) )
			r2.cmd( "age {sub1} {sub2}".format( sub1=sub, sub2=_sub ) )
			graph.add_edge( pydot.Edge(sub, _sub) )
		if _sub in known_subs or deep >= MAX_DEEP:
			continue
		known_subs.add(_sub)
		subs_walk(_sub, deep+1)

current_sub = r2.cmd("afn").split('\n')[0]
r2.cmd("ag-")
r2.cmd( "agn {sub}".format( sub=current_sub ) )
if pydot:
	graph.add_node( pydot.Node( current_sub, style="filled", fillcolor=get_node_color(current_sub)[0], fontcolor=get_node_color(current_sub)[1] ) )
print current_sub
subs_walk(current_sub, 1)

if pydot:
	graph.write_dot('xrefs_from_%s.dot' % current_sub)
	os.system('xdot xrefs_from_%s.dot &' % current_sub)
