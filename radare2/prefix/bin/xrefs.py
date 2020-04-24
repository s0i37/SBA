#!/usr/bin/python
import r2pipe
from json import dumps

WWW='''
<head>
  <style> body { margin: 0; } </style>
  <script src="https://unpkg.com/3d-force-graph"></script>
</head>
<body>
  <div id="3d-graph"></div>
  <script>
  	var xrefs = __xrefs__
    const elem = document.getElementById('3d-graph');
    const Graph = ForceGraph3D()(elem)
      .graphData(xrefs)
      .nodeAutoColorBy('color')
      .nodeLabel(node => `${node.name}`)
      .onNodeHover(node => elem.style.cursor = node ? 'pointer' : null)
      .onNodeClick(node => alert(`function ${node.id}`));
  </script>
</body>
'''
r2 = r2pipe.open()

current = r2.cmd("afn")
def get_color(name):
	if name == current:
		return 'red'
	elif name.find('imp.') != -1:
		return 'yellow'
	elif name.find('sym.') != -1:
		return 'green'
	elif name.find('sub.') != -1:
		return 'purple'
	else:
		return 'white'

i = 0
def unknown():
	global i
	i += 1
	return "unknown%d" % i

xrefs = {'nodes': [], 'links': []}
functions = set()
for xref in r2.cmdj('axj'):
	if xref['type'] == 'CALL' and xref['addr'] != 0:
		fcn_addr_from = r2.cmd('afo @%d' % xref['from'])
		name_from = r2.cmd('afn @%d' % xref['from']) or unknown()
		fcn_addr_to = r2.cmd('afo @%d' % xref['addr'])
		name_to = r2.cmd('afn @%d' % xref['addr']) or unknown()
		if fcn_addr_from and fcn_addr_to:
			if not fcn_addr_from in functions:
				functions.add(fcn_addr_from)
				xrefs['nodes'].append(
					{
				      "id": fcn_addr_from,
				      "name": name_from,
				      "description": name_from,
				      "color": get_color(name_from)
				    }
				)
			if not fcn_addr_to in functions:
				functions.add(fcn_addr_to)
				xrefs['nodes'].append(
					{
				      "id": fcn_addr_to,
				      "name": name_to,
				      "description": name_to,
				      "color": get_color(name_to)
				    }
				)
			xrefs['links'].append(
				{
			      "source": fcn_addr_from,
			      "target": fcn_addr_to,
			      "color": get_color(name_to)
			    }
			)

with open('xrefs.html', 'w') as o:
	o.write( WWW.replace('__xrefs__', dumps(xrefs)) )
