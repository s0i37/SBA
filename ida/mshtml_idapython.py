from idaapi import *
from idautils import *
from idc import *

callbacks = set([1665795296, 1666346016, 0, 1666773288, 1666790704, 1666292656, 1666794440, 1666753176])
code_points = set()
for callback in callbacks:
	for code_point in DataRefsTo( callback ):
		print "0x%08x" % code_point
		code_points.add( code_point )
print str( code_points )