#!/usr/bin/python
import r2pipe
from pygments import highlight
from pygments.lexers import CppLexer
from pygments.formatters import Terminal256Formatter
from os import popen, unlink
import random
import string

OUTPUT_DIR = '/dev/shm'
output_file = ''.join( map( lambda x:random.choice(string.letters), xrange(10) ) )

r2 = r2pipe.open()
filepath = r2.cmdj("ij")['core']['file']
from_addr = r2.cmd("?v $FB")
to_addr = r2.cmd("?v $FE")

try:
	retdec = popen( "retdec --select-ranges %s-%s -o %s/%s %s 2> /dev/null" % (from_addr, to_addr, OUTPUT_DIR, output_file, filepath) )
	retdec.read()
	with open( "%s/%s" % (OUTPUT_DIR,output_file) ) as f:
		print highlight( f.read(), CppLexer(), Terminal256Formatter(style='pastie') )
except:
	pass

for ext in ['', '.backend.ll', '.json', '.backend.bc', '.frontend.dsm']:
	unlink( "%s/%s%s" % (OUTPUT_DIR, output_file, ext) )