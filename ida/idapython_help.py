from idaapi import *
from idautils import *
from idc import *
from os.path import (dirname,abspath)

cwd = dirname( abspath( __file__ ) )
def save_names():
	import idaapi
	import idautils
	import idc
	with open('%s/../idapython_names.txt' % cwd,'w') as f:
		for i in dir(idaapi):
			f.write( 'idaapi.' + str(i) + "\n" )
		for i in dir(idaapi._idaapi):
			f.write( 'idaapi._idaapi.' + str(i) + "\n" )
		for i in dir(idaapi._object):
			f.write( 'idaapi._object.' + str(i) + "\n" )
		for i in dir(idautils):
			f.write( 'idautils.' + str(i) + "\n" )
		for i in dir(idc):
			f.write( 'idc.' + str(i) + "\n" )
	print "[ok]"

def print_segments():
	addr = FirstSeg()
	print "0x%08x" % addr
	while True:
		addr = NextSeg( addr )
		if addr == BADADDR:
			break
		print "0x%08x: %s" % ( addr, SegName(addr) )
	print "[ok]"

def print_segments2():
	for addr in Segments():
		print "0x%08x: %s" % (addr, SegName(addr) )
	print "[ok]"

def print_global_vars():	
	count = 0
	for item in Heads( SegByName(".data"), SegEnd( SegByName(".data") ) ):
		count +=1 
	print count

def disas_all():
	for segment in Segments():
		for head in Heads( segment, SegEnd(segment) ):
			if isCode( GetFlags(head) ):
				print GetDisasm( head )

def server( queue=1 ):
	import socket
	s = socket.socket()
	s.bind( ('', 9090) )
	s.listen( queue )
	print 'netcat 0.0.0.0 9090\nwait for new connection...'
	c,a = s.accept()
	c.send( 'welcome to IDA\n>>> ' )
	try:
		while True:
			data = c.recv( 1024 )
			if not data:
				break
			try:
				exec( "__out = " + data )
				c.send( str( __out ) + "\n>>> " )
			except:
				exec( data )
				c.send( '>>> ' )
	except Exception as e:
		print str(e)
	finally:
		c.close()
	s.close()
	print '[done]'

def print_functions():
	i = 1
	for function in Functions( SegByName(".text"), SegEnd( SegByName(".text") ) ):
		print "%d %s" % (i, function)
		i += 1

def test():
	SetColor(0x7702de9d, CIC_ITEM, 0x0000FF)

save_names()