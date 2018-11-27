from msvcrt import getch
from socket import socket

ADDR = '127.0.0.1'
PORT = 9090

def client():
	s = socket()
	try:
		s.connect( ( ADDR, PORT) )
	except Exception as e:
		print str(e)
		return
	string = ''
	print s.recv( 1024 )
	'''while True:
		ch = getch()
		if ch != '\n':
			string += ch
			print '\r' + string
		elif ch in ('\x03', '\x04'):
			break
		else:
			s.send( string )
			string = ''
			print s.recv( 1024 )'''
	while True:
		string = ''
		string = raw_input('>>> ')
		s.send( string )
		print s.recv( 1024 )
	s.close()
client()
print '[done]'