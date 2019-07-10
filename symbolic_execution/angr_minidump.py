#!/usr/bin/python3
import angr
from sys import argv
from os import listdir,path
import logging
logging.getLogger('angr').setLevel('CRITICAL')


def get_perm_code(perm_str):
	code = 0
	if perm_str.find('r') != -1:
		code += 4
	if perm_str.find('w') != -1:
		code += 2
	if perm_str.find('x') != -1:
		code += 1
	return code

project = angr.load_shellcode("\x90".encode(), 'i686', start_offset=0, load_address=0)
state = project.factory.entry_state()

for page in listdir( argv[1] ):
	page_name,vaddr,perm = page.split('=')
	with open( path.join(argv[1], page), 'rb' ) as f:
		memory = f.read()
		print( "0x%08x: %s %dB" % (int(vaddr,16), page, len(memory)) )
		state.memory.store(int(vaddr,16), memory)
		state.memory.permissions(int(vaddr,16), get_perm_code(perm))

