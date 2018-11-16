import re
from idaapi import *
from idautils import *
from idc import *

#traces_dir = "\\users\\azhukov\\desktop\\FUZZ\\slssvc_traces\\"
traces_dir = "\\users\\azhukov\\desktop\\FUZZ\\ftviewse_traces\\"
RED = 0xaaaaff
GREEN = 0xaaffaa
GREEN_DARK = 0x22aa22
CYAN = 0xdddd00
BLUE = 0xffaaaa
YELLOW = 0x007777
GREY = 0xbbbbbb
WHITE = 0xffffff

segments = []
for segment in Segments():
	segments.append( segment )
MIN = min(segments) & 0xfffff000
MAX = max(segments) | 0x00000fff

def _get_registers(line):
	try:
		return re.match(".*\(([^\s]+) ([^\s]+) ([^\s]+) ([^\s]+) ([^\s]+) ([^\s]+) ([^\s]+) ([^\s]+)\)", line).groups()
	except:
		return None,None,None,None,None,None,None,None,


def reset_colors():
	for segment in Segments():
		for element in Heads( segment, SegEnd(segment) ):
			if isCode( GetFlags(element) ):
				SetColor( element, CIC_ITEM, WHITE )

def colorize_trace(trace_file, color):
	function_names = set()
	need_comment = 0
	with open( trace_file, "rb") as f:
		for line in f.read().split("\r\n"):
			try:
				eip = int(line[2:10], 16)
				if MIN <= eip <= MAX:
					SetColor( eip, CIC_ITEM, color )
					function_names.add( GetFunctionName(eip) )
					'''
					eax,edx,ecx,ebx,esi,edi,ebp,esp = _get_registers(line)
					if need_comment:
						set_cmt( need_comment, "ecx=%s" % ecx, 1 )
						print "0x%08x: %s" % (need_comment,ecx)
						need_comment = 0
					if GetDisasm(eip).find("mov") == 0 and GetDisasm(eip).find("ecx,") != -1:
						need_comment = eip
					elif GetDisasm(eip).find("mov") == 0 and GetDisasm(eip).find("esi,") != -1 and GetDisasm(eip).find("ecx") != -1:
						set_cmt( eip, "esi=%s" % ecx, 1 )
						print "0x%08x: %s" % (eip,ecx)
					'''
			except:
				pass
	print 'covered %d functions:' % len(function_names)
	print ', '.join(function_names)


def colorize_addrs_with_comments(addrs_file, color):
	''' comments is optional '''
	function_names = {}
	commented = set()
	with open( addrs_file, "rb") as f:
		for line in f.read().split("\r\n"):
			try:
				words = line.split(' ')
				eip = int( words[0][2:10], 16 )
				try: function_names[ GetFunctionName(eip) ].append( hex(eip) )
				except: function_names[ GetFunctionName(eip) ] = [ hex(eip) ]
				SetColor( eip, CIC_ITEM, color )
				comment = ' '.join( words[1:] )
				if comment:
					set_cmt( eip, comment, 1 ) if not eip in commented else set_cmt( eip, GetCommentEx(eip, 1) + '\n' + comment, 1 )
					commented.add(eip)
			except Exception as e:
				pass
	print "affected %d functions:" % len(function_names)
	for function_name, addrs in function_names.items():
		print function_name
		print ', '.join(addrs)

reset_colors()
colorize_trace( traces_dir + "trace-ftae_histserv-idle.txt", color=GREY )
colorize_trace( traces_dir + "trace-ftae_histserv.txt", color=BLUE )
colorize_trace( traces_dir + "trace-ftae_histserv-50.txt", color=CYAN )
colorize_addrs_with_comments( traces_dir + 'tainted_instr-ftae_histserv-crash.txt', color=YELLOW )

'''
SLSSVC.EXE
trace_err.txt 					GREY
trace_cmd1-FULL.txt 			GREEN_DARK
trace_cmd2.txt 					GREEN
trace_ans_cmd1.txt 				BLUE
trace_ans_data1-FULL.txt 		CYAN
trace_cve-2008-2005.txt			RED

RDCYHOST.EXE
trace-rdcyhost-idle.txt 		GREY
trace-rdcyhost.txt 				CYAN

FTAE_HISTSERV.EXE
trace-ftae_histserv-idle.txt 	GREY
trace-ftae_histserv.txt 		BLUE
trace-ftae_histserv-50.txt 		CYAN
'''