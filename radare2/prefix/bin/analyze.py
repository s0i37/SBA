#!/usr/bin/python
import r2pipe
from prettytable import PrettyTable
import argparse

parser = argparse.ArgumentParser( description='analyze helper tool' )
parser.add_argument('OPERATION', type=str, help='unsafe, args, params, vars')
parser.add_argument("-function", type=str, help="show args for this function")

parser.add_argument("-sort", type=str, help="sort by column")
parser.add_argument("-reverse", default=False, action='store_true', help="reverse sort ordering")
args = parser.parse_args()

table = PrettyTable()

UNSAFE=[
	"alloca",
	"scanf",
	"wscanf",
	"sscanf",
	"swscanf",
	"vscanf",
	"vsscanf",
	"strlen",
	"wcslen",
	"strtok",
	"strtok_r",
	"wcstok",
	"strcat",
	"strncat",
	"wcscat",
	"wcsncat",
	"strcpy",
	"strncpy",
	"wcscpy",
	"wcsncpy",
	"memcpy",
	"wmemcpy",
	"stpcpy",
	"stpncpy",
	"wcpcpy",
	"wcpncpy",
	"memmove",
	"wmemmove",
	"memcmp",
	"wmemcmp",
	"memset",
	"wmemset",
	"gets",
	"sprintf",
	"vsprintf",
	"swprintf",
	"vswprintf",
	"snprintf",
	"vsnprintf",
	"realpath",
	"getwd",
	"wctomb",
	"wcrtomb",
	"wcstombs",
	"wcsrtombs",
	"wcsnrtombs",
]

MAX_DEEP = 100
r2 = r2pipe.open()

current_sub = r2.cmd("afn")
known_subs = set()
def walk_up(sub, deep=0):
	global known_subs
	if deep == 0:
		known_subs = set()
	for xref in r2.cmdj( 'axtj {sub}'.format(sub=sub) ):
		if xref["type"].lower() == "call":
			addr = xref.get("fcn_addr")
			_sub = xref.get("fcn_name")
			if not _sub or sub == _sub:
				continue
			if _sub in known_subs or deep >= MAX_DEEP:
				continue
			known_subs.add(_sub)
			if _sub == current_sub:
				break
			deep = walk_up(_sub, deep+1)
	return deep if deep < 100 else 0

def show_unsafe(args):
	table.field_names = ['Function', 'Xrefs', 'How far', 'Potential Functions']
	table.sortby = args.sort
	table.reversesort = args.reverse
	class Function:
		def __init__(self, name):
			self.name = name
			self.xrefs = 0
			self.deep = 0
			self.calls = set()
	functions = {}

	for unsafe in UNSAFE:
		line = r2.cmd( "ii~{func}$".format(func=unsafe) )
		if line:
			addr = int(line.split()[1], 16)
			xrefs = r2.cmdj( "axtj @{addr}".format(addr=addr) )
			for xref in xrefs:
				if "fcn_addr" in xref:
					addr = xref["fcn_addr"]
					deep = walk_up(addr)
					if deep:
						xrefs = r2.cmdj( "axtj @{addr}".format(addr=addr) )
						if addr in functions.keys():
							functions[addr].calls.add(unsafe)
						else:
							name = r2.cmdj("afdj @{addr}".format(addr=addr))["name"]
							functions[addr] = Function(name)
							functions[addr].xrefs = len(xrefs)
							functions[addr].deep = deep
							functions[addr].calls.add(unsafe)
	for function in functions.values():
		table.add_row( [function.name, function.xrefs, function.deep, ','.join(function.calls)] )
	print table




def get_args(addr):
	args = []
	instrs = []
	if not r2.cmd("afn @{addr}".format(addr=addr)):
		return []
	for instr in r2.cmdj("pdbj @{addr}".format(addr=addr)):
		instrs.append(instr["offset"])
	instrs.reverse()
	i = 0
	for instr in instrs:
		if instr > addr:
			continue
		if i:
			arg = r2.cmd("Ct.@{addr}".format(addr=instr))
			if arg:
				args.append(arg)
			if r2.cmdj("aoj @{addr}".format(addr=instr))[0]["mnemonic"] == "call":
				break
		i += 1
	return args

def function_use(args):
	table.sortby = args.sort
	table.reversesort = args.reverse
	addr = None
	for function in r2.cmdj("isj"):
		if function["name"] == args.function or function["flagname"] == args.function or function["realname"] == args.function:
			addr = function["vaddr"]
			break
	if not addr:
		for function in r2.cmdj("aflj"):
			if function["name"] == args.function:
				addr = function["offset"]
				break
	if addr:
		args_count = 0
		calls = []
		for function_use in r2.cmdj("axtj @{addr}".format(addr=addr)):
			args = get_args(function_use["from"])
			calls.append( map(lambda a:r2.cmd("afn@%d"%a), [function_use["from"], addr]) + args )
			if len(args) > args_count:
				args_count = len(args)
		table.field_names = ['Function', 'Call'] + map(lambda i:"arg%d"%i, xrange(args_count))
		for call in calls:
			pad = map( lambda p:"", range(args_count-len(call[2:])) )
			table.add_row(call+pad)
	print table




def get_val(addr):
	for ref in r2.cmdj("afxj"):
		if ref["from"] == addr:
			return ref["to"]
			break
	return "?"

def get_string(addr):
	string = None
	if r2.cmdj("axfj @{addr}".format(addr=addr)):
		addr = r2.cmdj("axfj @{addr}".format(addr=addr))[0]["to"]
		string = r2.cmd("Cs. @{addr}".format(addr=addr))
	return string

def get_params(addr):
	params = []
	instrs = []
	if not r2.cmd("afn @{addr}".format(addr=addr)):
		return []
	for instr in r2.cmdj("pdbj @{addr}".format(addr=addr)):
		instrs.append(instr["offset"])
	instrs.reverse()
	i = 0
	for instr in instrs:
		if instr > addr:
			continue
		if i:
			arg = r2.cmd("Ct.@{addr}".format(addr=instr))
			if arg:
				string = get_string(instr)
				if string:
					params.append(string)
				else:
					val = get_val(instr)
					if type(val) == int:
						params.append(hex(val))
					else:
						params.append(val)
			if r2.cmdj("aoj @{addr}".format(addr=instr))[0]["mnemonic"] == "call":
				break
		i += 1
	return params

def function_call(args):
	table.sortby = args.sort
	table.reversesort = args.reverse
	addr = None
	for function in r2.cmdj("isj"):
		if function["name"] == args.function or function["flagname"] == args.function or function["realname"] == args.function:
			addr = function["vaddr"]
			break
	if not addr:
		for function in r2.cmdj("aflj"):
			if function["name"] == args.function:
				addr = function["offset"]
				break
	if addr:
		params_count = 0
		calls = []
		for function_use in r2.cmdj("axtj @{addr}".format(addr=addr)):
			params = get_params(function_use["from"])
			calls.append( map(lambda a:r2.cmd("afn@%d"%a), [function_use["from"], addr]) + params )
			if len(params) > params_count:
				params_count = len(params)
		table.field_names = ['Function', 'Call'] + map(lambda i:"arg%d"%i, xrange(params_count))
		for call in calls:
			pad = map( lambda p:"", range(params_count-len(call[2:])) )
			table.add_row(call+pad)
	print table



def function_vars(args):
	addr = r2.cmdj("afij")[0]["offset"]
	local_vars = r2.cmdj("afvj @{addr}".format(addr=addr))
	for var_type in local_vars.keys():
		for local_var in local_vars[var_type]:
			for access_read in r2.cmd("afvR {var}".format(var=local_var["name"])).split(' ').pop().split(','):
				if access_read:
					access_read = int(access_read, 16)
					instruction = r2.cmdj("pdj 1 @{addr}".format(addr=access_read))[0]["disasm"]
					print "R {var} {addr}: {instr}".format(var=local_var["name"], addr=hex(access_read), instr=instruction)
	for var_type in local_vars.keys():
		for local_var in local_vars[var_type]:
			for access_write in r2.cmd("afvW {var}".format(var=local_var["name"])).split(' ').pop().split(','):
				if access_write.split():
					access_write = int(access_write, 16)
					instruction = r2.cmdj("pdj 1 @{addr}".format(addr=access_write))[0]["disasm"]
					print "W {var} {addr}: {instr}".format(var=local_var["name"], addr=hex(access_write), instr=instruction)

if args.OPERATION == 'unsafe':
	show_unsafe(args)
elif args.OPERATION == 'args' and args.function:
	function_use(args)
elif args.OPERATION == 'params' and args.function:
	function_call(args)
elif args.OPERATION == 'vars' and args.function:
	function_vars(args)
else:
	parser.print_help()