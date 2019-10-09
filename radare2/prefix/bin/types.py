#!/usr/bin/python2
import r2pipe

r2 = r2pipe.open()

def get_rip():
	return int(r2.cmd("s"), 16)

def get_var(addr):
	try:
		return r2.cmd("afvR; afvW ~0x%x" % addr).split()[0]
	except:
		pass

def get_flag_by_addr(addr):
	return r2.cmdj("fdj @%d" %addr)

def get_flag_by_name(flag_name):
	for flag in r2.cmdj("fj"):
		if flag["name"] == flag_name:
			return flag

def disas(addr):
	return r2.cmdj("aoj @%d" % addr)[0]

def xrefs_from(addr):
	return r2.cmdj("axfj @%d" % addr)


EIP = {16: "ip", 32: "eip", 64: "rip"}.get( r2.cmdj("ej")["asm.bits"] )
class Emu:
	def __init__(self):
		self.clean()
		self.init()
		self.rip = r2.cmdj("arj")[EIP]
		self.__idx = 0
		pass

	def __del__(self):
		self.clean()

	def init(self):
		r2.cmd("aei")
		r2.cmd("aeip")
		r2.cmd("aeim")
		r2.cmd("aets+")
		r2.cmd(".afv*")

	def clean(self):
		r2.cmd("aei-;ar0")
		r2.cmd("dte-*")

	def goto(self, addr):
		r2.cmd("aepc %d" % addr)
		self.rip = addr

	def get_access(self):
		esil_trace_log = r2.cmd("dte").split('\n')
		esil_trace_log = filter(lambda l:l!='', esil_trace_log)
		self.__idx = int(esil_trace_log[-1][4:])
		access = []
		for esil_event in esil_trace_log:
			if esil_event.startswith("%d." % self.__idx):
				access.append(esil_event)
		return access

	def get_regs(self):
		return r2.cmdj("arj")

	def step(self):
		r2.cmd("aes")
		self.rip = r2.cmdj("arj")[EIP]



emu = Emu()
origin = get_rip()
var = get_var(origin)
if not var:
	print "[-] variable not found"
	exit()

flag = get_flag_by_name("fcnvar."+var)
print "[*] 0x%x: %s" % (flag["offset"], flag["name"])

deep = 0
while True:
	rip = emu.rip
	instr = disas(emu.rip)
	if disas(emu.rip)["mnemonic"] == "call":
		if get_flag_by_addr( int( xrefs_from(emu.rip)[0]["to"] ) ).get("name","").find(".imp.") != -1:
			emu.goto( r2.cmdj("pdj 2@%s"%EIP)[1]["offset"] )
			continue
		if disas(emu.rip)["disasm"].find("sym.__x86.get_pc_thunk.ax") == -1:
			deep += 1
	elif disas(emu.rip)["mnemonic"] == "ret":
		deep -= 1

	if deep < 0:
		break

	emu.step()
	#print "[%d] 0x%x: %s" % (deep, rip, instr["disasm"])
	
	for access in emu.get_access():
		if access.find("mem.read.data") != -1:
			io = "->"
		elif access.find("mem.write.data") != -1:
			io = "<-"
		elif access.find("reg.read.") != -1:
			io = "->"
		elif access.find("reg.write.") != -1:
			io = "<-"
		else:
			io = None
		if io:
			if access.find("mem") != -1:
				addr = int( access.split("=")[0].split(".")[-1], 16)
				ctype = {1: "char", 2: "short", 4: "int", 8: "long long"}[ len( access.split("=")[1] )/2 ]
			elif access.find("reg") != -1:
				addr = int( access.split("=")[1], 16)
				ctype = "void *"
			flag_used = get_flag_by_addr(addr)
			function_use = get_flag_by_addr(rip)
			if flag_used["name"] == flag["name"]:
				print "[+] 0x%x: [%s+%d] (%s) %s %s+%d: %s" % ( 
					addr,
					flag_used["name"], flag_used.get("offset",0), ctype,
					io,
					function_use["name"], function_use["offset"], instr["disasm"] )

del(emu)
r2.cmd("s %d" % origin)