from capstone import *
from capstone.x86 import *

md = Cs(CS_ARCH_X86, CS_MODE_32)
md.detail = True

CODE = raw_input('enter opcodes: ').decode('hex')

for instr in md.disasm( CODE, 0x38 ):
	#print instr == X86_INS_MOV
	print "%s %s" % (instr.mnemonic, instr.op_str)
	print "reads: %s, writes: %s" % ( str(instr.regs_read), str(instr.regs_write) )
	for op in instr.operands:
		if op.type == X86_OP_REG:
			print instr.reg_name( op.value.reg )
		elif op.type == X86_OP_IMM:
			print op.value.imm
		elif op.type == X86_OP_MEM:
			if op.value.mem.disp != 0:
				print op.value.mem.disp
			if op.value.mem.base != 0:
				print instr.reg_name( op.value.mem.base )
