import pyvex
import archinfo

opcode = "83c007".decode('hex') # add eax, 7

ir = pyvex.IRSB( opcode, 0x0066833a, archinfo.ArchX86() )
for statement in ir.statements:
	statement.pp()