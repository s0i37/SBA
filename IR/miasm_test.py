from miasm2.core.locationdb import LocationDB
from miasm2.analysis.machine import Machine

opcode1 = 'b837130000'.decode('hex')
opcode2 = '83c077'.decode('hex')
opcode3 = '50'.decode('hex')

machine = Machine('x86_32')

def IR(opcode):
	loc_db = LocationDB()
	instr = machine.mn.dis(opcode, 32)

	ira = machine.ira(loc_db)
	ircfg = ira.new_ircfg()
	ira.add_instr_to_ircfg(instr, ircfg)

	for lbl, irblock in ircfg.blocks.items():
		print irblock.to_string(loc_db)


IR(opcode1)
IR(opcode2)
IR(opcode3)