import sys
sys.path.append("/root/src/openreil/")
from pyopenreil.REIL import *

opcode = "83c007".decode('hex')

storage = CodeStorageMem(ARCH_X86)
reader = ReaderRaw(ARCH_X86, opcode, addr = 0)
tr = CodeStorageTranslator(reader, storage)
insn_list = tr.get_insn(0)
for insn in insn_list:
    print insn