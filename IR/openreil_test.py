import sys
sys.path.append("/root/src/openreil/")
from pyopenreil.REIL import *

opcode = "83c007".decode('hex') # add eax, 7

storage = CodeStorageMem(ARCH_X86)
reader = ReaderRaw(ARCH_X86, opcode, addr = 0)
tr = CodeStorageTranslator(reader, storage)
insn_list = tr.get_insn(0)
for insn in insn_list:
    print insn
print insn_list.to_symbolic(temp_regs = False)

# http://blog.cr4.sh/2015/03/automated-algebraic-cryptanalysis-with.html
'''
OPERATION 		a(src), 		b(src),		 	c(dst)

mov eax,7
STR             7:32,                 ,         R_EAX:32

c = a
R_EAX = 7
'''