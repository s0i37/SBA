'''
git clone https://github.com/keystone-engine/keystone
mkdir build && cd build && ../make-share.sh && make install
pip install keystone-engine
'''
from keystone import *

ks = Ks(KS_ARCH_X86, KS_MODE_32)
opcodes,count = ks.asm("jmp 4;nop")
bytearray(opcodes)
