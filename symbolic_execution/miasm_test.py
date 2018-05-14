from miasm2.arch.x86.arch import mn_x86
from miasm2.expression.expression import get_rw

CODE = raw_input('enter opcode: ').decode('hex')

#instr = mn_x86.fromstring(INSTR, 32)
instr = mn_x86.dis(CODE, 32)

r,w = get_rw( instr.args )
print "reads: %s" % ', '.join( [str(x) for x in r] )
print "writes: %s" % ', '.join( [str(x) for x in w] )
'''
for op in instr.args:
	print op.is_mem()
'''

from miasm2.analysis.machine import Machine
shellcode = open('test.bin','rb').read()
machine = Machine('x86_32')
jitter = machine.jitter(jit_type='python')
jitter.init_stack()
jitter.vm.add_memory_page(0x401000, 1 | 2, shellcode)
jitter.jit.log_regs = True
jitter.jit.log_mn = True
jitter.init_run(0x401000)
jitter.continue_run()