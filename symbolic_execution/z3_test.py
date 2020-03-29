from z3 import *

s = Solver()

x = Int('x')
s.add(16*x*x+145*x+9==0)

print s.check()
print s.model()


y = BitVec('y', 8)
s.add( y ^ 0x77 == 0 )
print s.model()
