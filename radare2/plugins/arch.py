import r2lang
from r2lang import R

def mycpu(a):
 def assemble(s):
     return [1, 2, 3, 4]

 def disassemble(buf):
     try:
         opcode = get_opcode(buf)
         opstr = optbl[opcode][1]
         return [4, opstr]
     except:
         return [4, "unknown"]

 return {
         "name" : "mycpu",
         "arch" : "mycpu",
         "bits" : 32,
         "endian" : "little",
         "license" : "GPL",
         "desc" : "MYCPU disasm",
         "assemble" : assemble,
         "disassemble" : disassemble,
 }

def mycpu_anal(a):
    def set_reg_profile():
        profile = "=PC    pc\n" + \
        "=SP    sp\n" + \
        "gpr    r0    .32    0    0\n" + \
        "gpr    r1    .32    4    0\n" + \
        "gpr    r2    .32    8    0\n" + \
        "gpr    r3    .32    12    0\n" + \
        "gpr    r4    .32    16    0\n" + \
        "gpr    r5    .32    20    0\n" + \
        "gpr    sp    .32    24    0\n" + \
        "gpr    pc    .32    28    0\n"
        return profile

    def op(addr, buf):
        analop = {
            "type" : R.R_ANAL_OP_TYPE_NULL,
            "cycles" : 0,
            "stackop" : 0,
            "stackptr" : 0,
            "ptr" : -1,
            "jump" : -1,
            "addr" : 0,
            "eob" : False,
            "esil" : "",
        }
        try:
            opcode = get_opcode(buf)
            esilstr = optbl[opcode][2]
            if optbl[opcode][0] == "J": # it's jump
                analop["type"] = R.R_ANAL_OP_TYPE_JMP
                analop["jump"] = decode_jump(opcode, j_mask)
                esilstr = jump_esil(esilstr, opcode, j_mask)

        except:
            result = analop
        # Don't forget to return proper instruction size!
        return [4, result]

    return {
            "name" : "mycpu",
            "arch" : "mycpu",
            "bits" : 32,
            "license" : "GPL",
            "desc" : "MYCPU anal",
            "esil" : 1,
            "set_reg_profile" : set_reg_profile,
            "op" : op,
    }

print("Registering MYCPU analysis plugin...")
print(r2lang.plugin("anal", mycpu_anal))
print("Registering MYCPU disasm plugin...")
print(r2lang.plugin("asm", mycpu))

#r2 -I mycpu.py some_file.bin
