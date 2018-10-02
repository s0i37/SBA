import r2lang

def le_format(a):
 def load(binf):
     return [0]

 def check_bytes(buf):
     try:
         if buf[0] == 77 and buf[1] == 90:
             lx_off, = struct.unpack("<I", buf[0x3c:0x40])
             if buf[lx_off] == 76 and buf[lx_off+1] == 88:
                 return [1]
         return [0]
     except:
         return [0]

 def info(binf):
     return [{
             "type" : "le",
             "bclass" : "le",
             "rclass" : "le",
             "os" : "OS/2",
             "subsystem" : "CLI",
             "machine" : "IBM",
             "arch" : "x86",
             "has_va" : 0,
             "bits" : 32,
             "big_endian" : 0,
             "dbg_info" : 0,
             }]

 return {
            "name" : "le",
            "desc" : "OS/2 LE/LX format",
            "license" : "GPL",
            "load" : load,
            "load_bytes" : load_bytes,
            "destroy" : destroy,
            "check_bytes" : check_bytes,
            "baddr" : baddr,
            "entries" : entries,
            "sections" : sections,
            "imports" : imports,
            "symbols" : symbols,
            "relocs" : relocs,
            "binsym" : binsym,
            "info" : info,
    }

print("Registering OS/2 LE/LX plugin...")
print(r2lang.plugin("bin", le_format))
