#!/usr/bin/python2
import r2pipe

flags = set()

def walk_section(start, size):
    addr = start
    while addr < start+size:
        flag = r2.cmd('fd @ %d' % addr)
        flag_name = flag.split()[0]
        if len( flag.split() ) == 3:
            flag_offset = int( flag.split()[2] )
        else:
            flag_offset = 0

        if flag_name.startswith('section.') or flag_name in flags:
            r2.cmd('Cd 4 1 @ %d' % addr)
            addr += 4
        else:
            if flag_offset:
                addr -= flag_offset

            flag_size = int( r2.cmd('fl @ %d' % addr), 16 )
            addr += flag_size + 1
            flags.add(flag_name)

r2 = r2pipe.open()
for section in r2.cmdj('iSj'):
    if section['perm'].find('x') == -1:
        print section['name']
        walk_section( section['vaddr'], section['size'] )

