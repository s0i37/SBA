#!/usr/bin/python2
import r2pipe
from pygments import highlight
from pygments.lexers import CppLexer
from pygments.formatters import Terminal256Formatter
from os import popen, unlink
from tempfile import NamedTemporaryFile
import random
import string

DECOMPILER = 'retdec-decompiler.py'

r2 = r2pipe.open()
arch = 'x86' if r2.cmd("e asm.bits") == '32' else 'x86-64'
vma = r2.cmd("?v $$").strip()
with NamedTemporaryFile() as blob:
	exec( r2.cmd("pcp $FS") )
	blob.write(buf)
	blob.flush()
	with NamedTemporaryFile() as output_file:
		retdec = popen( "{decompiler} -l py -m raw -e little -a {arch} --raw-entry-point=0 --raw-section-vma={vma} -o {out_file} {blob}".format(decompiler=DECOMPILER, arch=arch, vma=vma, out_file=output_file.name, blob=blob.name) )
		retdec.read()
		print highlight( output_file.read(), CppLexer(), Terminal256Formatter(style='pastie') )
		for ext in ['.bc', '.dsm', '.json', '.ll']:
			unlink(output_file.name+ext)