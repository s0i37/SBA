#!/usr/bin/python
import r2pipe
from PIL import Image, ImageDraw, ImageFont
import os
from sys import argv

WIDTH = 480
HEIGHT = 1080
COLORS = {
	'symbols': (0, 255, 0),
	'functions': (0, 255, 255),
	'strings': (0, 0, 255),
	'relocs': (255, 0, 0),
	'imports': (255, 0, 0)
}

r2 = r2pipe.open()
img = Image.new( 'RGB', (WIDTH,HEIGHT), "white" )
draw = ImageDraw.Draw(img)
pixels = img.load()

def draw_sections(r2, base):
	color_base = 0x40
	color_step = 0x40
	for section in r2.cmdj("iSj"):
		try:
			start = int( float(section['vaddr']) )
			end = int( float(section['vaddr'] + section['vsize']) )
			print "[*] section %s 0x%08x - 0x%08x" % ( section['name'], start, end )
			for offset in xrange(start, end+1):
				pixels[ int(float(offset-base)/bytes_per_pixel)%WIDTH , int(float(offset-base)/bytes_per_pixel)/WIDTH ] = (color_base,color_base,color_base)
			color_base += color_step
			color_base %= 0x100
		except Exception as e:
			print "[!] ignoring section %s 0x%08x out of range" % ( section['name'], start )

def draw_flags(r2, base):
	for flagspace in r2.cmdj("fsj"):
		if not flagspace['name'] in COLORS.keys():
			continue
		r2.cmd( "fs %s" % flagspace['name'] )
		try:
			for flag in r2.cmdj("fj"):
				start = int( float(flag['offset']) )
				end = int( float(flag['offset'] + flag['size']) )
				for offset in xrange(start, end+1):
					pixels[ int(float(offset-base)/bytes_per_pixel)%WIDTH , int(float(offset-base)/bytes_per_pixel)/WIDTH ] = COLORS[ flagspace['name'] ]
		except:
			print "[!] ignoring %s 0x%08x out of range" % ( flag['name'], start )


if len(argv) > 1 and argv[1].lower() == 's':
	(section_base, section_size) = r2.cmd("iS.").split()[5:7]
	section_base = int(section_base, 16)
	section_end = section_base + int(section_size)
	bytes_per_pixel = float(section_end-section_base)/((WIDTH-1)*(HEIGHT-1))
	if bytes_per_pixel < 1:
		bytes_per_pixel = 1
	draw_flags(r2, section_base)
else:
	module_base = r2.cmdj("omj")[0]['from']
	module_end = r2.cmdj("omj")[-1:][0]['to']
	bytes_per_pixel = float(module_end-module_base)/((WIDTH-1)*(HEIGHT-1))
	if bytes_per_pixel < 1:
		bytes_per_pixel = 1
	draw_sections(r2, module_base)
	draw_flags(r2, module_base)

#img.show()
img.save("binviz.png")
os.system('xdg-open binviz.png 1> /dev/null 2> /dev/null')
os.unlink('binviz.png')
