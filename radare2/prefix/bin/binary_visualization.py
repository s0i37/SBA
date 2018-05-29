#!/usr/bin/python
import r2pipe
from PIL import Image, ImageDraw, ImageFont
import os

WIDTH = 640
HEIGHT = 1920
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

module_base = r2.cmdj("omj")[0]['from']
module_end = r2.cmdj("omj")[-1:][0]['to']
bytes_per_pixel = float(module_end-module_base)/((WIDTH-1)*(HEIGHT-1))
if bytes_per_pixel < 1:
	bytes_per_pixel = 1
for flagspace in r2.cmdj("fsj"):
	if not flagspace['name'] in COLORS.keys():
		continue
	r2.cmd( "fs %s" % flagspace['name'] )
	try:
		for flag in r2.cmdj("fj"):
			start = int( float(flag['offset']) )
			end = int( float(flag['offset'] + flag['size']) )
			for offset in xrange(start, end+1):
				pixels[ int(float(offset-module_base)/bytes_per_pixel)%WIDTH , int(float(offset-module_base)/bytes_per_pixel)/WIDTH ] = COLORS[ flagspace['name'] ]
	except:
		print "ignoring %s 0x%08x out of range" % ( flag['name'], flag['offset'] )

#img.show()
img.save("binviz.png")
os.system('xdg-open binviz.png 1> /dev/null 2> /dev/null')
os.unlink('binviz.png')
