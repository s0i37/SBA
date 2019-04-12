RED = 0xaaaaff
GREEN = 0xaaffaa
GREEN_DARK = 0x22aa22
CYAN = 0xdddd00
BLUE = 0xffaaaa
YELLOW = 0x00ffff
GREY = 0xbbbbbb
WHITE = 0xffffff


def colorize_taint(addrs_file, color, prefix=''):
	function_names = []
	commented = set()
	with open(addrs_file) as f:
		for line in f:
			try:
				eip = int( line.split(' ')[0], 16)
				comment = ' '.join(line.split(' ')[1:]).strip()

				function_name = GetFunctionName(eip)
				if not function_name in function_names:
					function_names.append(function_name)
				SetColor(eip, CIC_ITEM, color)
				
				if comment:
					if not eip in commented:
						set_cmt( eip, comment, 0 )
						commented.add(eip)
					else:
						#set_cmt( eip, GetCommentEx(eip, 0) + '\n' + comment, 0 )
						pass
			except Exception as e:
				print str(e)
				pass

	if prefix:
		num = 0
		new_function_names = []
		for function_name in function_names:
			try:
				new_function_name = "{prefix}_{num}_{func}".format( prefix=prefix, num=num, func=function_name )
				MakeName( LocByName(function_name), new_function_name )
				new_function_names.append(new_function_name)
			except:
				pass
			num += 1
		function_names = new_function_names

	print "tainted %d functions:" % len(function_names)
	for function_name in function_names:
		print function_name



#colorize_taint( AskFile(0, "*.txt", "specify taint log file"), color=YELLOW, prefix='taint' )
colorize_taint( 'z:/var/pub/winrar_fuzz/taint-winrar.txt', color=YELLOW, prefix='taint' )
