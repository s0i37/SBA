
for ea in Functions():
	func_name = GetFunctionName(ea)
	for (start_ea, end_ea) in Chunks(ea):
		print "0x%08x-0x%08x %s" % (start_ea, end_ea, func_name)
