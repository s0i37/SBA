
for ea in Functions():
	func_name = GetFunctionName(ea)
	for (start_ea, end_ea) in Chunks(ea):
		print "%s 0x%08x 0x%08x" % (func_name, start_ea, end_ea)
