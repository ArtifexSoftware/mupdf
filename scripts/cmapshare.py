# Find and extract common CMap subsets.
# Taken flattened CMaps as input, using only the 'cidchar' sections.
# The outputs are truncated; so use 'cmapflatten.py' to clean them up.

import sys, os

def load_cmap_set(filename):
	cmap = set()
	active = False
	for line in open(filename).readlines():
		line = line.strip()
		if line.endswith("endcidchar"): active = False
		if active: cmap.add(line)
		if line.endswith("begincidchar"): active = True
	return cmap

def load_cmap_prologue(filename):
	prologue = []
	for line in open(filename).readlines():
		line = line.strip()
		if line.endswith("begincidchar"):
			break
		prologue.append(line)
	return prologue

epilogue = [
	'endcidchar',
]

common_name = os.path.basename(sys.argv[1])

# First find the common subset
common = load_cmap_set(sys.argv[2])
for f in sys.argv[3:]:
	common &= load_cmap_set(f)

def print_cmap(filename, prologue, cmap):
	out = open(filename, "w")
	for line in prologue:
		if not line.endswith("usecmap"):
			print >>out, line
		if line == 'begincmap':
			print >>out, "/"+common_name, "usecmap"
	print >>out, len(cmap), "begincidchar"
	for line in sorted(cmap):
		print >>out, line
	for line in epilogue:
		print >>out, line

# Print common subset
print_cmap(sys.argv[1], ["/CMapName /%s" % common_name], common)

# Now find unique bits
for f in sys.argv[2:]:
	cmap = load_cmap_set(f) - common
	prologue = load_cmap_prologue(f)
	print_cmap(f+".shared", prologue, cmap)
