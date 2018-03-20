# Convert unicode mapping table to C arrays mapping glyph names and unicode values.
#
# ftp://ftp.unicode.org/Public/MAPPINGS/VENDORS/MISC/KOI8-U.TXT
# ftp://ftp.unicode.org/Public/MAPPINGS/ISO8859/8859-7.TXT
#

glyphs = {}
for line in open("scripts/glyphlist.txt").readlines():
	if line[0] != '#':
		n, u = line.rstrip().split(';')
		if len(u) == 4:
			u = int(u, base=16)
			glyphs[u] = n

def load_table(fn):
	table = [0] * 256
	for line in open(fn).readlines():
		if line[0] != '#':
			line = line.split()
			c = int(line[0][2:], base=16)
			u = int(line[1][2:], base=16)
			table[c] = u
	return table

def dump_table(name, table):
	print "const char *pdf_glyph_name_from_%s[%d] = {" % (name, len(table))
	for u in table:
		if u in glyphs:
			print '"%s",' % glyphs[u]
		else:
			print '_notdef,'
	print "};"
	print
	print "static const struct { unsigned short u, c; } %s_from_unicode[] = {" % name
	rev = []
	i = 0
	for u in table:
		if u in glyphs:
			if u >= 128:
				rev += ['{0x%04x,%d},' % (u, i)]
		i = i + 1
	rev.sort()
	for s in rev:
		print s
	print "};"
	print

dump_table("koi8u", load_table("scripts/KOI8-U.TXT"))
dump_table("iso8859_7", load_table("scripts/8859-7.TXT"))
