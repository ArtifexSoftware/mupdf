#
# requires: gtk-config freetype-config xxd sed
#

CFLAGS = -Wall -O3 -std=c89 -Iinclude `freetype-config --cflags`
LDLIBS = `freetype-config --libs` -ljpeg -lz -lm

X11DIR = /usr/X11R6

all: libfitz.a libmupdf.a libfonts.a pdfrip pdfclean pdfdebug x11pdf gtkpdf

#	util/strlcpy.o util/strlcat.o \
#	util/getopt.o \
#	util/strsep.o \

libfitz.a: \
		base/cpudep.o \
		base/error.o \
		base/memory.o \
		base/md5.o \
		base/arc4.o \
		base/rect.o \
		base/matrix.o \
		base/hash.o \
		base/rune.o \
		object/simple.o \
		object/array.o \
		object/dict.o \
		object/print.o \
		object/parse.o \
		filter/buffer.o \
		filter/filter.o \
		filter/filec.o \
		filter/filer.o \
		filter/filew.o \
		filter/null.o \
		filter/arc4filter.o \
		filter/pipeline.o \
		filter/ahxd.o \
		filter/ahxe.o \
		filter/a85d.o \
		filter/a85e.o \
		filter/rld.o \
		filter/rle.o \
		filter/predict.o \
		filter/lzwd.o \
		filter/lzwe.o \
		filter/faxd.o \
		filter/faxdtab.o \
		filter/faxe.o \
		filter/faxetab.o \
		filter/flate.o \
		filter/dctd.o \
		filter/dcte.o \
		tree/cmap.o \
		tree/font.o \
		tree/colorspace.o \
		tree/image.o \
		tree/shade.o \
		tree/tree.o \
		tree/node1.o \
		tree/node2.o \
		tree/text.o \
		tree/path.o \
		tree/debug.o \
		tree/optimize.o \
		render/glyphcache.o \
		render/pixmap.o \
		render/porterduff.o \
		render/meshdraw.o \
		render/imagedraw.o \
		render/imageunpack.o \
		render/imagescale.o \
		render/pathscan.o \
		render/pathfill.o \
		render/pathstroke.o \
		render/render.o
	ar cru $(@) $(?)
	ranlib $(@)

libmupdf.a: \
		mupdf/debug.o \
		mupdf/lex.o \
		mupdf/parse.o \
		mupdf/crypt.o \
		mupdf/open.o \
		mupdf/repair.o \
		mupdf/save.o \
		mupdf/xref.o \
		mupdf/stream.o \
		mupdf/doctor.o \
		mupdf/nametree.o \
		mupdf/outline.o \
		mupdf/annot.o \
		mupdf/pagetree.o \
		mupdf/store.o \
		mupdf/resources.o \
		mupdf/function.o \
		mupdf/colorspace1.o \
		mupdf/colorspace2.o \
		mupdf/xobject.o \
		mupdf/image.o \
		mupdf/pattern.o \
		mupdf/shade.o \
		mupdf/shade2.o \
		mupdf/shade3.o \
		mupdf/cmap.o \
		mupdf/unicode.o \
		mupdf/fontagl.o \
		mupdf/fontenc.o \
		mupdf/fontfile.o \
		mupdf/font.o \
		mupdf/type3.o \
		mupdf/page.o \
		mupdf/build.o \
		mupdf/interpret.o
	ar cru $(@) $(?)
	ranlib $(@)

%.c: %.cff
	xxd -i $(<) | sed -e 's/data_//g;s/, /,/g' > $(@)

data/Dingbats.c: data/Dingbats.cff
data/NimbusMonL-Bold.c: data/NimbusMonL-Bold.cff
data/NimbusMonL-BoldObli.c: data/NimbusMonL-BoldObli.cff
data/NimbusMonL-Regu.c: data/NimbusMonL-Regu.cff
data/NimbusMonL-ReguObli.c: data/NimbusMonL-ReguObli.cff
data/NimbusRomNo9L-Medi.c: data/NimbusRomNo9L-Medi.cff
data/NimbusRomNo9L-MediItal.c: data/NimbusRomNo9L-MediItal.cff
data/NimbusRomNo9L-Regu.c: data/NimbusRomNo9L-Regu.cff
data/NimbusRomNo9L-ReguItal.c: data/NimbusRomNo9L-ReguItal.cff
data/NimbusSanL-Bold.c: data/NimbusSanL-Bold.cff
data/NimbusSanL-BoldItal.c: data/NimbusSanL-BoldItal.cff
data/NimbusSanL-Regu.c: data/NimbusSanL-Regu.cff
data/NimbusSanL-ReguItal.c: data/NimbusSanL-ReguItal.cff
data/StandardSymL.c: data/StandardSymL.cff
data/URWChanceryL-MediItal.c: data/URWChanceryL-MediItal.cff

.FONTS: \
	data/Dingbats.c \
	data/NimbusMonL-Bold.c \
	data/NimbusMonL-BoldObli.c \
	data/NimbusMonL-Regu.c \
	data/NimbusMonL-ReguObli.c \
	data/NimbusRomNo9L-Medi.c \
	data/NimbusRomNo9L-MediItal.c \
	data/NimbusRomNo9L-Regu.c \
	data/NimbusRomNo9L-ReguItal.c \
	data/NimbusSanL-Bold.c \
	data/NimbusSanL-BoldItal.c \
	data/NimbusSanL-Regu.c \
	data/NimbusSanL-ReguItal.c \
	data/StandardSymL.c \
	data/URWChanceryL-MediItal.c

libfonts.a: \
	data/Dingbats.o \
	data/NimbusMonL-Bold.o \
	data/NimbusMonL-BoldObli.o \
	data/NimbusMonL-Regu.o \
	data/NimbusMonL-ReguObli.o \
	data/NimbusRomNo9L-Medi.o \
	data/NimbusRomNo9L-MediItal.o \
	data/NimbusRomNo9L-Regu.o \
	data/NimbusRomNo9L-ReguItal.o \
	data/NimbusSanL-Bold.o \
	data/NimbusSanL-BoldItal.o \
	data/NimbusSanL-Regu.o \
	data/NimbusSanL-ReguItal.o \
	data/StandardSymL.o \
	data/URWChanceryL-MediItal.o
	ar cru $(@) $(?)
	ranlib $(@)

test/ximage.o: test/ximage.c
	$(CC) -c $(CFLAGS) -o $(@) $(?) -I$(X11DIR)/include

test/x11pdf.o: test/x11pdf.c
	$(CC) -c $(CFLAGS) -o $(@) $(?) -I$(X11DIR)/include

x11pdf: test/x11pdf.o test/ximage.o
	$(CC) -o $(@) $(?) libmupdf.a libfonts.a libfitz.a $(LDLIBS) -L$(X11DIR)/lib -lX11 -lXext

test/gtkpdf.o: test/gtkpdf.c
	$(CC) -c $(CFLAGS) -o $(@) $(?) `gtk-config --cflags`

gtkpdf: test/gtkpdf.o
	$(CC) -o $(@) $(?) libmupdf.a libfonts.a libfitz.a $(LDLIBS) `gtk-config --libs gthread`

pdfrip: test/pdfrip.o
	$(CC) -o $(@) $(?) libmupdf.a libfonts.a libfitz.a $(LDLIBS)

pdfdebug: test/pdfdebug.o
	$(CC) -o $(@) $(?) libmupdf.a libfonts.a libfitz.a $(LDLIBS)

pdfclean: test/pdfclean.o
	$(CC) -o $(@) $(?) libmupdf.a libfonts.a libfitz.a $(LDLIBS)

