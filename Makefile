# GNU Makefile

build ?= release

OUT := build/$(build)
GEN := generated

default: all

# --- Configuration ---

include Makerules
include Makethird

# Do not specify CFLAGS or LIBS on the make invocation line - specify
# XCFLAGS or XLIBS instead. Make ignores any lines in the makefile that
# set a variable that was set on the command line.
CFLAGS += $(XCFLAGS) -Iinclude -I$(GEN)
LIBS += $(XLIBS) -lm

LIBS += $(FREETYPE_LIBS)
LIBS += $(HARFBUZZ_LIBS)
LIBS += $(JBIG2DEC_LIBS)
LIBS += $(JPEG_LIBS)
LIBS += $(JPEGXR_LIB)
LIBS += $(MUJS_LIBS)
LIBS += $(OPENJPEG_LIBS)
LIBS += $(OPENSSL_LIBS)
LIBS += $(ZLIB_LIBS)
LIBS += $(LURATECH_LIBS)

CFLAGS += $(FREETYPE_CFLAGS)
CFLAGS += $(HARFBUZZ_CFLAGS)
CFLAGS += $(JBIG2DEC_CFLAGS)
CFLAGS += $(JPEG_CFLAGS)
CFLAGS += $(JPEGXR_CFLAGS)
CFLAGS += $(MUJS_CFLAGS)
CFLAGS += $(OPENJPEG_CFLAGS)
CFLAGS += $(OPENSSL_CFLAGS)
CFLAGS += $(ZLIB_CFLAGS)
CFLAGS += $(LURATECH_CFLAGS)

# --- Commands ---

ifneq "$(verbose)" "yes"
QUIET_AR = @ echo ' ' ' ' AR $@ ;
QUIET_CC = @ echo ' ' ' ' CC $@ ;
QUIET_CXX = @ echo ' ' ' ' CXX $@ ;
QUIET_GEN = @ echo ' ' ' ' GEN $@ ;
QUIET_LINK = @ echo ' ' ' ' LINK $@ ;
QUIET_MKDIR = @ echo ' ' ' ' MKDIR $@ ;
QUIET_RM = @ echo ' ' ' ' RM $@ ;
QUIET_TAGS = @ echo ' ' ' ' TAGS $@ ;
endif

CC_CMD = $(QUIET_CC) $(CC) $(CFLAGS) -o $@ -c $<
CXX_CMD = $(QUIET_CXX) $(CXX) $(CFLAGS) -o $@ -c $<
AR_CMD = $(QUIET_AR) $(AR) cr $@ $^
LINK_CMD = $(QUIET_LINK) $(CC) $(LDFLAGS) -o $@ $^ $(LIBS)
MKDIR_CMD = $(QUIET_MKDIR) mkdir -p $@
RM_CMD = $(QUIET_RM) rm -f $@
TAGS_CMD = $(QUIET_TAGS) ctags $^

# --- File lists ---

ALL_DIR := $(OUT)/fitz
ALL_DIR += $(OUT)/pdf
ALL_DIR += $(OUT)/xps
ALL_DIR += $(OUT)/svg
ALL_DIR += $(OUT)/cbz
ALL_DIR += $(OUT)/html
ALL_DIR += $(OUT)/gprf
ALL_DIR += $(OUT)/tools
ALL_DIR += $(OUT)/platform/x11
ALL_DIR += $(OUT)/platform/x11/curl
ALL_DIR += $(OUT)/platform/gl
ALL_DIR += $(OUT)/fonts

FITZ_HDR := include/mupdf/fitz.h $(wildcard include/mupdf/fitz/*.h)
PDF_HDR := include/mupdf/pdf.h $(wildcard include/mupdf/pdf/*.h)
XPS_HDR := include/mupdf/xps.h
SVG_HDR := include/mupdf/svg.h
HTML_HDR := include/mupdf/html.h

FITZ_SRC := $(wildcard source/fitz/*.c)
PDF_SRC := $(wildcard source/pdf/*.c)
XPS_SRC := $(wildcard source/xps/*.c)
SVG_SRC := $(wildcard source/svg/*.c)
CBZ_SRC := $(wildcard source/cbz/*.c)
HTML_SRC := $(wildcard source/html/*.c)
GPRF_SRC := $(wildcard source/gprf/*.c)

FITZ_SRC_HDR := $(wildcard source/fitz/*.h)
PDF_SRC_HDR := $(wildcard source/pdf/*.h) source/pdf/pdf-name-table.h
XPS_SRC_HDR := $(wildcard source/xps/*.h)
SVG_SRC_HDR := $(wildcard source/svg/*.h)
HTML_SRC_HDR := $(wildcard source/html/*.h)
GPRF_SRC_HDR := $(wildcard source/gprf/*.h)

FITZ_OBJ := $(subst source/, $(OUT)/, $(addsuffix .o, $(basename $(FITZ_SRC))))
PDF_OBJ := $(subst source/, $(OUT)/, $(addsuffix .o, $(basename $(PDF_SRC))))
XPS_OBJ := $(subst source/, $(OUT)/, $(addsuffix .o, $(basename $(XPS_SRC))))
SVG_OBJ := $(subst source/, $(OUT)/, $(addsuffix .o, $(basename $(SVG_SRC))))
CBZ_OBJ := $(subst source/, $(OUT)/, $(addsuffix .o, $(basename $(CBZ_SRC))))
HTML_OBJ := $(subst source/, $(OUT)/, $(addsuffix .o, $(basename $(HTML_SRC))))
GPRF_OBJ := $(subst source/, $(OUT)/, $(addsuffix .o, $(basename $(GPRF_SRC))))

$(FITZ_OBJ) : $(FITZ_HDR) $(FITZ_SRC_HDR)
$(PDF_OBJ) : $(FITZ_HDR) $(PDF_HDR) $(PDF_SRC_HDR)
$(XPS_OBJ) : $(FITZ_HDR) $(XPS_HDR) $(XPS_SRC_HDR)
$(SVG_OBJ) : $(FITZ_HDR) $(SVG_HDR) $(SVG_SRC_HDR)
$(CBZ_OBJ) : $(FITZ_HDR)
$(HTML_OBJ) : $(FITZ_HDR) $(HTML_HDR) $(HTML_SRC_HDR)
$(GPRF_OBJ) : $(FITZ_HDR) $(GPRF_HDR) $(GPRF_SRC_HDR)

# --- Generated embedded font files ---

FONT_BIN_DROID := $(wildcard resources/fonts/droid/*.ttf)
FONT_BIN_NOTO := $(wildcard resources/fonts/noto/*.ttf)
FONT_BIN_HAN := $(wildcard resources/fonts/han/*.otf)
FONT_BIN_URW := $(wildcard resources/fonts/urw/*.cff)
FONT_BIN_SIL := $(wildcard resources/fonts/sil/*.cff)

FONT_GEN_DROID := $(subst resources/fonts/droid/, $(GEN)/, $(addsuffix .c, $(basename $(FONT_BIN_DROID))))
FONT_GEN_NOTO := $(subst resources/fonts/noto/, $(GEN)/, $(addsuffix .c, $(basename $(FONT_BIN_NOTO))))
FONT_GEN_HAN := $(subst resources/fonts/han/, $(GEN)/, $(addsuffix .c, $(basename $(FONT_BIN_HAN))))
FONT_GEN_URW := $(subst resources/fonts/urw/, $(GEN)/, $(addsuffix .c, $(basename $(FONT_BIN_URW))))
FONT_GEN_SIL := $(subst resources/fonts/sil/, $(GEN)/, $(addsuffix .c, $(basename $(FONT_BIN_SIL))))

FONT_BIN := $(FONT_BIN_DROID) $(FONT_BIN_NOTO) $(FONT_BIN_HAN) $(FONT_BIN_URW) $(FONT_BIN_SIL)
FONT_GEN := $(FONT_GEN_DROID) $(FONT_GEN_NOTO) $(FONT_GEN_HAN) $(FONT_GEN_URW) $(FONT_GEN_SIL)
FONT_OBJ := $(subst $(GEN)/, $(OUT)/fonts/, $(addsuffix .o, $(basename $(FONT_GEN))))

$(GEN)/%.c : resources/fonts/droid/%.ttf $(FONTDUMP)
	$(QUIET_GEN) $(FONTDUMP) $@ $<
$(GEN)/%.c : resources/fonts/noto/%.ttf $(FONTDUMP)
	$(QUIET_GEN) $(FONTDUMP) $@ $<
$(GEN)/%.c : resources/fonts/han/%.otf $(FONTDUMP)
	$(QUIET_GEN) $(FONTDUMP) $@ $<
$(GEN)/%.c : resources/fonts/urw/%.cff $(FONTDUMP)
	$(QUIET_GEN) $(FONTDUMP) $@ $<
$(GEN)/%.c : resources/fonts/sil/%.cff $(FONTDUMP)
	$(QUIET_GEN) $(FONTDUMP) $@ $<

$(FONT_OBJ) : $(FONT_GEN)
$(FONT_GEN_DROID) : $(FONT_BIN_DROID)
$(FONT_GEN_NOTO) : $(FONT_BIN_NOTO)
$(FONT_GEN_HAN) : $(FONT_BIN_HAN)
$(FONT_GEN_URW) : $(FONT_BIN_URW)
$(FONT_GEN_SIL) : $(FONT_BIN_SIL)

# --- Library ---

MUPDF_LIB = $(OUT)/libmupdf.a
THIRD_LIB = $(OUT)/libmupdfthird.a

MUPDF_OBJ := $(FITZ_OBJ) $(FONT_OBJ) $(PDF_OBJ) $(XPS_OBJ) $(SVG_OBJ) $(CBZ_OBJ) $(HTML_OBJ) $(GPRF_OBJ)
THIRD_OBJ := $(FREETYPE_OBJ) $(HARFBUZZ_OBJ) $(JBIG2DEC_OBJ) $(JPEG_OBJ) $(JPEGXR_OBJ) $(LURATECH_OBJ) $(MUJS_OBJ) $(OPENJPEG_OBJ) $(ZLIB_OBJ)

$(MUPDF_LIB) : $(MUPDF_OBJ)
$(THIRD_LIB) : $(THIRD_OBJ)

INSTALL_LIBS := $(MUPDF_LIB) $(THIRD_LIB)

# --- Rules ---

$(ALL_DIR) $(OUT) $(GEN) :
	$(MKDIR_CMD)

$(OUT)/%.a :
	$(RM_CMD)
	$(AR_CMD)
	$(RANLIB_CMD)

$(OUT)/%: $(OUT)/%.o
	$(LINK_CMD)

$(OUT)/%.o : source/%.c | $(ALL_DIR)
	$(CC_CMD)

$(OUT)/%.o : source/%.cpp | $(ALL_DIR)
	$(CXX_CMD)

$(OUT)/%.o : scripts/%.c | $(OUT)
	$(CC_CMD)

$(OUT)/fonts/%.o : $(GEN)/%.c | $(ALL_DIR)
	$(CC_CMD) -O0

$(OUT)/platform/x11/%.o : platform/x11/%.c | $(ALL_DIR)
	$(CC_CMD) $(X11_CFLAGS)

$(OUT)/platform/x11/%.o: platform/x11/%.rc | $(OUT)
	windres $< $@

$(OUT)/platform/x11/curl/%.o : platform/x11/%.c | $(ALL_DIR)
	$(CC_CMD) $(X11_CFLAGS) $(CURL_CFLAGS) -DHAVE_CURL

$(OUT)/platform/gl/%.o : platform/gl/%.c | $(ALL_DIR)
	$(CC_CMD) $(GLFW_CFLAGS)

.PRECIOUS : $(OUT)/%.o # Keep intermediates from chained rules

# --- Generated CMap and JavaScript files ---

CMAPDUMP := $(OUT)/cmapdump
FONTDUMP := $(OUT)/fontdump
NAMEDUMP := $(OUT)/namedump
CQUOTE := $(OUT)/cquote
BIN2HEX := $(OUT)/bin2hex

CMAP_CNS_SRC := $(wildcard resources/cmaps/cns/*)
CMAP_GB_SRC := $(wildcard resources/cmaps/gb/*)
CMAP_JAPAN_SRC := $(wildcard resources/cmaps/japan/*)
CMAP_KOREA_SRC := $(wildcard resources/cmaps/korea/*)

$(GEN)/gen_cmap_cns.h : $(CMAP_CNS_SRC)
	$(QUIET_GEN) $(CMAPDUMP) $@ $(CMAP_CNS_SRC)
$(GEN)/gen_cmap_gb.h : $(CMAP_GB_SRC)
	$(QUIET_GEN) $(CMAPDUMP) $@ $(CMAP_GB_SRC)
$(GEN)/gen_cmap_japan.h : $(CMAP_JAPAN_SRC)
	$(QUIET_GEN) $(CMAPDUMP) $@ $(CMAP_JAPAN_SRC)
$(GEN)/gen_cmap_korea.h : $(CMAP_KOREA_SRC)
	$(QUIET_GEN) $(CMAPDUMP) $@ $(CMAP_KOREA_SRC)

CMAP_GEN := $(addprefix $(GEN)/, gen_cmap_cns.h gen_cmap_gb.h gen_cmap_japan.h gen_cmap_korea.h)

include/mupdf/pdf.h : include/mupdf/pdf/name-table.h
NAME_GEN := include/mupdf/pdf/name-table.h source/pdf/pdf-name-table.h
$(NAME_GEN) : resources/pdf/names.txt
	$(QUIET_GEN) $(NAMEDUMP) resources/pdf/names.txt $(NAME_GEN)

JAVASCRIPT_SRC := source/pdf/pdf-js-util.js
JAVASCRIPT_GEN := $(GEN)/gen_js_util.h
$(JAVASCRIPT_GEN) : $(JAVASCRIPT_SRC)
	$(QUIET_GEN) $(CQUOTE) $@ $(JAVASCRIPT_SRC)

ADOBECA_SRC := resources/certs/AdobeCA.p7c
ADOBECA_GEN := $(GEN)/gen_adobe_ca.h
$(ADOBECA_GEN) : $(ADOBECA_SRC)
	$(QUIET_GEN) $(BIN2HEX) $@ $(ADOBECA_SRC)

ifneq "$(CROSSCOMPILE)" "yes"
$(CMAP_GEN) : $(CMAPDUMP) | $(GEN)
$(FONT_GEN) : $(FONTDUMP) | $(GEN)
$(NAME_GEN) : $(NAMEDUMP) | $(GEN)
$(JAVASCRIPT_GEN) : $(CQUOTE) | $(GEN)
$(ADOBECA_GEN) : $(BIN2HEX) | $(GEN)
endif

generate: $(CMAP_GEN) $(FONT_GEN) $(JAVASCRIPT_GEN) $(ADOBECA_GEN) $(NAME_GEN)

$(OUT)/pdf/pdf-cmap-table.o : $(CMAP_GEN)
$(OUT)/pdf/pdf-pkcs7.o : $(ADOBECA_GEN)
$(OUT)/pdf/pdf-js.o : $(JAVASCRIPT_GEN)
$(OUT)/pdf/pdf-object.o : source/pdf/pdf-name-table.h
$(OUT)/cmapdump.o : include/mupdf/pdf/cmap.h source/fitz/context.c source/fitz/error.c source/fitz/memory.c source/fitz/output.c source/fitz/string.c source/fitz/buffer.c source/fitz/stream-open.c source/fitz/stream-read.c source/fitz/strtod.c source/fitz/strtof.c source/fitz/ftoa.c source/fitz/printf.c source/fitz/time.c source/pdf/pdf-lex.c source/pdf/pdf-cmap.c source/pdf/pdf-cmap-parse.c source/pdf/pdf-name-table.h

# --- Tools and Apps ---

MUTOOL := $(OUT)/mutool
MUTOOL_OBJ := $(addprefix $(OUT)/tools/, mutool.o muconvert.o mudraw.o murun.o)
MUTOOL_OBJ += $(addprefix $(OUT)/tools/, pdfclean.o pdfcreate.o pdfextract.o pdfinfo.o pdfmerge.o pdfposter.o pdfpages.o pdfshow.o)
$(MUTOOL_OBJ): $(FITZ_HDR) $(PDF_HDR)
MUTOOL_LIB = $(OUT)/libmutools.a
$(MUTOOL_LIB) : $(MUTOOL_OBJ)
$(MUTOOL) : $(MUTOOL_LIB) $(MUPDF_LIB) $(THIRD_LIB)
	$(LINK_CMD)

MURASTER := $(OUT)/muraster
MURASTER_OBJ := $(addprefix $(OUT)/tools/, muraster.o)
$(MURASTER_OBJ): $(FITZ_HDR)
$(MURASTER) : $(MURASTER_OBJ) $(MUPDF_LIB) $(THIRD_LIB)
	$(LINK_CMD)

MJSGEN := $(OUT)/mjsgen
MJSGEN_OBJ := $(addprefix $(OUT)/tools/, mjsgen.o)
$(MUTOOL_OBJ): $(FITZ_HDR) $(PDF_HDR)
$(MJSGEN) : $(MJSGEN_OBJ) $(MUPDF_LIB) $(THIRD_LIB)
	$(LINK_CMD)

MUJSTEST := $(OUT)/mujstest
MUJSTEST_OBJ := $(addprefix $(OUT)/platform/x11/, jstest_main.o pdfapp.o)
$(MUJSTEST_OBJ) : $(FITZ_HDR) $(PDF_HDR)
$(MUJSTEST) : $(MUJSTEST_OBJ) $(MUPDF_LIB) $(THIRD_LIB)
	$(LINK_CMD)

ifeq "$(HAVE_X11)" "yes"
MUVIEW_X11 := $(OUT)/mupdf-x11
MUVIEW_X11_OBJ := $(addprefix $(OUT)/platform/x11/, x11_main.o x11_image.o pdfapp.o)
$(MUVIEW_X11_OBJ) : $(FITZ_HDR) $(PDF_HDR)
$(MUVIEW_X11) : $(MUVIEW_X11_OBJ) $(MUPDF_LIB) $(THIRD_LIB)
	$(LINK_CMD) $(X11_LIBS)

ifeq "$(HAVE_GLFW)" "yes"
MUVIEW_GLFW := $(OUT)/mupdf-gl
MUVIEW_GLFW_OBJ := $(addprefix $(OUT)/platform/gl/, gl-font.o gl-input.o gl-main.o)
$(MUVIEW_GLFW_OBJ) : $(FITZ_HDR) $(PDF_HDR) platform/gl/gl-app.h
$(MUVIEW_GLFW) : $(MUVIEW_GLFW_OBJ) $(MUPDF_LIB) $(THIRD_LIB) $(GLFW_LIB)
	$(LINK_CMD) $(GLFW_LIBS)
endif

ifeq "$(HAVE_CURL)" "yes"
MUVIEW_X11_CURL := $(OUT)/mupdf-x11-curl
MUVIEW_X11_CURL_OBJ := $(addprefix $(OUT)/platform/x11/curl/, x11_main.o x11_image.o pdfapp.o curl_stream.o)
$(MUVIEW_X11_CURL_OBJ) : $(FITZ_HDR) $(PDF_HDR)
$(MUVIEW_X11_CURL) : $(MUVIEW_X11_CURL_OBJ) $(MUPDF_LIB) $(THIRD_LIB) $(CURL_LIB)
	$(LINK_CMD) $(X11_LIBS) $(CURL_LIBS) $(SYS_CURL_DEPS)
endif
endif

ifeq "$(HAVE_WIN32)" "yes"
MUVIEW_WIN32 := $(OUT)/mupdf
MUVIEW_WIN32_OBJ := $(addprefix $(OUT)/platform/x11/, win_main.o pdfapp.o win_res.o)
$(MUVIEW_WIN32_OBJ) : $(FITZ_HDR) $(PDF_HDR)
$(MUVIEW_WIN32) : $(MUVIEW_WIN32_OBJ) $(MUPDF_LIB) $(THIRD_LIB)
	$(LINK_CMD) $(WIN32_LIBS)
endif

MUVIEW := $(MUVIEW_X11) $(MUVIEW_WIN32) $(MUVIEW_GLFW)
MUVIEW_CURL := $(MUVIEW_X11_CURL) $(MUVIEW_WIN32_CURL)

INSTALL_APPS := $(MUTOOL) $(MUVIEW) $(MURASTER) $(MUJSTEST) $(MUVIEW_CURL)

# --- Examples ---

examples: $(OUT)/example $(OUT)/multi-threaded

$(OUT)/example: docs/example.c $(MUPDF_LIB) $(THIRD_LIB)
	$(LINK_CMD) $(CFLAGS)
$(OUT)/multi-threaded: docs/multi-threaded.c $(MUPDF_LIB) $(THIRD_LIB)
	$(LINK_CMD) $(CFLAGS) -lpthread

# --- Update version string header ---

VERSION = $(shell git describe --tags)

version:
	sed -i~ -e '/FZ_VERSION /s/".*"/"'$(VERSION)'"/' include/mupdf/fitz/version.h

# --- Format man pages ---

%.txt: %.1
	nroff -man $< | col -b | expand > $@

MAN_FILES := $(wildcard docs/man/*.1)
TXT_FILES := $(MAN_FILES:%.1=%.txt)

catman: $(TXT_FILES)

# --- Install ---

prefix ?= /usr/local
bindir ?= $(prefix)/bin
libdir ?= $(prefix)/lib
incdir ?= $(prefix)/include
mandir ?= $(prefix)/share/man
docdir ?= $(prefix)/share/doc/mupdf

third: $(THIRD_LIB)
extra: $(CURL_LIB) $(GLFW_LIB)
libs: $(INSTALL_LIBS)
apps: $(INSTALL_APPS)

install: libs apps
	install -d $(DESTDIR)$(incdir)/mupdf
	install -d $(DESTDIR)$(incdir)/mupdf/fitz
	install -d $(DESTDIR)$(incdir)/mupdf/pdf
	install include/mupdf/*.h $(DESTDIR)$(incdir)/mupdf
	install include/mupdf/fitz/*.h $(DESTDIR)$(incdir)/mupdf/fitz
	install include/mupdf/pdf/*.h $(DESTDIR)$(incdir)/mupdf/pdf

	install -d $(DESTDIR)$(libdir)
	install $(INSTALL_LIBS) $(DESTDIR)$(libdir)

	install -d $(DESTDIR)$(bindir)
	install $(INSTALL_APPS) $(DESTDIR)$(bindir)

	install -d $(DESTDIR)$(mandir)/man1
	install docs/man/*.1 $(DESTDIR)$(mandir)/man1

	install -d $(DESTDIR)$(docdir)
	install README COPYING CHANGES docs/*.txt $(DESTDIR)$(docdir)

tarball:
	bash scripts/archive.sh

# --- Clean and Default ---

java:
	$(MAKE) -C platform/java

tags: $(shell find include source platform thirdparty -name '*.[ch]' -or -name '*.cc' -or -name '*.hh')
	$(TAGS_CMD)

cscope.files: $(shell find include source platform -name '*.[ch]')
	@ echo $^ | tr ' ' '\n' > $@

cscope.out: cscope.files
	cscope -b

all: libs apps

clean:
	rm -rf $(OUT)
nuke:
	rm -rf build/* $(GEN) $(NAME_GEN)

release:
	$(MAKE) build=release
debug:
	$(MAKE) build=debug

.PHONY: all clean nuke install third libs apps generate
