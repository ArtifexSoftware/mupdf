# GNU Makefile

build ?= release

OUT := build/$(build)

default: all

# --- Configuration ---

include Makerules
include Makethird

# Do not specify CFLAGS or LIBS on the make invocation line - specify
# XCFLAGS or XLIBS instead. Make ignores any lines in the makefile that
# set a variable that was set on the command line.
CFLAGS += $(XCFLAGS) -Iinclude
LIBS += $(XLIBS) -lm

LIBS += $(FREETYPE_LIBS)
LIBS += $(HARFBUZZ_LIBS)
LIBS += $(JBIG2DEC_LIBS)
LIBS += $(JPEGXR_LIB)
LIBS += $(LCMS2_LIBS)
LIBS += $(LIBCRYPTO_LIBS)
LIBS += $(LIBJPEG_LIBS)
LIBS += $(LURATECH_LIBS)
LIBS += $(MUJS_LIBS)
LIBS += $(OPENJPEG_LIBS)
LIBS += $(ZLIB_LIBS)

CFLAGS += $(FREETYPE_CFLAGS)
CFLAGS += $(HARFBUZZ_CFLAGS)
CFLAGS += $(JBIG2DEC_CFLAGS)
CFLAGS += $(JPEGXR_CFLAGS)
CFLAGS += $(LCMS2_CFLAGS)
CFLAGS += $(LIBCRYPTO_CFLAGS)
CFLAGS += $(LIBJPEG_CFLAGS)
CFLAGS += $(LURATECH_CFLAGS)
CFLAGS += $(MUJS_CFLAGS)
CFLAGS += $(OPENJPEG_CFLAGS)
CFLAGS += $(ZLIB_CFLAGS)

ALL_DIR := $(OUT)/generated
ALL_DIR += $(OUT)/scripts
ALL_DIR += $(OUT)/source/fitz
ALL_DIR += $(OUT)/source/pdf
ALL_DIR += $(OUT)/source/xps
ALL_DIR += $(OUT)/source/svg
ALL_DIR += $(OUT)/source/cbz
ALL_DIR += $(OUT)/source/html
ALL_DIR += $(OUT)/source/gprf
ALL_DIR += $(OUT)/source/tools
ALL_DIR += $(OUT)/source/helpers
ALL_DIR += $(OUT)/source/helpers/mu-threads
ALL_DIR += $(OUT)/source/helpers/pkcs7
ALL_DIR += $(OUT)/platform/x11
ALL_DIR += $(OUT)/platform/x11/curl
ALL_DIR += $(OUT)/platform/gl

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
QUIET_WINDRES = @ echo ' ' ' ' WINDRES $@ ;
endif

CC_CMD = $(QUIET_CC) $(CC) $(CFLAGS) -o $@ -c $<
CXX_CMD = $(QUIET_CXX) $(CXX) $(filter-out -Wdeclaration-after-statement,$(CFLAGS)) -o $@ -c $<
AR_CMD = $(QUIET_AR) $(AR) cr $@ $^
LINK_CMD = $(QUIET_LINK) $(CC) $(LDFLAGS) -o $@ $^ $(LIBS)
MKDIR_CMD = $(QUIET_MKDIR) mkdir -p $@
RM_CMD = $(QUIET_RM) rm -f $@
TAGS_CMD = $(QUIET_TAGS) ctags $^
WINDRES_CMD = $(QUIET_WINDRES) $(WINDRES) $< $@

# --- Rules ---

$(ALL_DIR) $(OUT) generated :
	$(MKDIR_CMD)

$(OUT)/%.a :
	$(RM_CMD)
	$(AR_CMD)
	$(RANLIB_CMD)

$(OUT)/%.exe: $(OUT)/%.o | $(ALL_DIR)
	$(LINK_CMD)

$(OUT)/source/helpers/mu-threads/%.o : source/helpers/mu-threads/%.c | $(ALL_DIR)
	$(CC_CMD) $(THREADING_CFLAGS)

$(OUT)/source/helpers/pkcs7/%.o : source/helpers/pkcs7/%.c | $(ALL_DIR)
	$(CC_CMD)

$(OUT)/source/tools/%.o : source/tools/%.c | $(ALL_DIR)
	$(CC_CMD) $(THREADING_CFLAGS)

$(OUT)/generated/%.o : generated/%.c | $(ALL_DIR)
	$(CC_CMD) -O0

$(OUT)/platform/x11/%.o : platform/x11/%.c | $(ALL_DIR)
	$(CC_CMD) $(X11_CFLAGS)

$(OUT)/platform/x11/%.o: platform/x11/%.rc | $(ALL_DIR)
	$(WINDRES_CMD)

$(OUT)/platform/x11/curl/%.o : platform/x11/%.c | $(ALL_DIR)
	$(CC_CMD) $(X11_CFLAGS) $(CURL_CFLAGS) -DHAVE_CURL

$(OUT)/platform/gl/%.o : platform/gl/%.c | $(ALL_DIR)
	$(CC_CMD) $(GLUT_CFLAGS)

$(OUT)/%.o : %.c | $(ALL_DIR)
	$(CC_CMD)

$(OUT)/%.o : %.cpp | $(ALL_DIR)
	$(CXX_CMD)

.PRECIOUS : $(OUT)/%.o # Keep intermediates from chained rules

# --- File lists ---

FITZ_HDR := include/mupdf/fitz.h $(wildcard include/mupdf/fitz/*.h)
PDF_HDR := include/mupdf/pdf.h $(wildcard include/mupdf/pdf/*.h)
THREAD_HDR := include/mupdf/helpers/mu-threads.h
PKCS7_HDR := $(sort $(wildcard include/mupdf/helpers/pkcs7-*.h))

FITZ_SRC := $(sort $(wildcard source/fitz/*.c))
PDF_SRC := $(sort $(wildcard source/pdf/*.c))
XPS_SRC := $(sort $(wildcard source/xps/*.c))
SVG_SRC := $(sort $(wildcard source/svg/*.c))
CBZ_SRC := $(sort $(wildcard source/cbz/*.c))
HTML_SRC := $(sort $(wildcard source/html/*.c))
GPRF_SRC := $(sort $(wildcard source/gprf/*.c))
THREAD_SRC := $(sort $(wildcard source/helpers/mu-threads/*.c))
PKCS7_SRC := $(wildcard source/helpers/pkcs7/pkcs7-check.c)
ifeq "$(HAVE_LIBCRYPTO)" "yes"
PKCS7_SRC += $(wildcard source/helpers/pkcs7/pkcs7-openssl.c)
endif

FITZ_SRC_HDR := $(wildcard source/fitz/*.h)
PDF_SRC_HDR := $(wildcard source/pdf/*.h) source/pdf/pdf-name-table.h
XPS_SRC_HDR := $(wildcard source/xps/*.h)
SVG_SRC_HDR := $(wildcard source/svg/*.h)
HTML_SRC_HDR := $(wildcard source/html/*.h)
GPRF_SRC_HDR := $(wildcard source/gprf/*.h)

FITZ_OBJ := $(FITZ_SRC:%.c=$(OUT)/%.o)
PDF_OBJ := $(PDF_SRC:%.c=$(OUT)/%.o)
XPS_OBJ := $(XPS_SRC:%.c=$(OUT)/%.o)
SVG_OBJ := $(SVG_SRC:%.c=$(OUT)/%.o)
CBZ_OBJ := $(CBZ_SRC:%.c=$(OUT)/%.o)
HTML_OBJ := $(HTML_SRC:%.c=$(OUT)/%.o)
GPRF_OBJ := $(GPRF_SRC:%.c=$(OUT)/%.o)
THREAD_OBJ := $(THREAD_SRC:%.c=$(OUT)/%.o)
PKCS7_OBJ := $(PKCS7_SRC:%.c=$(OUT)/%.o)
SIGNATURE_OBJ := $(OUT)/platform/x11/pdfapp.o $(OUT)/source/tools/pdfsign.o

$(FITZ_OBJ) : $(FITZ_HDR) $(FITZ_SRC_HDR)
$(PDF_OBJ) : $(FITZ_HDR) $(PDF_HDR) $(PDF_SRC_HDR)
$(PDF_OBJ) : $(FITZ_SRC_HDR) # ugh, ugly hack for fitz-imp.h + colorspace-imp.h
$(XPS_OBJ) : $(FITZ_HDR) $(XPS_HDR) $(XPS_SRC_HDR)
$(XPS_OBJ) : $(FITZ_SRC_HDR) # ugh, ugly hack for fitz-imp.h
$(SVG_OBJ) : $(FITZ_HDR) $(SVG_HDR) $(SVG_SRC_HDR)
$(CBZ_OBJ) : $(FITZ_HDR) $(CBZ_HDR) $(CBZ_SRC_HDR)
$(HTML_OBJ) : $(FITZ_HDR) $(HTML_HDR) $(HTML_SRC_HDR)
$(GPRF_OBJ) : $(FITZ_HDR) $(GPRF_HDR) $(GPRF_SRC_HDR)
$(THREAD_OBJ) : $(THREAD_HDR)
$(PKCS7_OBJ) : $(FITZ_HDR) $(PDF_HDR) $(PKCS7_HDR)
$(SIGNATURE_OBJ) : $(PKCS7_HDR)

# --- Generated PDF name tables ---

NAMEDUMP_EXE := $(OUT)/scripts/namedump.exe

include/mupdf/pdf.h : include/mupdf/pdf/name-table.h
NAME_GEN := include/mupdf/pdf/name-table.h source/pdf/pdf-name-table.h
$(NAME_GEN) : resources/pdf/names.txt
	$(QUIET_GEN) $(NAMEDUMP_EXE) resources/pdf/names.txt $(NAME_GEN)

ifneq "$(CROSSCOMPILE)" "yes"
$(NAME_GEN) : $(NAMEDUMP_EXE)
endif

$(OUT)/source/pdf/pdf-object.o : source/pdf/pdf-name-table.h

generate: $(NAME_GEN)

# --- Generated embedded font files ---

HEXDUMP_EXE := $(OUT)/scripts/hexdump.exe

FONT_BIN_DROID := $(sort $(wildcard resources/fonts/droid/*.ttf))
FONT_BIN_NOTO := $(sort $(wildcard resources/fonts/noto/*.ttf))
FONT_BIN_HAN := $(sort $(wildcard resources/fonts/han/*.otf))
FONT_BIN_URW := $(sort $(wildcard resources/fonts/urw/*.cff))
FONT_BIN_SIL := $(sort $(wildcard resources/fonts/sil/*.cff))

FONT_GEN_DROID := $(subst resources/fonts/droid/, generated/, $(addsuffix .c, $(basename $(FONT_BIN_DROID))))
FONT_GEN_NOTO := $(subst resources/fonts/noto/, generated/, $(addsuffix .c, $(basename $(FONT_BIN_NOTO))))
FONT_GEN_HAN := $(subst resources/fonts/han/, generated/, $(addsuffix .c, $(basename $(FONT_BIN_HAN))))
FONT_GEN_URW := $(subst resources/fonts/urw/, generated/, $(addsuffix .c, $(basename $(FONT_BIN_URW))))
FONT_GEN_SIL := $(subst resources/fonts/sil/, generated/, $(addsuffix .c, $(basename $(FONT_BIN_SIL))))

FONT_BIN := $(FONT_BIN_DROID) $(FONT_BIN_NOTO) $(FONT_BIN_HAN) $(FONT_BIN_URW) $(FONT_BIN_SIL)
FONT_GEN := $(FONT_GEN_DROID) $(FONT_GEN_NOTO) $(FONT_GEN_HAN) $(FONT_GEN_URW) $(FONT_GEN_SIL)
FONT_OBJ := $(FONT_GEN:%.c=$(OUT)/%.o)

generated/%.c : resources/fonts/droid/%.ttf $(HEXDUMP_EXE) | generated
	$(QUIET_GEN) $(HEXDUMP_EXE) -s $@ $<
generated/%.c : resources/fonts/noto/%.ttf $(HEXDUMP_EXE) | generated
	$(QUIET_GEN) $(HEXDUMP_EXE) -s $@ $<
generated/%.c : resources/fonts/han/%.otf $(HEXDUMP_EXE) | generated
	$(QUIET_GEN) $(HEXDUMP_EXE) -s $@ $<
generated/%.c : resources/fonts/urw/%.cff $(HEXDUMP_EXE) | generated
	$(QUIET_GEN) $(HEXDUMP_EXE) -s $@ $<
generated/%.c : resources/fonts/sil/%.cff $(HEXDUMP_EXE) | generated
	$(QUIET_GEN) $(HEXDUMP_EXE) -s $@ $<

$(FONT_OBJ) : $(FONT_GEN)
$(FONT_GEN_DROID) : $(FONT_BIN_DROID)
$(FONT_GEN_NOTO) : $(FONT_BIN_NOTO)
$(FONT_GEN_HAN) : $(FONT_BIN_HAN)
$(FONT_GEN_URW) : $(FONT_BIN_URW)
$(FONT_GEN_SIL) : $(FONT_BIN_SIL)

ifneq "$(CROSSCOMPILE)" "yes"
$(FONT_GEN) : $(HEXDUMP_EXE)
endif

generate: $(FONT_GEN)

# --- Generated ICC profiles ---

ICC_BIN := resources/icc/gray.icc resources/icc/rgb.icc resources/icc/cmyk.icc resources/icc/lab.icc
ICC_GEN := generated/icc-profiles.c
ICC_OBJ := $(ICC_GEN:%.c=$(OUT)/%.o)

$(ICC_OBJ) : $(ICC_GEN)
$(ICC_GEN) : $(ICC_BIN) | generated
	$(QUIET_GEN) $(HEXDUMP_EXE) $@ $(ICC_BIN)

ifneq "$(CROSSCOMPILE)" "yes"
$(ICC_GEN) : $(HEXDUMP_EXE)
endif

generate: $(ICC_GEN)

# --- Generated CMap files ---

CMAPDUMP_EXE := $(OUT)/scripts/cmapdump.exe

CMAP_CJK_SRC := $(sort $(wildcard resources/cmaps/cjk/*))
CMAP_EXTRA_SRC := $(sort $(wildcard resources/cmaps/extra/*))
CMAP_UTF8_SRC := $(sort $(wildcard resources/cmaps/utf8/*))
CMAP_UTF32_SRC := $(sort $(wildcard resources/cmaps/utf32/*))

CMAP_GEN := \
	generated/pdf-cmap-cjk.c \
	generated/pdf-cmap-extra.c \
	generated/pdf-cmap-utf8.c \
	generated/pdf-cmap-utf32.c
CMAP_OBJ := $(CMAP_GEN:%.c=$(OUT)/%.o)

generated/pdf-cmap-cjk.c : $(CMAP_CJK_SRC) | generated
	$(QUIET_GEN) $(CMAPDUMP_EXE) $@ $(CMAP_CJK_SRC)
generated/pdf-cmap-extra.c : $(CMAP_EXTRA_SRC) | generated
	$(QUIET_GEN) $(CMAPDUMP_EXE) $@ $(CMAP_EXTRA_SRC)
generated/pdf-cmap-utf8.c : $(CMAP_UTF8_SRC) | generated
	$(QUIET_GEN) $(CMAPDUMP_EXE) $@ $(CMAP_UTF8_SRC)
generated/pdf-cmap-utf32.c : $(CMAP_UTF32_SRC) | generated
	$(QUIET_GEN) $(CMAPDUMP_EXE) $@ $(CMAP_UTF32_SRC)

$(CMAP_OBJ) : $(CMAP_GEN)

ifneq "$(CROSSCOMPILE)" "yes"
$(CMAP_GEN) : $(CMAPDUMP_EXE)
endif

generate: $(CMAP_GEN)

$(OUT)/scripts/cmapdump.o : \
	$(NAME_GEN) \
	include/mupdf/pdf/cmap.h \
	source/fitz/context.c \
	source/fitz/error.c \
	source/fitz/memory.c \
	source/fitz/output.c \
	source/fitz/string.c \
	source/fitz/buffer.c \
	source/fitz/stream-open.c \
	source/fitz/stream-read.c \
	source/fitz/strtof.c \
	source/fitz/ftoa.c \
	source/fitz/printf.c \
	source/fitz/time.c \
	source/pdf/pdf-lex.c \
	source/pdf/pdf-cmap.c \
	source/pdf/pdf-cmap-parse.c \

# --- Generated embedded javascript files ---

JAVASCRIPT_SRC := source/pdf/pdf-js-util.js
JAVASCRIPT_GEN := generated/pdf-js-util.c
JAVASCRIPT_OBJ := $(JAVASCRIPT_GEN:%.c=$(OUT)/%.o)

$(JAVASCRIPT_GEN) : $(JAVASCRIPT_SRC) | generated
	$(QUIET_GEN) $(HEXDUMP_EXE) -0 $@ $(JAVASCRIPT_SRC)

ifneq "$(CROSSCOMPILE)" "yes"
$(JAVASCRIPT_GEN) : $(HEXDUMP_EXE)
endif

$(JAVASCRIPT_OBJ) : $(JAVASCRIPT_GEN)

generate: $(JAVASCRIPT_GEN)

# --- Library ---

MUPDF_LIB = $(OUT)/libmupdf.a
THIRD_LIB = $(OUT)/libmupdfthird.a
THREAD_LIB = $(OUT)/libmuthreads.a
PKCS7_LIB = $(OUT)/libmupkcs7.a

MUPDF_OBJ := \
	$(FITZ_OBJ) \
	$(PDF_OBJ) \
	$(CMAP_OBJ) \
	$(FONT_OBJ) \
	$(JAVASCRIPT_OBJ) \
	$(XPS_OBJ) \
	$(SVG_OBJ) \
	$(CBZ_OBJ) \
	$(HTML_OBJ) \
	$(GPRF_OBJ) \
	$(ICC_OBJ)

THIRD_OBJ := \
	$(FREETYPE_OBJ) \
	$(HARFBUZZ_OBJ) \
	$(JBIG2DEC_OBJ) \
	$(JPEGXR_OBJ) \
	$(LIBJPEG_OBJ) \
	$(LURATECH_OBJ) \
	$(MUJS_OBJ) \
	$(OPENJPEG_OBJ) \
	$(ZLIB_OBJ) \
	$(LCMS2_OBJ)

$(MUPDF_LIB) : $(MUPDF_OBJ)
$(THIRD_LIB) : $(THIRD_OBJ)
$(THREAD_LIB) : $(THREAD_OBJ)
$(PKCS7_LIB) : $(PKCS7_OBJ)

INSTALL_LIBS := $(MUPDF_LIB) $(THIRD_LIB)

# --- Tools and Apps ---

MUTOOL_EXE := $(OUT)/mutool
MUTOOL_SRC := source/tools/mutool.c source/tools/muconvert.c source/tools/mudraw.c source/tools/murun.c source/tools/mutrace.c
MUTOOL_SRC += $(sort $(wildcard source/tools/pdf*.c))
MUTOOL_OBJ := $(MUTOOL_SRC:%.c=$(OUT)/%.o)
$(MUTOOL_OBJ) : $(FITZ_HDR) $(PDF_HDR)
$(MUTOOL_EXE) : $(MUTOOL_OBJ) $(MUPDF_LIB) $(THIRD_LIB) $(THREAD_LIB) $(PKCS7_LIB)
	$(LINK_CMD) $(THREADING_LIBS)

MURASTER_EXE := $(OUT)/muraster
MURASTER_OBJ := $(OUT)/source/tools/muraster.o
$(MURASTER_OBJ) : $(FITZ_HDR)
$(MURASTER_EXE) : $(MURASTER_OBJ) $(MUPDF_LIB) $(THIRD_LIB) $(THREAD_LIB)
	$(LINK_CMD) $(THREADING_LIBS)

MJSGEN_EXE := $(OUT)/mjsgen
MJSGEN_OBJ := $(OUT)/source/tools/mjsgen.o
$(MJSGEN_OBJ) : $(FITZ_HDR) $(PDF_HDR)
$(MJSGEN_EXE) : $(MJSGEN_OBJ) $(MUPDF_LIB) $(THIRD_LIB)
	$(LINK_CMD)

MUJSTEST_EXE := $(OUT)/mujstest
MUJSTEST_OBJ := $(addprefix $(OUT)/platform/x11/, jstest_main.o pdfapp.o)
$(MUJSTEST_OBJ) : $(FITZ_HDR) $(PDF_HDR)
$(MUJSTEST_EXE) : $(MUJSTEST_OBJ) $(MUPDF_LIB) $(THIRD_LIB) $(PKCS7_LIB)
	$(LINK_CMD)

ifeq "$(HAVE_X11)" "yes"
MUVIEW_X11_EXE := $(OUT)/mupdf-x11
MUVIEW_X11_OBJ := $(addprefix $(OUT)/platform/x11/, x11_main.o x11_image.o pdfapp.o)
$(MUVIEW_X11_OBJ) : $(FITZ_HDR) $(PDF_HDR)
$(MUVIEW_X11_EXE) : $(MUVIEW_X11_OBJ) $(MUPDF_LIB) $(THIRD_LIB) $(PKCS7_LIB)
	$(LINK_CMD) $(X11_LIBS)

ifeq "$(HAVE_CURL)" "yes"
MUVIEW_X11_CURL_EXE := $(OUT)/mupdf-x11-curl
MUVIEW_X11_CURL_OBJ := $(addprefix $(OUT)/platform/x11/curl/, x11_main.o x11_image.o pdfapp.o curl_stream.o)
$(MUVIEW_X11_CURL_OBJ) : $(FITZ_HDR) $(PDF_HDR)
$(MUVIEW_X11_CURL_EXE) : $(MUVIEW_X11_CURL_OBJ) $(MUPDF_LIB) $(THIRD_LIB) $(CURL_LIB) $(PKCS7_LIB)
	$(LINK_CMD) $(X11_LIBS) $(CURL_LIBS) $(SYS_CURL_DEPS)
endif
endif

ifeq "$(HAVE_GLUT)" "yes"
MUVIEW_GLUT_EXE := $(OUT)/mupdf-gl
MUVIEW_GLUT_OBJ := $(addprefix $(OUT)/platform/gl/, gl-font.o gl-input.o gl-main.o)
$(MUVIEW_GLUT_OBJ) : $(FITZ_HDR) $(PDF_HDR) platform/gl/gl-app.h
$(MUVIEW_GLUT_EXE) : $(MUVIEW_GLUT_OBJ) $(MUPDF_LIB) $(THIRD_LIB) $(GLUT_LIB)
	$(LINK_CMD) $(GLUT_LIB) $(GLUT_LIBS)
endif

ifeq "$(HAVE_WIN32)" "yes"
MUVIEW_WIN32_EXE := $(OUT)/mupdf
MUVIEW_WIN32_OBJ := $(addprefix $(OUT)/platform/x11/, win_main.o pdfapp.o win_res.o)
$(MUVIEW_WIN32_OBJ) : $(FITZ_HDR) $(PDF_HDR)
$(MUVIEW_WIN32_EXE) : $(MUVIEW_WIN32_OBJ) $(MUPDF_LIB) $(THIRD_LIB) $(PKCS7_LIB)
	$(LINK_CMD) $(WIN32_LIBS)
endif

MUVIEW_EXE := $(MUVIEW_X11_EXE) $(MUVIEW_WIN32_EXE) $(MUVIEW_GLUT_EXE)
MUVIEW_CURL_EXE := $(MUVIEW_X11_CURL_EXE) $(MUVIEW_WIN32_CURL_EXE)

INSTALL_APPS := $(MUTOOL_EXE) $(MUVIEW_EXE)
EXTRA_APPS += $(MURASTER_EXE)
EXTRA_APPS += $(MUVIEW_CURL_EXE)
EXTRA_APPS += $(MUJSTEST_EXE)
EXTRA_APPS += $(MJSGEN_EXE)

# --- Examples ---

examples: $(OUT)/example $(OUT)/multi-threaded

$(OUT)/example: docs/examples/example.c $(MUPDF_LIB) $(THIRD_LIB)
	$(LINK_CMD) $(CFLAGS)
$(OUT)/multi-threaded: docs/examples/multi-threaded.c $(MUPDF_LIB) $(THIRD_LIB)
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
extra-libs: $(CURL_LIB) $(GLUT_LIB)
libs: $(INSTALL_LIBS)
apps: $(INSTALL_APPS)
extra-apps: $(EXTRA_APPS)
extra: extra-libs extra-apps

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
	install -d $(DESTDIR)$(docdir)/examples
	install README COPYING CHANGES $(DESTDIR)$(docdir)
	install docs/*.html docs/*.css docs/*.png $(DESTDIR)$(docdir)
	install docs/examples/* $(DESTDIR)$(docdir)/examples

tarball:
	bash scripts/archive.sh

# --- Clean and Default ---

WATCH_SRCS := $(shell find include source platform -type f -name '*.[ch]')
watch:
	@ while ! inotifywait -q -e modify $(WATCH_SRCS) ; do time -p $(MAKE) ; done

java:
	$(MAKE) -C platform/java

tags: $(shell find include source platform thirdparty -name '*.[ch]' -or -name '*.cc' -or -name '*.hh' -or -name '*.java')
	$(TAGS_CMD)

cscope.files: $(shell find include source platform -name '*.[ch]')
	@ echo $^ | tr ' ' '\n' > $@

cscope.out: cscope.files
	cscope -b

all: libs apps

clean:
	rm -rf $(OUT)
nuke:
	rm -rf build/* generated $(NAME_GEN)

release:
	$(MAKE) build=release
debug:
	$(MAKE) build=debug
sanitize:
	$(MAKE) build=sanitize
tofu:
	$(MAKE) OUT=build/tofu CMAP_GEN= FONT_GEN_DROID= FONT_GEN_NOTO= FONT_GEN_HAN= FONT_GEN_SIL= XCFLAGS="-DNOCJK -DTOFU"
tofumax:
	$(MAKE) OUT=build/tofumax CMAP_GEN= FONT_GEN= XCFLAGS="-DNOCJK -DTOFU -DTOFU_BASE14"

android: generate
	ndk-build -j8 \
		APP_BUILD_SCRIPT=platform/java/Android.mk \
		APP_PROJECT_PATH=build/android \
		APP_PLATFORM=android-16 \
		APP_OPTIM=$(build)

.PHONY: all clean nuke install third libs apps generate
