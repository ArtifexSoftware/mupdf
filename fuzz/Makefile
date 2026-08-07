# Copyright (C) 2025 Artifex Software, Inc.
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Makefile for building MuPDF fuzzers locally
#
# Usage:
#   make                  # Build all fuzzers
#   make fuzz_image       # Build specific fuzzer
#   make run_image        # Run fuzzer with corpus
#   make clean            # Remove built fuzzers
#
# Prerequisites:
#   - clang with fuzzer support
#   - MuPDF libraries built: make -C .. libs HAVE_X11=no HAVE_GLUT=no

MUPDF_ROOT = ..
CC = clang
CFLAGS = -g -O1 -fno-omit-frame-pointer \
         -fsanitize=fuzzer,address,undefined \
         -I$(MUPDF_ROOT)/include
LDFLAGS = -fsanitize=fuzzer,address,undefined
LIBS = $(MUPDF_ROOT)/build/release/libmupdf.a \
       $(MUPDF_ROOT)/build/release/libmupdf-third.a \
       -lm -lpthread

FUZZERS = fuzz_archive fuzz_cbz fuzz_cmap fuzz_colorspace fuzz_epub \
          fuzz_filter fuzz_font fuzz_html fuzz_html5 fuzz_image \
          fuzz_json fuzz_path fuzz_pdf_lexer fuzz_pdf_object \
          fuzz_pdf_stream fuzz_stext fuzz_svg fuzz_xml fuzz_xps

.PHONY: all clean run_% libs

all: libs $(FUZZERS)

libs:
	$(MAKE) -C $(MUPDF_ROOT) libs HAVE_X11=no HAVE_GLUT=no

fuzz_%: fuzz_%.c $(MUPDF_ROOT)/build/release/libmupdf.a
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS) $(LIBS)

# Run a fuzzer with its corpus (e.g., make run_image)
run_%: fuzz_%
	@mkdir -p corpus/$*
	./fuzz_$* corpus/$* $(if $(wildcard corpus/$*/*),,-max_total_time=60)

clean:
	rm -f $(FUZZERS)
	rm -rf corpus/*/crash-* corpus/*/oom-*

# Coverage build (for measuring code coverage)
coverage: CFLAGS = -g -O1 -fprofile-instr-generate -fcoverage-mapping -I$(MUPDF_ROOT)/include
coverage: LDFLAGS = -fprofile-instr-generate -fcoverage-mapping
coverage: clean all
