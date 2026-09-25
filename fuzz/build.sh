#!/bin/bash -eu
# Copyright (C) 2025 Artifex Software, Inc.
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# OSS-Fuzz build script for MuPDF fuzzers

# Build MuPDF static libraries
make -j$(nproc) libs HAVE_X11=no HAVE_GLUT=no

# List of all 19 fuzzers
FUZZERS="archive cbz cmap colorspace epub filter font html html5 image json path pdf_lexer pdf_object pdf_stream stext svg xml xps"

# Build each fuzzer
for f in $FUZZERS; do
    $CC $CFLAGS -Iinclude \
        fuzz/fuzz_$f.c -o $OUT/fuzz_$f \
        $LIB_FUZZING_ENGINE build/release/libmupdf.a build/release/libmupdf-third.a -lm -lpthread
done

# Copy dictionaries
if [ -d "fuzz/dictionaries" ]; then
    for dict in fuzz/dictionaries/*.dict; do
        if [ -f "$dict" ]; then
            base=$(basename "$dict" .dict)
            cp "$dict" "$OUT/fuzz_${base}.dict" 2>/dev/null || true
        fi
    done
fi

# Create seed corpora
for f in $FUZZERS; do
    if [ -d "fuzz/corpus/$f" ] && [ "$(ls -A fuzz/corpus/$f 2>/dev/null)" ]; then
        zip -jr "$OUT/fuzz_${f}_seed_corpus.zip" "fuzz/corpus/$f/" 2>/dev/null || true
    fi
done

echo "Build complete: $(ls -1 $OUT/fuzz_* | wc -l) artifacts created"
