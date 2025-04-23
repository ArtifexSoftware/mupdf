#!/bin/bash

EMSDK_DIR=/opt/emsdk

XCFLAGS="-Os"
XCFLAGS="$XCFLAGS -DTOFU"
XCFLAGS="$XCFLAGS -DTOFU_CJK_EXT"
XCFLAGS="$XCFLAGS -DMEMENTO_STACKTRACE_METHOD=0"
XCFLAGS="$XCFLAGS -DFZ_ENABLE_XPS=0"
XCFLAGS="$XCFLAGS -DFZ_ENABLE_SVG=0"
XCFLAGS="$XCFLAGS -DFZ_ENABLE_OCR_OUTPUT=0"

export EMSDK_QUIET=1
source $EMSDK_DIR/emsdk_env.sh
echo

emsdk activate 4.0.8 >/dev/null || exit

BUILD=${1:-release}

echo BUILDING MUPDF CORE
make --no-print-directory -j4 -C ../.. build=$BUILD OS=wasm XCFLAGS="$XCFLAGS" brotli=no mujs=no libs
echo

echo BUILDING MUPDF WASM
mkdir -p dist
emcc -o dist/mupdf-wasm.js -I ../../include lib/mupdf.c \
	--no-entry \
	-sABORTING_MALLOC=0 \
	-sALLOW_MEMORY_GROWTH=1 \
	-sNODEJS_CATCH_EXIT=0 \
	-sMODULARIZE=1 \
	-sEXPORT_ES6=1 \
	-sEXPORT_NAME='"libmupdf_wasm"' \
	-sEXPORTED_RUNTIME_METHODS='["UTF8ToString","lengthBytesUTF8","stringToUTF8","HEAPU8","HEAPU32","HEAPF32"]' \
	 ../../build/wasm/$BUILD/libmupdf.a \
	 ../../build/wasm/$BUILD/libmupdf-third.a
echo

echo BUILDING TYPESCRIPT
cat lib/mupdf.c | sed '/#include/d' | emcc -E - | node tools/make-wasm-type.js > lib/mupdf-wasm.d.ts
npx tsc -p .
