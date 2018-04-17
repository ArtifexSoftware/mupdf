#!/bin/bash
# Create Makefile for win32 nmake to build fontdump resources.
# Also generate fontdump resources locally.

FONTS="resources/fonts/urw/*.cff resources/fonts/han/*.ttc resources/fonts/droid/*.ttf resources/fonts/noto/*.ttf resources/fonts/noto/*.otf resources/fonts/sil/*.cff"
OUT=scripts/fontdump.nmake.tmp

echo -e >$OUT "# This is an automatically generated file. Do not edit. */"
echo -e >>$OUT "default: generate"
echo -e >>$OUT "hexdump.exe: scripts/hexdump.c"
echo -e >>$OUT "\tcl /nologo scripts/hexdump.c setargv.obj"

mkdir -p build
cc -O2 -o build/hexdump.exe scripts/hexdump.c

DIRS=$(dirname $FONTS | sort -u)
for D in $DIRS
do
	echo -e >>$OUT "generated/$D:"
	echo -e >>$OUT "\tmkdir generated/$D"
done

for F in $FONTS
do
	C=$(echo generated/$F.c)
	D=$(dirname $C)

	echo $C
	mkdir -p $D
	#./build/hexdump.exe -s $C $F

	echo -e >>$OUT "generate: $C"
	echo -e >>$OUT "$C: $F $D hexdump.exe"
	echo -e >>$OUT "\thexdump.exe $C $F"
done

tr / \\\\ < $OUT > scripts/fontdump.nmake
rm -f $OUT
