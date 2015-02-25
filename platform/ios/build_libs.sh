#!/bin/bash

# Call this script from a "Run Script" target in the Xcode project to
# cross compile MuPDF and third party libraries using the regular Makefile.
# Also see "iOS" section in Makerules.

if [ ! -e ../../generated/gen_cmap_korea.h ]
then
	echo 'ERROR: You are missing the generated files.'
	echo 'ERROR: Please run "make generate" from the mupdf directory.'
	exit 1
fi

export OS=ios
export build=$(echo $CONFIGURATION | tr A-Z a-z)

FLAGS="-Wno-unused-function -Wno-empty-body"
for A in $ARCHS
do
	FLAGS="$FLAGS -arch $A"
done

OUT=build/$build-$OS-$(echo $ARCHS | tr ' ' '-')

echo Compiling libraries for $ARCHS.
make -j4 -C ../.. OUT=$OUT XCFLAGS="$FLAGS" XLDFLAGS="$FLAGS" third libs || exit 1

echo Copying library to $BUILT_PRODUCTS_DIR/.
mkdir -p "$BUILT_PRODUCTS_DIR"
cp -f ../../$OUT/lib*.a $BUILT_PRODUCTS_DIR
ranlib $BUILT_PRODUCTS_DIR/lib*.a

echo Done.
