#!/bin/sh

# Call this script from a "Run Script" target in the Xcode project to
# set up the environment and use the regular makefile to cross compile
# MuPDF and third party libraries.

# Ensure we have all the generated cmap and font files from a
# regular build.
make -C .. generate

OS=$(basename $PLATFORM_DIR | sed s/\.platform// | tr A-Z a-z)
build=$(echo $BUILD_STYLE | tr A-Z a-z)
make -C .. CROSSCOMPILE=yes libs || exit 1
mkdir -p "$BUILT_PRODUCTS_DIR"
cp ../build/$build-$OS/lib*.a "$BUILT_PRODUCTS_DIR"

echo Done.
