#!/bin/bash

# Call this script from a "Run Script" target in the Xcode project to
# cross compile MuPDF and third party libraries using the regular Makefile.
# Also see "iOS" section in Makerules.

echo Generating cmap and font files
make -C .. generate || exit 1

export OS=ios
export build=$(echo $BUILD_STYLE | tr A-Z a-z)

for ARCH in $ARCHS
do
	case $ARCH in
		armv6) ARCHFLAGS="-arch armv6 -mno-thumb" ;;
		armv7) ARCHFLAGS="-arch armv7 -mthumb" ;;
		*) ARCHFLAGS="-arch $ARCH" ;;
	esac

	export CFLAGS="$ARCHFLAGS -isysroot $SDKROOT"
	export LDFLAGS="$ARCHFLAGS -isysroot $SDKROOT"
	export OUT=build/$build-$OS-$ARCH

	echo Building libraries for $ARCH.
	make -C .. libs || exit 1
done

echo Performing liposuction

mkdir -p "$BUILT_PRODUCTS_DIR"

for LIB in ../$OUT/lib*.a
do
	LIB=$(basename $LIB)
	IN=""
	for ARCH in $ARCHS
	do
		IN="$IN ../build/$build-$OS-$ARCH/$LIB"
	done
	lipo $IN -output $BUILT_PRODUCTS_DIR/$LIB -create
done

echo Done.
