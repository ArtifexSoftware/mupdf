/*
	Bidirectional text processing.

	Derived from the SmartOffice code, which is itself derived
	from the example unicode standard code. Original copyright
	messages follow:

	Copyright (C) Picsel, 2004-2008. All Rights Reserved.

	Processes Unicode text by arranging the characters into an order
	suitable for display. E.g. Hebrew text will be arranged from
	right-to-left and any English within the text will remain in the
	left-to-right order.

	This is an implementation of the Unicode Bidirectional Algorithm
	which can be found here: http://www.unicode.org/reports/tr9/ and
	is based on the reference implementation found on Unicode.org.
*/

#ifndef MUPDF_FITZ_BIDI_H
#define MUPDF_FITZ_BIDI_H

#include "mupdf/fitz/system.h"
#include "mupdf/fitz/context.h"

typedef enum fz_bidi_direction
{
	FZ_BIDI_LTR = 0,
	FZ_BIDI_RTL = 1,
	FZ_BIDI_NEUTRAL = 2,
	FZ_BIDI_UNSET = 3
} fz_bidi_direction;

typedef enum fz_bidi_flags
{
	FZ_BIDI_CLASSIFY_WHITE_SPACE = 1,
	FZ_BIDI_REPLACE_TAB = 2
} fz_bidi_flags;

/*
	Prototype for callback function supplied to fz_bidi_fragment_text.

	fragment:
		first character in fragment

	fragmentLen:
		number of characters in fragment

	bidiLevel:
		The bidirectional level for this text.
		The bottom bit will be set iff block
		should concatenate with other blocks as
		right-to-left.

	script:
		The script in use for this fragment (other than common or inherited)

	arg:
		Data from caller of Bidi_fragmentText
*/
typedef void (fz_bidi_fragment_fn)(
	const uint32_t *fragment,
	size_t fragmentLen,
	int bidiLevel,
	int script,
	void *arg
);

/*
	Partitions the given Unicode sequence into one or more
	unidirectional fragments and invokes the given callback
	function for each fragment.

	For example, if directionality of text is:

		0123456789
		rrlllrrrrr,

	we'll invoke callback with:

		&text[0], length == 2
		&text[2], length == 3
		&text[5], length == 5

	text:
		start of Unicode sequence

	textlen:
		number of Unicodes to analyse

	baseDir:
		direction of paragraph (specify FZ_BIDI_NEUTRAL to force auto-detection)

	callback:
		function to be called for each fragment

	arg:
		data to be passed to the callback function

	flags:
		flags to control operation (see fz_bidi_flags above)
*/
void fz_bidi_fragment_text(
	fz_context *ctx,
	const uint32_t *text,
	size_t textlen,
	fz_bidi_direction *baseDir,
	fz_bidi_fragment_fn *callback,
	void *arg,
	int flags
);

#endif
