/*
 * Bidirectional text processing.
 *
 * Derived from the SmartOffice code, which is itself derived
 * from the example unicode standard code. Original copyright
 * messages follow:
 *
 * Copyright (C) Picsel, 2004-2008. All Rights Reserved.
 *
 * Processes Unicode text by arranging the characters into an order suitable
 * for display. E.g. Hebrew text will be arranged from right-to-left and
 * any English within the text will remain in the left-to-right order.
 *
 * This is an implementation of the Unicode Bidirectional Algorithm which
 * can be found here: http://www.unicode.org/reports/tr9/ and is based
 * on the reference implementation found on Unicode.org.
 */

#ifndef FITZ_BIDI_H
#define FITZ_BIDI_H

#include "mupdf/fitz/system.h"

typedef enum fz_bidi_direction_e
{
	BIDI_LEFT_TO_RIGHT = 0,
	BIDI_RIGHT_TO_LEFT = 1,
	BIDI_NEUTRAL = 2
}
fz_bidi_direction;

typedef enum fz_bidi_flags_e
{
	BIDI_CLASSIFY_WHITE_SPACE = 1,
	BIDI_REPLACE_TAB = 2
}
fz_bidi_flags;

typedef uint8_t fz_bidi_chartype;
typedef int fz_bidi_level; /*   Note: Max level is 125 */

enum
{
	BIDI_LEVEL_MAX = 125 /* Updated for 6.3.0 */
};

/**
 * Prototype for callback function supplied to Bidi_fragmentText.
 *
 * @param	fragment	first character in fragment
 * @param	fragmentLen	number of characters in fragment
 * @param	block_r2l	true if block should concatenate with other blocks
 *				as right-to-left
 * @param	char_r2l	true if characters within block should be laid out
 *				as right-to-left
 * @param       script          the script in use for this fragment (other than common
 *                              or inherited)
 * @param	arg		data from caller of Bidi_fragmentText
 */
typedef void (fz_bidi_fragment_callback)(const uint32_t *fragment,
					size_t fragmentLen,
					int block_r2l,
					int char_r2l,
					int script,
					void *arg);

/**
 * Partitions the given Unicode sequence into one or more unidirectional
 * fragments and invokes the given callback function for each fragment.
 *
 * For example, if directionality of text is:
 *			0123456789
 *			rrlllrrrrr,
 * we'll invoke callback with:
 *			&text[0], length == 2, rightToLeft ==  true
 *			&text[2], length == 3, rightToLeft == false
 *			&text[5], length == 5, rightToLeft ==  true.
 *
 * @param[in] text	start of Unicode sequence
 * @param[in] textlen   number of Unicodes to analyse
 * @param[in] baseDir   direction of paragraph (specify BIDI_NEUTRAL
 *				to force auto-detection)
 * @param[in] callback  function to be called for each fragment
 * @param[in] arg	data to be passed to the callback function
 * @param[in] flags     flags to control operation (see fz_bidi_flags above)
 */
void fz_bidi_fragment_text(fz_context *ctx,
			const uint32_t *text,
			size_t textlen,
			fz_bidi_direction *baseDir,
			fz_bidi_fragment_callback *callback,
			void *arg,
			int flags);

#endif /* FITZ_BIDI_H */
