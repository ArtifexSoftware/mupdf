/**
  * Bidirectional text processing.
  *
  */
/* Copyright (C) Picsel, 2004-2008. All Rights Reserved. */
/** @defgroup BidiText
 *  @ingroup EpageText
 *  @{
 * Bidirectional text processing.
 *
 * Processes Unicode text by arranging the characters into an order suitable
 * for display. E.g. Hebrew text will be arranged from right-to-left and
 * any English within the text will remain in the left-to-right order.
 * Characters such as parenthesis will be substituted for their mirrored
 * equivalents if they are part of text which must be reversed.
 *
 * This is an implementation of the Unicode Bidirectional Algorithm which
 * can be found here: http://www.unicode.org/reports/tr9/ and is based
 * on the reference implementation found on Unicode.org.
 */

#ifndef BIDI_BIDI_H
#define BIDI_BIDI_H

#include "mupdf/fitz/system.h"


/* Bidirectional Character Types
 * as defined by the Unicode Bidirectional Algorithm Table 3-7.
 * The list of bidirectional character types here is not grouped the
 * same way as the table 3-7, since the numeric values for the types
 * are chosen to keep the state and action tables compact.
 */
enum
{
    /* input types */
             /* ON MUST be zero, code relies on ON = N = 0 */
    BDI_ON = 0, /**< Other Neutral  */
    BDI_L,      /**< Left-to-right Letter */
    BDI_R,      /**< Right-to-left Letter */
    BDI_AN,     /**< Arabic Number */
    BDI_EN,     /**< European Number */
    BDI_AL,     /**< Arabic Letter (Right-to-left) */
    BDI_NSM,    /**< Non-spacing Mark */
    BDI_CS,     /**< Common Separator */
    BDI_ES,     /**< European Separator */
    BDI_ET,     /**< European Terminator (post/prefix e.g. $ and %) */

    /* resolved types */
    BDI_BN,     /**< Boundary neutral (type of RLE etc after explicit levels)*/

    /* input types, */
    BDI_S,      /**< Segment Separator (TAB)         used only in L1 */
    BDI_WS,     /**< White space                     used only in L1 */
    BDI_B,      /**< Paragraph Separator (aka as PS) */

    /* types for explicit controls */
    BDI_RLO,    /**< these are used only in X1-X9 */
    BDI_RLE,
    BDI_LRO,
    BDI_LRE,
    BDI_PDF,

    /* resolved types, also resolved directions */
    BDI_N = BDI_ON   /**< alias, where ON, WS and S are treated the same */
};

typedef enum Bidi_Direction
{
    Bidi_LeftToRight = 0,
    Bidi_RightToLeft = 1,
    Bidi_Neutral     = 2
}
Bidi_Direction;

typedef enum Bidi_Flags
{
    Bidi_classifyWhiteSpace  = 1,
    Bidi_replaceTab          = 2
}
Bidi_Flags;

typedef int Bidi_CharType; /**< Same as in the third-party library */
typedef int Bidi_Level;    /**< Same as in the third-party library.
                            *   Note: Max level is 61 */

enum
{
    Bidi_LevelMax = 61
};



/**
 * Prototype for function supplied to Bidi_processLine and
 * invoked for each fragment.
 *
 * @param     offset        first character in fragment
 * @param     fragmentLen   number of characters in fragment
 * @param     rightToLeft   true if fragment is right-to-left
 * @param     mirror        The mirror code of the fragment if it exists
 * @param     arg           data from caller of Bidi_processLine
 * @param     isRtlNumber   true if fragment contains only RTL numbers.
 */
typedef void (Bidi_PL_Fragment_Callback)(unsigned int    offset,
                                         size_t          fragmentLen,
                                         int             rightToLeft,
                                         uint16_t        mirror,
                                         void           *arg,
                                         int            isRtlNumber);



/**
 * Prototype for function supplied to Bidi_processLine, which invokes it
 * repeatedly to build a single 'string' to represent the entire line.
 *
 * @param     arg           data from caller of Bidi_processLine.
 * @param     objText       receives pointer to either the object's text or
 *                          NULL if there are no more objects on the line.
 * @param     objLength     receives length of object's text.
 * @param     more          receives true if there is more text on this 'line'.
 * @param     explicitDirection     receives Explicit direction of object'stext.
 *                          Bidi_Neutral can be passed if no Direction is specified.
 */
typedef void (Bidi_PL_NextObj_Callback)(void            *arg,
                                        const uint16_t **objText,
                                        size_t          *objLength,
                                        int             *more,
                                        Bidi_Direction  *explicitDirection);



/**
 * Converts text from logical to display order.  The conversion
 * is in-place, i.e. the given string is changed by this function.
 *
 * @param     text input/output text
 * @param[in] baseDir  base direction
 * @param[in] outputDir  render direction
 * @param[in] len  string length
 *
 * @return              error
 */
void Bidi_processText(fz_context *ctx,
		      uint16_t       *text,
                      Bidi_Direction  baseDir,
                      Bidi_Direction  outputDir,
                      int             len);



/**
 * Determines the bidi class for a single character
 *
 * @param[in]  ch  The character
 *
 * @return         The bidi character type
 */
Bidi_CharType Bidi_classFromChN(uint16_t ch);



/**
 * Determines the character classes for given text
 *
 * @param[in]  text               input text
 * @param[out] types              output types
 * @param[in]  len                text length
 * @param[in]  flags              classifyWhiteSpace, forceRightToLeft
 */
void Bidi_classifyCharacters(const uint16_t *text,
                             Bidi_CharType  *types,
                             int             len,
                             Bidi_Flags      flags);



/**
 * Iterates over a collection of strings, and rearranges them
 * according to their directions.
 *
 * @param[in] nextObjCb   function invoked repeatedly to describe the
 *                        collection of strings on the line.
 * @param[in] fragmentCb  function to be invoked for each fragment.
 * @param[in] callerData  caller-defined structure which will be passed
 *                        to each of the callback functions.
 * @param[in] bidiFlag    Bidi flag passed to the function.
 * @param[out] more       Location to place true if the "line" has more
 *                        data
 *
 * @returns direction of paragraph
 */
Bidi_Direction Bidi_processLine(fz_context *ctx,
				Bidi_PL_NextObj_Callback    nextObjCb,
                                Bidi_PL_Fragment_Callback   fragmentCb,
                                void                       *callerData,
                                int                         bidiFlag,
                                int                        *more);


int Bidi_isEuropeanNumber(const uint16_t *str, unsigned int len);

/**
 * returns a character's mirrored equivalent
 *
 * @param     u     Unicode character to process
 */
uint16_t Bidi_mirrorChar(const uint16_t u);



/**
 * Prototype for callback function supplied to Bidi_fragmentText.
 *
 * @param     fragment      first character in fragment
 * @param     fragmentLen   number of characters in fragment
 * @param     rightToLeft   true if fragment is right-to-left
 * @param     mirror        The mirror code of the fragment if it exists
 * @param     arg           data from caller of Bidi_fragmentText
 */
typedef void (Bidi_Fragment_Callback)(const uint16_t *fragment,
					size_t fragmentLen,
					int rightToLeft,
					uint16_t mirror,
					void *arg);



/**
 * Partitions the given Unicode sequence into one or more unidirectional
 * fragments and invokes the given callback function for each fragment.
 *
 * For example, if directionality of text is:
 *               0123456789
 *               rrlllrrrrr,
 * we'll invoke callback with:
 *               &text[0], length == 2, rightToLeft ==  true
 *               &text[2], length == 3, rightToLeft == false
 *               &text[5], length == 5, rightToLeft ==  true.
 *
 * @param[in] text      start of Unicode sequence
 * @param[in] textlen   number of Unicodes to analyse
 * @param[in] baseDir   direction of paragraph (specify Bidi_Neutral
 *                      to force auto-detection)
 * @param[in] callback  function to be called for each fragment
 * @param[in] arg       data to be passed to the callback function
 * @param[in] bidiFlag  flag to be passed to the callback function
 */
void Bidi_fragmentText(fz_context *ctx,
			const uint16_t *text,
			size_t textlen,
			Bidi_Direction *baseDir,
			Bidi_Fragment_Callback callback,
			void *arg,
			int bidiFlag);

#endif /* BIDI_BIDI_H */

/** @} */
