/**
  * Bidirectional text processing.
  *
  * Processes uint16_t text by arranging the characters into an order suitable
  * for display. E.g. Hebrew text will be arranged from right-to-left and
  * any English within the text will remain in the left-to-right order.
  * Characters such as parenthesis will be substituted for their mirrored
  * equivalents if they are part of text which must be reversed.
  *
  * This is an implementation of the uint16_t Bidirectional Algorithm which
  * can be found here: http://www.uint16_t.org/reports/tr9/ and is based
  * on the reference implementation of the algorithm found on that page.
  *
  * FIXME - Describe the role of this module from the point of view of EDR.
  *
  * For a nice overview of how it works, read this...
  * http://www.w3.org/TR/REC-html40/struct/dirlang.html
  *
  * Copyright (C) Picsel, 2004. All Rights Reserved.
  */

/**
  * Original copyright notice from uint16_t reference implementation.
  * ----------------------------------------------------------------
  * Written by: Asmus Freytag
  *	 C++ and Windows dependencies removed, and
  *	 command line interface added by: Rick McGowan
  *
  *	 Copyright (C) 1999, ASMUS, Inc.	 All Rights Reserved
  */

/*
 * Includes...
 */

#include "mupdf/fitz.h"
#include "bidi-impl.h" /* standard bidi code interface */

/*
 * Macros...
 */

#define ODD(x) ((x) & 1)

#define REPLACEABLE_TYPE(t)\
						(((t)==BDI_ES) || ((t)==BDI_ET )|| ((t)==BDI_CS )||\
						 ((t)==BDI_NSM)|| ((t)==BDI_PDF)|| ((t)==BDI_BN )||\
						 ((t)==BDI_S)  || ((t)==BDI_WS )|| ((t)==BDI_N  ) )

#ifdef DEBUG_BIDI_VERBOSE
#define DBUGVF(params) do { fz_warn params; } while (0)
#else
#define DBUGVF(params) do {} while (0)
#endif

#ifdef DEBUG_BIDI_OUTLINE
#define DBUGH(params) do { fz_warn params; } while (0)
#else
#define DBUGH(params) do {} while (0)
#endif

#define UNICODE_EOS                                  ((uint16_t)0)
#define UNICODE_DIGIT_ZERO                           ((uint16_t)0x0030)
#define UNICODE_DIGIT_NINE                           ((uint16_t)0x0039)
#define UNICODE_SUPERSCRIPT_TWO                      ((uint16_t)0x00B2)
#define UNICODE_SUPERSCRIPT_THREE                    ((uint16_t)0x00B3)
#define UNICODE_SUPERSCRIPT_ONE                      ((uint16_t)0x00B9)
#define UNICODE_RTL_START                            ((uint16_t)0x0590)
#define UNICODE_RTL_END                              ((uint16_t)0x07BF)
#define UNICODE_ARABIC_INDIC_DIGIT_ZERO              ((uint16_t)0x0660)
#define UNICODE_ARABIC_INDIC_DIGIT_NINE              ((uint16_t)0x0669)
#define UNICODE_EXTENDED_ARABIC_INDIC_DIGIT_ZERO     ((uint16_t)0x06F0)
#define UNICODE_EXTENDED_ARABIC_INDIC_DIGIT_NINE     ((uint16_t)0x06F9)
#define UNICODE_ZERO_WIDTH_NON_JOINER                ((uint16_t)0x200C)
#define UNICODE_SUPERSCRIPT_ZERO                     ((uint16_t)0x2070)
#define UNICODE_SUPERSCRIPT_FOUR                     ((uint16_t)0x2074)
#define UNICODE_SUPERSCRIPT_NINE                     ((uint16_t)0x2079)
#define UNICODE_SUBSCRIPT_ZERO                       ((uint16_t)0x2080)
#define UNICODE_SUBSCRIPT_NINE                       ((uint16_t)0x2089)
#define UNICODE_CIRCLED_DIGIT_ONE                    ((uint16_t)0x2460)
#define UNICODE_NUMBER_TWENTY_FULL_STOP              ((uint16_t)0x249B)
#define UNICODE_CIRCLED_DIGIT_ZERO                   ((uint16_t)0x24EA)
#define UNICODE_FULLWIDTH_DIGIT_ZERO                 ((uint16_t)0xFF10)
#define UNICODE_FULLWIDTH_DIGIT_NINE                 ((uint16_t)0xFF19)

#ifndef TRUE
#define TRUE (1)
#endif
#ifndef FALSE
#define FALSE (0)
#endif

/*
 * Enumerations...
 */


#ifdef DEBUG
/* display support: */
static const char charFromTypes[] =
{
	' ',	/* ON, */
	'>',	/* L,  */
	'<',	/* R,  */
	'9',	/* AN, */
	'1',	/* EN, */
	'a',	/* AL  */
	'@',	/* NSM */
	'.',	/* CS  */
	',',	/* ES  */
	'$',	/* ET  */
	':',	/* BN  */
	'X',	/* S   */
	'_',	/* WS  */
	'B',	/* B   */
	'+',	/* RLO */
	'+',	/* RLE */
	'+',	/* LRO */
	'+',	/* LRE */
	'-',	/* PDF */
	'='	 /* LS  */
};
#endif /* DEBUG */



typedef struct Bidi_ProcessLine_fragData
{
	uint16_t *entireText;
	Bidi_PL_Fragment_Callback *callersCallback;
	void *callersData;
}
Bidi_ProcessLine_fragData;


typedef struct BidiPropList
{
	uint16_t first;
	uint16_t last;
	Bidi_CharType type;
} BidiPropList;


/* The following two arrays were generated
 * using the perl script unidata2array.pl
 */

static const BidiPropList bidiPropList[] =
{
	{0x0000,0x0008,BDI_BN}, {0x0009,0x0009,BDI_S},  {0x000A,0x000A,BDI_B},
	{0x000B,0x000B,BDI_S},  {0x000C,0x000C,BDI_WS}, {0x000D,0x000D,BDI_B},
	{0x000E,0x001B,BDI_BN}, {0x001C,0x001E,BDI_B},  {0x001F,0x001F,BDI_S},
	{0x0020,0x0020,BDI_WS}, {0x0021,0x0022,BDI_ON}, {0x0023,0x0025,BDI_ET},
	{0x0026,0x002A,BDI_ON}, {0x002B,0x002B,BDI_ES}, {0x002C,0x002C,BDI_CS},
	{0x002D,0x002D,BDI_ES}, {0x002E,0x002E,BDI_CS}, {0x002F,0x002F,BDI_ES},
	{0x0030,0x0039,BDI_EN}, {0x003A,0x003A,BDI_CS}, {0x003B,0x0040,BDI_ON},
	{0x0041,0x005A,BDI_L},  {0x005B,0x0060,BDI_ON}, {0x0061,0x007A,BDI_L},
	{0x007B,0x007E,BDI_ON}, {0x007F,0x0084,BDI_BN}, {0x0085,0x0085,BDI_B},
	{0x0086,0x009F,BDI_BN}, {0x00A0,0x00A0,BDI_CS}, {0x00A1,0x00A1,BDI_ON},
	{0x00A2,0x00A5,BDI_ET}, {0x00A6,0x00A9,BDI_ON}, {0x00AA,0x00AA,BDI_L},
	{0x00AB,0x00AC,BDI_ON}, {0x00AD,0x00AD,BDI_BN}, {0x00AE,0x00AF,BDI_ON},
	{0x00B0,0x00B1,BDI_ET}, {0x00B2,0x00B3,BDI_EN}, {0x00B4,0x00B4,BDI_ON},
	{0x00B5,0x00B5,BDI_L},  {0x00B6,0x00B8,BDI_ON}, {0x00B9,0x00B9,BDI_EN},
	{0x00BA,0x00BA,BDI_L},  {0x00BB,0x00BF,BDI_ON}, {0x00C0,0x00D6,BDI_L},
	{0x00D7,0x00D7,BDI_ON}, {0x00D8,0x00F6,BDI_L},  {0x00F7,0x00F7,BDI_ON},
	{0x00F8,0x02B8,BDI_L},  {0x02B9,0x02BA,BDI_ON}, {0x02BB,0x02C1,BDI_L},
	{0x02C2,0x02CF,BDI_ON}, {0x02D0,0x02D1,BDI_L},  {0x02D2,0x02DF,BDI_ON},
	{0x02E0,0x02E4,BDI_L},  {0x02E5,0x02ED,BDI_ON}, {0x02EE,0x02EE,BDI_L},
	{0x02EF,0x02FF,BDI_ON}, {0x0300,0x036F,BDI_NSM},{0x0374,0x0375,BDI_ON},
	{0x0376,0x037D,BDI_L},  {0x037E,0x037E,BDI_ON}, {0x0384,0x0385,BDI_ON},
	{0x0386,0x0386,BDI_L},  {0x0387,0x0387,BDI_ON}, {0x0388,0x03F5,BDI_L},
	{0x03F6,0x03F6,BDI_ON}, {0x03F7,0x0482,BDI_L},  {0x0483,0x0486,BDI_NSM},
	{0x0488,0x0489,BDI_NSM},{0x048A,0x0589,BDI_L},  {0x058A,0x058A,BDI_ON},
	{0x0591,0x05BD,BDI_NSM},{0x05BE,0x05BE,BDI_R},  {0x05BF,0x05BF,BDI_NSM},
	{0x05C0,0x05C0,BDI_R},  {0x05C1,0x05C2,BDI_NSM},{0x05C3,0x05C3,BDI_R},
	{0x05C4,0x05C5,BDI_NSM},{0x05C6,0x05C6,BDI_R},  {0x05C7,0x05C7,BDI_NSM},
	{0x05D0,0x05EA,BDI_R},  {0x05F0,0x05F4,BDI_R},  {0x0600,0x060B,BDI_AL},
	{0x060C,0x060C,BDI_CS}, {0x060D,0x060D,BDI_AL}, {0x060E,0x060F,BDI_ON},
	{0x0610,0x0615,BDI_NSM},{0x0616,0x064A,BDI_AL}, {0x064B,0x065E,BDI_NSM},
	{0x065F,0x065F,BDI_AL}, {0x0660,0x0669,BDI_EN}, {0x066A,0x066A,BDI_ET},
	{0x066B,0x066C,BDI_EN}, {0x066D,0x066F,BDI_AL}, {0x0670,0x0670,BDI_NSM},
	{0x0671,0x06D5,BDI_AL}, {0x06D6,0x06DC,BDI_NSM},{0x06DD,0x06DD,BDI_AL},
	{0x06DE,0x06E4,BDI_NSM},{0x06E5,0x06E6,BDI_AL}, {0x06E7,0x06E8,BDI_NSM},
	{0x06E9,0x06E9,BDI_ON}, {0x06EA,0x06ED,BDI_NSM},{0x06EE,0x06EF,BDI_AL},
	{0x06F0,0x06F9,BDI_EN}, {0x06FA,0x070E,BDI_AL}, {0x070F,0x070F,BDI_BN},
	{0x0710,0x0710,BDI_AL}, {0x0711,0x0711,BDI_NSM},{0x0712,0x072F,BDI_AL},
	{0x0730,0x074A,BDI_NSM},{0x074B,0x07A5,BDI_AL}, {0x07A6,0x07B0,BDI_NSM},
	{0x07B1,0x07BF,BDI_AL}, {0x07C0,0x07EA,BDI_R},  {0x07EB,0x07F3,BDI_NSM},
	{0x07F4,0x07F5,BDI_R},  {0x07F6,0x07F9,BDI_ON}, {0x07FA,0x08FF,BDI_R},
	{0x0901,0x0902,BDI_NSM},{0x0903,0x093B,BDI_L},  {0x093C,0x093C,BDI_NSM},
	{0x093D,0x0940,BDI_L},  {0x0941,0x0948,BDI_NSM},{0x0949,0x094C,BDI_L},
	{0x094D,0x094D,BDI_NSM},{0x094E,0x0950,BDI_L},  {0x0951,0x0954,BDI_NSM},
	{0x0955,0x0961,BDI_L},  {0x0962,0x0963,BDI_NSM},{0x0964,0x0980,BDI_L},
	{0x0981,0x0981,BDI_NSM},{0x0982,0x09BB,BDI_L},  {0x09BC,0x09BC,BDI_NSM},
	{0x09BD,0x09C0,BDI_L},  {0x09C1,0x09C4,BDI_NSM},{0x09C5,0x09CC,BDI_L},
	{0x09CD,0x09CD,BDI_NSM},{0x09CE,0x09E1,BDI_L},  {0x09E2,0x09E3,BDI_NSM},
	{0x09E4,0x09F1,BDI_L},  {0x09F2,0x09F3,BDI_ET}, {0x09F4,0x0A00,BDI_L},
	{0x0A01,0x0A02,BDI_NSM},{0x0A03,0x0A3B,BDI_L},  {0x0A3C,0x0A3C,BDI_NSM},
	{0x0A3D,0x0A40,BDI_L},  {0x0A41,0x0A42,BDI_NSM},{0x0A47,0x0A48,BDI_NSM},
	{0x0A4B,0x0A4D,BDI_NSM},{0x0A4E,0x0A6F,BDI_L},  {0x0A70,0x0A71,BDI_NSM},
	{0x0A72,0x0A80,BDI_L},  {0x0A81,0x0A82,BDI_NSM},{0x0A83,0x0ABB,BDI_L},
	{0x0ABC,0x0ABC,BDI_NSM},{0x0ABD,0x0AC0,BDI_L},  {0x0AC1,0x0AC5,BDI_NSM},
	{0x0AC7,0x0AC8,BDI_NSM},{0x0AC9,0x0ACC,BDI_L},  {0x0ACD,0x0ACD,BDI_NSM},
	{0x0ACE,0x0AE1,BDI_L},  {0x0AE2,0x0AE3,BDI_NSM},{0x0AE4,0x0AF0,BDI_L},
	{0x0AF1,0x0AF1,BDI_ET}, {0x0B01,0x0B01,BDI_NSM},{0x0B02,0x0B3B,BDI_L},
	{0x0B3C,0x0B3C,BDI_NSM},{0x0B3D,0x0B3E,BDI_L},  {0x0B3F,0x0B3F,BDI_NSM},
	{0x0B40,0x0B40,BDI_L},  {0x0B41,0x0B43,BDI_NSM},{0x0B44,0x0B4C,BDI_L},
	{0x0B4D,0x0B4D,BDI_NSM},{0x0B56,0x0B56,BDI_NSM},{0x0B57,0x0B81,BDI_L},
	{0x0B82,0x0B82,BDI_NSM},{0x0B83,0x0BBF,BDI_L},  {0x0BC0,0x0BC0,BDI_NSM},
	{0x0BC1,0x0BCC,BDI_L},  {0x0BCD,0x0BCD,BDI_NSM},{0x0BCE,0x0BF2,BDI_L},
	{0x0BF3,0x0BF8,BDI_ON}, {0x0BF9,0x0BF9,BDI_ET}, {0x0BFA,0x0BFA,BDI_ON},
	{0x0BFB,0x0C3D,BDI_L},  {0x0C3E,0x0C40,BDI_NSM},{0x0C41,0x0C45,BDI_L},
	{0x0C46,0x0C48,BDI_NSM},{0x0C4A,0x0C4D,BDI_NSM},{0x0C55,0x0C56,BDI_NSM},
	{0x0C57,0x0CBB,BDI_L},  {0x0CBC,0x0CBC,BDI_NSM},{0x0CBD,0x0CCB,BDI_L},
	{0x0CCC,0x0CCD,BDI_NSM},{0x0CCE,0x0CE1,BDI_L},  {0x0CE2,0x0CE3,BDI_NSM},
	{0x0CE4,0x0CF0,BDI_L},  {0x0CF1,0x0CF2,BDI_ON}, {0x0CF3,0x0D40,BDI_L},
	{0x0D41,0x0D43,BDI_NSM},{0x0D44,0x0D4C,BDI_L},  {0x0D4D,0x0D4D,BDI_NSM},
	{0x0D4E,0x0DC9,BDI_L},  {0x0DCA,0x0DCA,BDI_NSM},{0x0DCB,0x0DD1,BDI_L},
	{0x0DD2,0x0DD4,BDI_NSM},{0x0DD6,0x0DD6,BDI_NSM},{0x0DD7,0x0E30,BDI_L},
	{0x0E31,0x0E31,BDI_NSM},{0x0E32,0x0E33,BDI_L},  {0x0E34,0x0E3A,BDI_NSM},
	{0x0E3F,0x0E3F,BDI_ET}, {0x0E40,0x0E46,BDI_L},  {0x0E47,0x0E4E,BDI_NSM},
	{0x0E4F,0x0EB0,BDI_L},  {0x0EB1,0x0EB1,BDI_NSM},{0x0EB2,0x0EB3,BDI_L},
	{0x0EB4,0x0EB9,BDI_NSM},{0x0EBB,0x0EBC,BDI_NSM},{0x0EBD,0x0EC7,BDI_L},
	{0x0EC8,0x0ECD,BDI_NSM},{0x0ECE,0x0F17,BDI_L},  {0x0F18,0x0F19,BDI_NSM},
	{0x0F1A,0x0F34,BDI_L},  {0x0F35,0x0F35,BDI_NSM},{0x0F36,0x0F36,BDI_L},
	{0x0F37,0x0F37,BDI_NSM},{0x0F38,0x0F38,BDI_L},  {0x0F39,0x0F39,BDI_NSM},
	{0x0F3A,0x0F3D,BDI_ON}, {0x0F3E,0x0F70,BDI_L},  {0x0F71,0x0F7E,BDI_NSM},
	{0x0F7F,0x0F7F,BDI_L},  {0x0F80,0x0F84,BDI_NSM},{0x0F85,0x0F85,BDI_L},
	{0x0F86,0x0F87,BDI_NSM},{0x0F88,0x0F8F,BDI_L},  {0x0F90,0x0F97,BDI_NSM},
	{0x0F99,0x0FBC,BDI_NSM},{0x0FBD,0x0FC5,BDI_L},  {0x0FC6,0x0FC6,BDI_NSM},
	{0x0FC7,0x102C,BDI_L},  {0x102D,0x1030,BDI_NSM},{0x1031,0x1031,BDI_L},
	{0x1032,0x1032,BDI_NSM},{0x1036,0x1037,BDI_NSM},{0x1038,0x1038,BDI_L},
	{0x1039,0x1039,BDI_NSM},{0x103A,0x1057,BDI_L},  {0x1058,0x1059,BDI_NSM},
	{0x105A,0x135E,BDI_L},  {0x135F,0x135F,BDI_NSM},{0x1360,0x138F,BDI_L},
	{0x1390,0x1399,BDI_ON}, {0x139A,0x167F,BDI_L},  {0x1680,0x1680,BDI_WS},
	{0x1681,0x169A,BDI_L},  {0x169B,0x169C,BDI_ON}, {0x169D,0x1711,BDI_L},
	{0x1712,0x1714,BDI_NSM},{0x1715,0x1731,BDI_L},  {0x1732,0x1734,BDI_NSM},
	{0x1735,0x1751,BDI_L},  {0x1752,0x1753,BDI_NSM},{0x1754,0x1771,BDI_L},
	{0x1772,0x1773,BDI_NSM},{0x1774,0x17B6,BDI_L},  {0x17B7,0x17BD,BDI_NSM},
	{0x17BE,0x17C5,BDI_L},  {0x17C6,0x17C6,BDI_NSM},{0x17C7,0x17C8,BDI_L},
	{0x17C9,0x17D3,BDI_NSM},{0x17D4,0x17DA,BDI_L},  {0x17DB,0x17DB,BDI_ET},
	{0x17DC,0x17DC,BDI_L},  {0x17DD,0x17DD,BDI_NSM},{0x17DE,0x17EF,BDI_L},
	{0x17F0,0x17F9,BDI_ON}, {0x1800,0x180A,BDI_ON}, {0x180B,0x180D,BDI_NSM},
	{0x180E,0x180E,BDI_WS}, {0x180F,0x18A8,BDI_L},  {0x18A9,0x18A9,BDI_NSM},
	{0x18AA,0x191F,BDI_L},  {0x1920,0x1922,BDI_NSM},{0x1923,0x1926,BDI_L},
	{0x1927,0x192B,BDI_NSM},{0x192C,0x1931,BDI_L},  {0x1932,0x1932,BDI_NSM},
	{0x1933,0x1938,BDI_L},  {0x1939,0x193B,BDI_NSM},{0x1940,0x1940,BDI_ON},
	{0x1944,0x1945,BDI_ON}, {0x1946,0x19DD,BDI_L},  {0x19DE,0x19FF,BDI_ON},
	{0x1A00,0x1A16,BDI_L},  {0x1A17,0x1A18,BDI_NSM},{0x1A19,0x1AFF,BDI_L},
	{0x1B00,0x1B03,BDI_NSM},{0x1B04,0x1B33,BDI_L},  {0x1B34,0x1B34,BDI_NSM},
	{0x1B35,0x1B35,BDI_L},  {0x1B36,0x1B3A,BDI_NSM},{0x1B3B,0x1B3B,BDI_L},
	{0x1B3C,0x1B3C,BDI_NSM},{0x1B3D,0x1B41,BDI_L},  {0x1B42,0x1B42,BDI_NSM},
	{0x1B43,0x1B6A,BDI_L},  {0x1B6B,0x1B73,BDI_NSM},{0x1B74,0x1DBF,BDI_L},
	{0x1DC0,0x1DCA,BDI_NSM},{0x1DFE,0x1DFF,BDI_NSM},{0x1E00,0x1FBC,BDI_L},
	{0x1FBD,0x1FBD,BDI_ON}, {0x1FBE,0x1FBE,BDI_L},  {0x1FBF,0x1FC1,BDI_ON},
	{0x1FC2,0x1FCC,BDI_L},  {0x1FCD,0x1FCF,BDI_ON}, {0x1FD0,0x1FDC,BDI_L},
	{0x1FDD,0x1FDF,BDI_ON}, {0x1FE0,0x1FEC,BDI_L},  {0x1FED,0x1FEF,BDI_ON},
	{0x1FF0,0x1FFC,BDI_L},  {0x1FFD,0x1FFE,BDI_ON}, {0x2000,0x200A,BDI_WS},
	{0x200B,0x200D,BDI_BN}, {0x200E,0x200E,BDI_L},  {0x200F,0x200F,BDI_R},
	{0x2010,0x2027,BDI_ON}, {0x2028,0x2028,BDI_WS}, {0x2029,0x2029,BDI_B},
	{0x202A,0x202A,BDI_LRE},{0x202B,0x202B,BDI_RLE},{0x202C,0x202C,BDI_PDF},
	{0x202D,0x202D,BDI_LRO},{0x202E,0x202E,BDI_RLO},{0x202F,0x202F,BDI_CS},
	{0x2030,0x2034,BDI_ET}, {0x2035,0x2043,BDI_ON}, {0x2044,0x2044,BDI_CS},
	{0x2045,0x205E,BDI_ON}, {0x205F,0x205F,BDI_WS}, {0x2060,0x2063,BDI_BN},
	{0x206A,0x206F,BDI_BN}, {0x2070,0x2070,BDI_EN}, {0x2071,0x2073,BDI_L},
	{0x2074,0x2079,BDI_EN}, {0x207A,0x207B,BDI_ES}, {0x207C,0x207E,BDI_ON},
	{0x207F,0x207F,BDI_L},  {0x2080,0x2089,BDI_EN}, {0x208A,0x208B,BDI_ES},
	{0x208C,0x208E,BDI_ON}, {0x208F,0x209F,BDI_L},  {0x20A0,0x20B5,BDI_ET},
	{0x20D0,0x20EF,BDI_NSM},{0x2100,0x2101,BDI_ON}, {0x2102,0x2102,BDI_L},
	{0x2103,0x2106,BDI_ON}, {0x2107,0x2107,BDI_L},  {0x2108,0x2109,BDI_ON},
	{0x210A,0x2113,BDI_L},  {0x2114,0x2114,BDI_ON}, {0x2115,0x2115,BDI_L},
	{0x2116,0x2118,BDI_ON}, {0x2119,0x211D,BDI_L},  {0x211E,0x2123,BDI_ON},
	{0x2124,0x2124,BDI_L},  {0x2125,0x2125,BDI_ON}, {0x2126,0x2126,BDI_L},
	{0x2127,0x2127,BDI_ON}, {0x2128,0x2128,BDI_L},  {0x2129,0x2129,BDI_ON},
	{0x212A,0x212D,BDI_L},  {0x212E,0x212E,BDI_ET}, {0x212F,0x2139,BDI_L},
	{0x213A,0x213B,BDI_ON}, {0x213C,0x213F,BDI_L},  {0x2140,0x2144,BDI_ON},
	{0x2145,0x2149,BDI_L},  {0x214A,0x214D,BDI_ON}, {0x214E,0x2152,BDI_L},
	{0x2153,0x215F,BDI_ON}, {0x2160,0x218F,BDI_L},  {0x2190,0x2211,BDI_ON},
	{0x2212,0x2212,BDI_ES}, {0x2213,0x2213,BDI_ET}, {0x2214,0x2335,BDI_ON},
	{0x2336,0x237A,BDI_L},  {0x237B,0x2394,BDI_ON}, {0x2395,0x2395,BDI_L},
	{0x2396,0x23E7,BDI_ON}, {0x2400,0x2426,BDI_ON}, {0x2440,0x244A,BDI_ON},
	{0x2460,0x2487,BDI_ON}, {0x2488,0x249B,BDI_EN}, {0x249C,0x24E9,BDI_L},
	{0x24EA,0x269C,BDI_ON}, {0x26A0,0x26AB,BDI_ON}, {0x26AC,0x26AC,BDI_L},
	{0x26AD,0x26B2,BDI_ON}, {0x2701,0x2704,BDI_ON}, {0x2706,0x2709,BDI_ON},
	{0x270C,0x2727,BDI_ON}, {0x2729,0x274B,BDI_ON}, {0x274D,0x274D,BDI_ON},
	{0x274F,0x2752,BDI_ON}, {0x2756,0x2756,BDI_ON}, {0x2758,0x275E,BDI_ON},
	{0x2761,0x2794,BDI_ON}, {0x2798,0x27AF,BDI_ON}, {0x27B1,0x27BE,BDI_ON},
	{0x27C0,0x27CA,BDI_ON}, {0x27D0,0x27EB,BDI_ON}, {0x27F0,0x27FF,BDI_ON},
	{0x2800,0x28FF,BDI_L},  {0x2900,0x2B1A,BDI_ON}, {0x2B20,0x2B23,BDI_ON},
	{0x2B24,0x2CE4,BDI_L},  {0x2CE5,0x2CEA,BDI_ON}, {0x2CF9,0x2CFF,BDI_ON},
	{0x2D00,0x2DFF,BDI_L},  {0x2E00,0x2E17,BDI_ON}, {0x2E1C,0x2E1D,BDI_ON},
	{0x2E80,0x2E99,BDI_ON}, {0x2E9B,0x2EF3,BDI_ON}, {0x2F00,0x2FD5,BDI_ON},
	{0x2FF0,0x2FFB,BDI_ON}, {0x3000,0x3000,BDI_WS}, {0x3001,0x3004,BDI_ON},
	{0x3005,0x3007,BDI_L},  {0x3008,0x3020,BDI_ON}, {0x3021,0x3029,BDI_L},
	{0x302A,0x302F,BDI_NSM},{0x3030,0x3030,BDI_ON}, {0x3031,0x3035,BDI_L},
	{0x3036,0x3037,BDI_ON}, {0x3038,0x303C,BDI_L},  {0x303D,0x303F,BDI_ON},
	{0x3040,0x3098,BDI_L},  {0x3099,0x309A,BDI_NSM},{0x309B,0x309C,BDI_ON},
	{0x309D,0x309F,BDI_L},  {0x30A0,0x30A0,BDI_ON}, {0x30A1,0x30FA,BDI_L},
	{0x30FB,0x30FB,BDI_ON}, {0x30FC,0x31BF,BDI_L},  {0x31C0,0x31CF,BDI_ON},
	{0x31D0,0x321C,BDI_L},  {0x321D,0x321E,BDI_ON}, {0x321F,0x324F,BDI_L},
	{0x3250,0x325F,BDI_ON}, {0x3260,0x327B,BDI_L},  {0x327C,0x327E,BDI_ON},
	{0x327F,0x32B0,BDI_L},  {0x32B1,0x32BF,BDI_ON}, {0x32C0,0x32CB,BDI_L},
	{0x32CC,0x32CF,BDI_ON}, {0x32D0,0x3376,BDI_L},  {0x3377,0x337A,BDI_ON},
	{0x337B,0x33DD,BDI_L},  {0x33DE,0x33DF,BDI_ON}, {0x33E0,0x33FE,BDI_L},
	{0x33FF,0x33FF,BDI_ON}, {0x3400,0x4DBF,BDI_L},  {0x4DC0,0x4DFF,BDI_ON},
	{0x4E00,0xA48F,BDI_L},  {0xA490,0xA4C6,BDI_ON}, {0xA700,0xA71A,BDI_ON},
	{0xA720,0xA721,BDI_ON}, {0xA722,0xA801,BDI_L},  {0xA802,0xA802,BDI_NSM},
	{0xA803,0xA805,BDI_L},  {0xA806,0xA806,BDI_NSM},{0xA807,0xA80A,BDI_L},
	{0xA80B,0xA80B,BDI_NSM},{0xA80C,0xA824,BDI_L},  {0xA825,0xA826,BDI_NSM},
	{0xA827,0xA827,BDI_L},  {0xA828,0xA82B,BDI_ON}, {0xA82C,0xA873,BDI_L},
	{0xA874,0xA877,BDI_ON}, {0xA878,0xFB1C,BDI_L},  {0xFB1D,0xFB1D,BDI_R},
	{0xFB1E,0xFB1E,BDI_NSM},{0xFB1F,0xFB28,BDI_R},  {0xFB29,0xFB29,BDI_ES},
	{0xFB2A,0xFB4F,BDI_R},  {0xFB50,0xFD3D,BDI_AL}, {0xFD3E,0xFD3F,BDI_ON},
	{0xFD40,0xFDFC,BDI_AL}, {0xFDFD,0xFDFD,BDI_ON}, {0xFDFE,0xFDFF,BDI_AL},
	{0xFE00,0xFE0F,BDI_NSM},{0xFE10,0xFE19,BDI_ON}, {0xFE20,0xFE23,BDI_NSM},
	{0xFE30,0xFE4F,BDI_ON}, {0xFE50,0xFE50,BDI_CS}, {0xFE51,0xFE51,BDI_ON},
	{0xFE52,0xFE52,BDI_CS}, {0xFE54,0xFE54,BDI_ON}, {0xFE55,0xFE55,BDI_CS},
	{0xFE56,0xFE5E,BDI_ON}, {0xFE5F,0xFE5F,BDI_ET}, {0xFE60,0xFE61,BDI_ON},
	{0xFE62,0xFE63,BDI_ES}, {0xFE64,0xFE66,BDI_ON}, {0xFE68,0xFE68,BDI_ON},
	{0xFE69,0xFE6A,BDI_ET}, {0xFE6B,0xFE6B,BDI_ON}, {0xFE70,0xFEFE,BDI_AL},
	{0xFEFF,0xFEFF,BDI_BN}, {0xFF01,0xFF02,BDI_ON}, {0xFF03,0xFF05,BDI_ET},
	{0xFF06,0xFF0A,BDI_ON}, {0xFF0B,0xFF0B,BDI_ES}, {0xFF0C,0xFF0C,BDI_CS},
	{0xFF0D,0xFF0D,BDI_ES}, {0xFF0E,0xFF0F,BDI_CS}, {0xFF10,0xFF19,BDI_EN},
	{0xFF1A,0xFF1A,BDI_CS}, {0xFF1B,0xFF20,BDI_ON}, {0xFF21,0xFF3A,BDI_L},
	{0xFF3B,0xFF40,BDI_ON}, {0xFF41,0xFF5A,BDI_L},  {0xFF5B,0xFF65,BDI_ON},
	{0xFF66,0xFFDF,BDI_L},  {0xFFE0,0xFFE1,BDI_ET}, {0xFFE2,0xFFE4,BDI_ON},
	{0xFFE5,0xFFE6,BDI_ET}, {0xFFE8,0xFFEE,BDI_ON}, {0xFFF9,0xFFFD,BDI_ON}
};

#define NUM_BDIPROP_SPANS ( sizeof( bidiPropList ) / sizeof( BidiPropList ) )

/*
 *The original BidiMirrorList bidiMirrorList[] array has been replaced by
 *uint32_t bidiOptMirrorList[] an array that represents a tree structure
 *formed from the original mirror list by the Perl script
 *create-mirrorlist.pl in Review #11191
 *
 *below is the first part of the tree:- representing the uint16_t values
 *0x0028, 0x0029, 0x003C, 0x003E, 0x005B, 0x005D
 *
 *               0
 *               |
 *           ----0----
 *          /    |    \
 *	   2	 3     5
 *	  / \   / \   / \
 *	 8   9 C   E B   D
 *
 *Every uint16_t value that shares nybble ancestors share parent nodes
 *on the tree.
 *The tree is of fixed depth 4 and each node holds the following values
 *{4-bits nybble, 12-bits next, 16-bits uint16_t mirror}.
 *The tree is represented as an array of bit-masks.
 *
 *The nybble value is the value in the tree above.
 *The next Offset is the index into the array which points to the next
 *sibling for the current node (i.e. the next node horizintally to the right
 *that shares the same parent).
 *The mirror value is the code to be mapped.
 */
static const uint32_t bidiOptMirrorList[] =
{
	0x00120000, 0x0FFF0000, 0x20050000,
	0x80040029, 0x9FFF0028, 0x30080000,
	0xC007003E, 0xEFFF003C, 0x500B0000,
	0xB00A005D, 0xDFFF005B, 0x700E0000,
	0xB00D007D, 0xDFFF007B, 0xA0100000,
	0xBFFF00BB, 0xBFFF0000, 0xBFFF00AB,
	0x215A0000, 0x00200000, 0x30170000,
	0x9016203A, 0xAFFF2039, 0x401A0000,
	0x50192046, 0x6FFF2045, 0x701D0000,
	0xD01C207E, 0xEFFF207D, 0x8FFF0000,
	0xD01F208E, 0xEFFF208D, 0x20A20000,
	0x00280000, 0x8023220B, 0x9024220C,
	0xA025220D, 0xB0262208, 0xC0272209,
	0xDFFF220A, 0x102A0000, 0x5FFF29F5,
	0x302D0000, 0xC02C223D, 0xDFFF223C,
	0x402F0000, 0x3FFF22CD, 0x50340000,
	0x20312253, 0x30322252, 0x40332255,
	0x5FFF2254, 0x603F0000, 0x40362265,
	0x50372264, 0x60382267, 0x70392266,
	0x803A2269, 0x903B2268, 0xA03C226B,
	0xB03D226A, 0xE03E226F, 0xFFFF226E,
	0x70500000, 0x00412271, 0x10422270,
	0x20432273, 0x30442272, 0x40452275,
	0x50462274, 0x60472277, 0x70482276,
	0x80492279, 0x904A2278, 0xA04B227B,
	0xB04C227A, 0xC04D227D, 0xD04E227C,
	0xE04F227F, 0xFFFF227E, 0x805E0000,
	0x00522281, 0x10532280, 0x20542283,
	0x30552282, 0x40562285, 0x50572284,
	0x60582287, 0x70592286, 0x805A2289,
	0x905B2288, 0xA05C228B, 0xB05D228A,
	0xFFFF2290, 0x90630000, 0x0060228F,
	0x10612292, 0x20622291, 0x8FFF29B8,
	0xA06A0000, 0x206522A3, 0x306622A2,
	0x60672ADE, 0x80682AE4, 0x90692AE3,
	0xBFFF2AE5, 0xB0730000, 0x006C22B1,
	0x106D22B0, 0x206E22B3, 0x306F22B2,
	0x407022B5, 0x507122B4, 0x607222B7,
	0x7FFF22B6, 0xC0790000, 0x907522CA,
	0xA07622C9, 0xB07722CC, 0xC07822CB,
	0xDFFF2243, 0xD0860000, 0x007B22D1,
	0x107C22D0, 0x607D22D7, 0x707E22D6,
	0x807F22D9, 0x908022D8, 0xA08122DB,
	0xB08222DA, 0xC08322DD, 0xD08422DC,
	0xE08522DF, 0xFFFF22DE, 0xE0950000,
	0x008822E1, 0x108922E0, 0x208A22E3,
	0x308B22E2, 0x408C22E5, 0x508D22E4,
	0x608E22E7, 0x708F22E6, 0x809022E9,
	0x909122E8, 0xA09222EB, 0xB09322EA,
	0xC09422ED, 0xDFFF22EC, 0xFFFF0000,
	0x009722F1, 0x109822F0, 0x209922FA,
	0x309A22FB, 0x409B22FC, 0x609C22FD,
	0x709D22FE, 0xA09E22F2, 0xB09F22F3,
	0xC0A022F4, 0xD0A122F6, 0xEFFF22F7,
	0x30AB0000, 0x00A80000, 0x80A52309,
	0x90A62308, 0xA0A7230B, 0xBFFF230A,
	0x2FFF0000, 0x90AA232A, 0xAFFF2329,
	0x70CC0000, 0x60B50000, 0x80AE2769,
	0x90AF2768, 0xA0B0276B, 0xB0B1276A,
	0xC0B2276D, 0xD0B3276C, 0xE0B4276F,
	0xFFFF276E, 0x70BC0000, 0x00B72771,
	0x10B82770, 0x20B92773, 0x30BA2772,
	0x40BB2775, 0x5FFF2774, 0xD0C10000,
	0x50BE27D6, 0x60BF27D5, 0xD0C027DE,
	0xEFFF27DD, 0xEFFF0000, 0x20C327E3,
	0x30C427E2, 0x40C527E5, 0x50C627E4,
	0x60C727E7, 0x70C827E6, 0x80C927E9,
	0x90CA27E8, 0xA0CB27EB, 0xBFFF27EA,
	0x90FD0000, 0x80DB0000, 0x30CF2984,
	0x40D02983, 0x50D12986, 0x60D22985,
	0x70D32988, 0x80D42987, 0x90D5298A,
	0xA0D62989, 0xB0D7298C, 0xC0D8298B,
	0xD0D92990, 0xE0DA298F, 0xFFFF298E,
	0x90E50000, 0x00DD298D, 0x10DE2992,
	0x20DF2991, 0x30E02994, 0x40E12993,
	0x50E22996, 0x60E32995, 0x70E42998,
	0x8FFF2997, 0xB0E70000, 0x8FFF2298,
	0xC0ED0000, 0x00E929C1, 0x10EA29C0,
	0x40EB29C5, 0x50EC29C4, 0xFFFF29D0,
	0xD0F70000, 0x00EF29CF, 0x10F029D2,
	0x20F129D1, 0x40F229D5, 0x50F329D4,
	0x80F429D9, 0x90F529D8, 0xA0F629DB,
	0xBFFF29DA, 0xFFFF0000, 0x50F92215,
	0x80FA29F9, 0x90FB29F8, 0xC0FC29FD,
	0xDFFF29FC, 0xAFFF0000, 0x21030000,
	0xB1002A2C, 0xC1012A2B, 0xD1022A2E,
	0xEFFF2A2D, 0x31080000, 0x41052A35,
	0x51062A34, 0xC1072A3D, 0xDFFF2A3C,
	0x610B0000, 0x410A2A65, 0x5FFF2A64,
	0x71110000, 0x910D2A7A, 0xA10E2A79,
	0xD10F2A7E, 0xE1102A7D, 0xFFFF2A80,
	0x81190000, 0x01132A7F, 0x11142A82,
	0x21152A81, 0x31162A84, 0x41172A83,
	0xB1182A8C, 0xCFFF2A8B, 0x91260000,
	0x111B2A92, 0x211C2A91, 0x311D2A94,
	0x411E2A93, 0x511F2A96, 0x61202A95,
	0x71212A98, 0x81222A97, 0x91232A9A,
	0xA1242A99, 0xB1252A9C, 0xCFFF2A9B,
	0xA1320000, 0x11282AA2, 0x21292AA1,
	0x612A2AA7, 0x712B2AA6, 0x812C2AA9,
	0x912D2AA8, 0xA12E2AAB, 0xB12F2AAA,
	0xC1302AAD, 0xD1312AAC, 0xFFFF2AB0,
	0xB13B0000, 0x01342AAF, 0x31352AB4,
	0x41362AB3, 0xB1372ABC, 0xC1382ABB,
	0xD1392ABE, 0xE13A2ABD, 0xFFFF2AC0,
	0xC1460000, 0x013D2ABF, 0x113E2AC2,
	0x213F2AC1, 0x31402AC4, 0x41412AC3,
	0x51422AC6, 0x61432AC5, 0xD1442ACE,
	0xE1452ACD, 0xFFFF2AD0, 0xD14F0000,
	0x01482ACF, 0x11492AD2, 0x214A2AD1,
	0x314B2AD4, 0x414C2AD3, 0x514D2AD6,
	0x614E2AD5, 0xEFFF22A6, 0xE1550000,
	0x315122A9, 0x415222A8, 0x515322AB,
	0xC1542AED, 0xDFFF2AEC, 0xFFFF0000,
	0x71572AF8, 0x81582AF7, 0x91592AFA,
	0xAFFF2AF9, 0x31700000, 0x0FFF0000,
	0x01650000, 0x815E3009, 0x915F3008,
	0xA160300B, 0xB161300A, 0xC162300D,
	0xD163300C, 0xE164300F, 0xFFFF300E,
	0x1FFF0000, 0x01673011, 0x11683010,
	0x41693015, 0x516A3014, 0x616B3017,
	0x716C3016, 0x816D3019, 0x916E3018,
	0xA16F301B, 0xBFFF301A, 0xFFFF0000,
	0xFFFF0000, 0x01750000, 0x8174FF09,
	0x9FFFFF08, 0x11780000, 0xC177FF1E,
	0xEFFFFF1C, 0x317B0000, 0xB17AFF3D,
	0xDFFFFF3B, 0x517F0000, 0xB17DFF5D,
	0xD17EFF5B, 0xFFFFFF60, 0x6FFF0000,
	0x0181FF5F, 0x2182FF63, 0x3FFFFF62
};

#define NUM_BIDI_OPTMIRRORS (sizeof(bidiOptMirrorList)/sizeof(uint32_t))

#define MIRROR_NYBBLE_SHIFT	 28
#define MIRROR_NEXT_MASK		0x0FFF0000
#define MIRROR_NEXT_SHIFT	   16
#define MIRROR_VALUE_MASK	   0x0000FFFF
#define TRIPPLE_NYBBLE_NEG	  4095

/*
 * Functions and static functions...
 */


/** Returns a directional type for different characters. The type is found in
  * the lookup table bidiPropList using a binary search. Each element in the
  * table is a range of code-points which share the same type, all arranged
  * in ascending order.
  */
static Bidi_CharType classFromChWS(uint16_t ch)
{
	int start = 0;
	int end = NUM_BDIPROP_SPANS - 1;
	int mid = end / 2;

	while (start <= end)
	{
		if (ch < bidiPropList[mid].first)
			end = mid - 1;
		else if (ch > bidiPropList[mid].last)
			start = mid + 1;
		else
		{
			if (bidiPropList[mid].type == BDI_B)
				return BDI_ON;
			return bidiPropList[mid].type;
		}

		mid = (start + end) / 2;
	}

	return BDI_L; /* in the absence of anything better to do. */
}

/** Return a direction for white-space on the second pass of the algorithm.
  */
Bidi_CharType Bidi_classFromChN(uint16_t ch)
{
	int fromChWS = classFromChWS(ch);

	if (fromChWS == BDI_S || fromChWS == BDI_WS)
		return BDI_N;

	return fromChWS;
}


int Bidi_isEuropeanNumber(const uint16_t *str, unsigned int len)
{
	const uint16_t *end = str + len;

	for ( ; str != end; str++)
	{
		const uint16_t  u = *str;
		if ((u >= UNICODE_RTL_START && u < UNICODE_ARABIC_INDIC_DIGIT_ZERO) ||
		(u > UNICODE_ARABIC_INDIC_DIGIT_NINE && u < UNICODE_EXTENDED_ARABIC_INDIC_DIGIT_ZERO) ||
		(u > UNICODE_EXTENDED_ARABIC_INDIC_DIGIT_NINE && u <= UNICODE_RTL_END))
		{
			/* This is just a normal RTL character or accent */
			return FALSE;
		}
		else if(!(
			(u >= UNICODE_DIGIT_ZERO && u <= UNICODE_DIGIT_NINE) ||
			(u == UNICODE_SUPERSCRIPT_TWO) ||
			(u == UNICODE_SUPERSCRIPT_THREE) ||
			(u == UNICODE_SUPERSCRIPT_ONE) ||
			(u >= UNICODE_ARABIC_INDIC_DIGIT_ZERO && u <= UNICODE_ARABIC_INDIC_DIGIT_NINE) ||
			(u >= UNICODE_EXTENDED_ARABIC_INDIC_DIGIT_ZERO && u <= UNICODE_EXTENDED_ARABIC_INDIC_DIGIT_NINE) ||
			(u == UNICODE_SUPERSCRIPT_ZERO) ||
			(u >= UNICODE_SUPERSCRIPT_FOUR && u <= UNICODE_SUPERSCRIPT_NINE) ||
			(u >= UNICODE_SUBSCRIPT_ZERO && u <= UNICODE_SUBSCRIPT_NINE) ||
			(u >= UNICODE_CIRCLED_DIGIT_ONE && u <= UNICODE_NUMBER_TWENTY_FULL_STOP) ||
			(u == UNICODE_CIRCLED_DIGIT_ZERO) ||
			(u >= UNICODE_FULLWIDTH_DIGIT_ZERO && u <= UNICODE_FULLWIDTH_DIGIT_NINE) ||
			(u == UNICODE_ZERO_WIDTH_NON_JOINER)
			 )
			)
		{
			return FALSE;
		}
	}
	return TRUE;
}

/** The Bidi_mirrorChar function tranverses the tree looking for nybble
  * matches.
  *
  * EXAMPLE:
  * If uint16_t value u=0x005D has been passed to Bidi_mirrorChar for testing,
  * it is separated into nybbles 0,0,5,D
  * The first node in the tree (index 0 in the array) is the starting point,
  * and luckily the first 4-bits hold a 0, which matches. We can therefore
  * drop down to the child to check that. The child of a node is stored in
  * the next array position, in this case index 1.
  * The nybble of index 1 is a 0 and matches the second nybble we are
  * searching for. Because of the match, the next child index 2 is moved to.
  * Now the nybble at index 2 of the tree is a 2 and doesn't match the 5 we
  * are searching for. Bits 5-16 of the array represent the offset to the
  * next sibling. In this case the offset is 5, when we move to this array
  * value we see that it holds a 3 nybble, again this doesn't match, so we
  * get the next offset, which is 8, and move to that sibling.
  * The sibling holds the nybble 5, which is the next one we want; so
  * increment the index to its child. The child doesn't match and holds a B
  * instead of a D. So we move to the next sibling ... which matches!!
  * This node holds the mirror character 0x005B in bits 17-32.
  */
uint16_t Bidi_mirrorChar(const uint16_t u)
{
	int i, index;
	uint16_t uCpy;
	uint8_t n, nybble;

	if((u < UNICODE_RTL_START) || (u > UNICODE_RTL_END))
	{
		/* uint16_t value lies outside of RTL character range
		 * and could therefore be a mirrorable charcter
		 */
		index = 0;
		uCpy = (uint16_t)u;
		/* look through each nybble of the uint16_t and search in tree
		 * for matches
		 */
		for(i = 0; i < 4; i++)
		{
			n = (uint8_t)(uCpy >> 12); /* the current nybble of the target */
			/* the nybble of the first child node */
			nybble = (uint8_t)(bidiOptMirrorList[index] >> MIRROR_NYBBLE_SHIFT);

			/* search through node siblings for the matching nybble */
			while(nybble != n)
			{
				/* index to next sibling */
				index = (bidiOptMirrorList[index] & MIRROR_NEXT_MASK) >> MIRROR_NEXT_SHIFT;
				if(index == TRIPPLE_NYBBLE_NEG) /* 12-bit next value is -1 */
				{
					/* no more siblings */
					return UNICODE_EOS;
				}
				nybble = (uint8_t)(bidiOptMirrorList[index] >> MIRROR_NYBBLE_SHIFT);
			}
			uCpy <<= 4;
			index++;
		}
		return (uint16_t)(bidiOptMirrorList[--index] & MIRROR_VALUE_MASK);
	}
	return UNICODE_EOS;
}

/** Searches a RTL fragment for a mirror character
 * When it finds one it creates a separate fragment for the
 * character and the surrounding fragments. It passes the mirrored
 * uint16_t back through the callback.
 */
static void Bidi_createFragmentMirrors(const uint16_t *text,
					int len,
					Bidi_Fragment_Callback callback,
					void *arg)
{
	int i;
	int lastPtr;
	uint16_t mirror;

	assert(text != NULL);
	assert(len > 0);
	lastPtr = 0;
	for (i = 0; i < len; i ++)
	{
		mirror = Bidi_mirrorChar(text[i]);
		if(mirror != UNICODE_EOS)
		{
			/* create preceding fragment */
			if(i > lastPtr)
			{
				(*callback)(&text[lastPtr],
							i - lastPtr,
							TRUE,
							UNICODE_EOS,
							arg);
				DBUGVF(("create mirror fragment for %x\n",(int)text[i]));
			}
			/* create mirror fragment */
			(*callback)(&text[i],
						1,
						TRUE,
						mirror,
						arg);
			lastPtr = i + 1;
		}
	}

	if(lastPtr < len)
	{
		/* create end fragment */
		(*callback)(&text[lastPtr],
					len - lastPtr,
					TRUE,
					UNICODE_EOS,
					arg);
	}
}



/** Determines the character classes for all following
  * passes of the algorithm. A character class is basically the type of Bidi
  * behaviour that the character exhibits.
  */
void Bidi_classifyCharacters(const uint16_t *text,
			Bidi_CharType *types,
			int len,
			Bidi_Flags flags)
{
	int i;

	if ((flags & Bidi_classifyWhiteSpace)!=0)
	{
		for (i = 0; i < len; i++)
		{
			types[i] = classFromChWS(text[i]);
		}
	}
	else
	{
#ifdef DEBUG_BIDI_VERBOSE
		fprintf(stderr, "Text:   ");
		for (i = 0; i < len; i++)
		{
			/* So that we can actually sort of read the debug string, any
			 * non-ascii characters are replaced with a 1-digit hash
			 * value from 0-9, making non-english characters appear
			 * as numbers
			 */
			fprintf(stderr, "%c", (text[i] <= 127 && text[i ]>= 32)?
								text[i]
							   :(char)((text[i] % 9) + 48)
				 );
		}
		fprintf(stderr, "\nTypes:  ");
#endif
		for (i = 0; i < len; i++)
		{
			types[i] = Bidi_classFromChN(text[i]);
#ifdef DEBUG_BIDI_VERBOSE
			fprintf(stderr, "%c", charFromTypes[(int)types[i]]);
#endif
		}
#ifdef DEBUG_BIDI_VERBOSE
		fprintf(stderr, "\n");
#endif
	}
}



/** Determines the base level of the text.
  * Implements rule P2 of the uint16_t Bidi Algorithm.
  * Note: Ignores explicit embeddings
  */
static Bidi_Level baseLevelFromText(Bidi_CharType *types, int len)
{
	int i;

	for (i = 0; i < len; i++)
	{
		switch (types[i])
		{
		/* strong left */
		case BDI_L:
			return Bidi_LeftToRight;

		/* strong right */
		case BDI_R:
		case BDI_AL:
			return Bidi_RightToLeft;
		}
	}
	return Bidi_LeftToRight;
}



static Bidi_Direction directionFromType( Bidi_CharType type )
{
	switch( type )
	{
	case BDI_L:
	case BDI_EN:
		return Bidi_LeftToRight;

	case BDI_R:
	case BDI_AL:
		return Bidi_RightToLeft;

	default:
		return Bidi_Neutral;
	}
}



static void classifyQuotedBlocks(const uint16_t *text,
				Bidi_CharType *types,
				size_t len)
{
	size_t i;
	int inQuote = FALSE;
	int pdfNeeded = FALSE;
	int ltrFound = FALSE;
	int rtlFound = FALSE;

	/* Only do anything special here if there is mixed content
	 * (LTR *and* RTL) in the text.
	 */
	for (i = 0; i < len; i++)
	{
		switch ( directionFromType(types[i]) )
		{
		case Bidi_LeftToRight:
			ltrFound = TRUE;
			break;

		case Bidi_RightToLeft:
			rtlFound = TRUE;
			break;

		default:
			break;
		}
	}

	/* Only make any changes if *both* LTR and RTL characters exist
	 * in this text.
	 */
	if ( !ltrFound || !rtlFound )
	{
		return;
	}

	for (i = 0; i < len; i++)
	{
		if (text[i]=='"')
		{
			/* If we're already in a quote then terminate it,
			 * else start a new block.
			 */
			if ( inQuote )
			{
				inQuote = FALSE;
				if ( pdfNeeded )
				{
					pdfNeeded = FALSE;
					types[i] = BDI_PDF;
				}
			}
			else
			{
				size_t j;
				int   done = FALSE;

				inQuote = TRUE;

				/* Find the first strong right or left type and
				 * use that to determine whether we should classify
				 * the quote as LRE or RLE.  Or neither, if we
				 * hit another quote before any strongly-directional
				 * character.
				 */
				for ( j = i + 1;
					  !done && (j < len) && text[j] != '"';
					  ++j )
				{
					switch( types[j] )
					{
					case BDI_RLE:
					case BDI_LRE:
						done = TRUE;
						break;

					case BDI_L:
					case BDI_EN:
						types[i]  = BDI_LRE;
						pdfNeeded = TRUE;
						done	  = TRUE;
						break;

					case BDI_R:
					case BDI_AL:
						types[i]  = BDI_RLE;
						pdfNeeded = TRUE;
						done	  = TRUE;
						break;

					default:
						break;
					}
				}
			}
		}
	}
}



/* Creates a buffer with an embedding level for every uint16_t in the
 * given text.  Also determines the base level and returns it in
 * *baseDir if *baseDir does not initially contain a valid direction.
 */
static Bidi_Level *
createLevels(fz_context *ctx,
		const uint16_t *text,
		size_t len,
		Bidi_Direction *baseDir,
		int resolveWhiteSpace,
		int bidiFlag)
{
	Bidi_Level *levels;
	Bidi_CharType *types = NULL;
	Bidi_Level baseLevel;

	levels = fz_malloc(ctx, len * sizeof(*levels));

	fz_var(types);

	fz_try(ctx)
	{
		types = fz_malloc(ctx, len * sizeof(Bidi_CharType));

		Bidi_classifyCharacters(text, types, len, bidiFlag);

		if (*baseDir != Bidi_LeftToRight && *baseDir != Bidi_RightToLeft)
		{
			/* Derive the base level from the text and
			 * update *baseDir in case the caller wants to know.
			 */
			baseLevel = baseLevelFromText(types, len);
			*baseDir = ODD(baseLevel)==1 ? Bidi_RightToLeft : Bidi_LeftToRight;
		}
		else
		{
			baseLevel = (Bidi_Level)*baseDir;
		}

		{
			/* Replace tab with base direction, i.e. make tab appear as
			 * 'strong left' if the base direction is left-to-right and
			 * 'strong right' if base direction is right-to-left.  This
			 * allows Layout to implicitly treat tabs as 'segment separators'.
			 */
			size_t i;

			for (i = 0u; i < len; i++)
			{
				if (text[i]=='\t')
				{
					types[i] = (*baseDir == Bidi_RightToLeft) ? BDI_R : BDI_L;
				}
			}
		}

		/* Look for quotation marks.  Classify them as RLE or LRE
		 * or leave them alone, depending on what follows them.
		 */
		classifyQuotedBlocks( text, types, len );

		/* Work out the levels and character types... */
		(void)Bidi_resolveExplicit(baseLevel, BDI_N, types, levels, len, 0);
		Bidi_resolveWeak(ctx, baseLevel, types, levels, len);
		Bidi_resolveNeutrals(baseLevel,types, levels, len);
		Bidi_resolveImplicit(types, levels, len);

		Bidi_classifyCharacters(text, types, len, Bidi_classifyWhiteSpace);

		if (resolveWhiteSpace)
		{
			/* resolve whitespace */
			Bidi_resolveWhitespace(baseLevel, types, levels, len);
		}

		/* The levels buffer now has odd and even numbers indicating
		 * rtl or ltr characters, respectively.
		 */
#ifdef DEBUG_BIDI_VERBOSE
		fprintf(stderr, "Levels: ");
		{
			size_t i;
			for (i = 0; i < len; i++)
			{
				fprintf(stderr, "%d", levels[i]>9?0:levels[i]);
			}
			fprintf(stderr, "\n");
		}
#endif
	}
	fz_always(ctx)
	{
		fz_free(ctx, types);
	}
	fz_catch(ctx)
	{
		fz_free(ctx, levels);
		fz_rethrow(ctx);
	}
	return levels;
}



/* Partitions the given uint16_t sequence into one or more unidirectional
 * fragments and invokes the given callback function for each fragment.
 */
void Bidi_fragmentText(fz_context *ctx,
			const uint16_t *text,
			size_t textlen,
			Bidi_Direction *baseDir,
			Bidi_Fragment_Callback callback,
			void *arg,
			int bidiFlag)
{
	size_t startOfFragment;
	size_t i;
	Bidi_Level *levels;

	if (text == NULL || callback == NULL || textlen == 0)
		return;

	DBUGH(("Bidi_fragmentText( '%S', len = %d )\n", text, textlen ));

	levels = createLevels(ctx, text, textlen, baseDir, FALSE, bidiFlag);

	/* We now have an array with an embedding level
	 * for each uint16_t in text.
	 */
	assert(levels != NULL);

	fz_try(ctx)
	{
		startOfFragment = 0;
		for (i = 1; i < textlen; i++)
		{
			if (levels[i] != levels[i-1])
			{
				/* We've gone past the end of the fragment.
				 * Create a text object for it, then start
				 * a new fragment.
				 */
				if(ODD(levels[startOfFragment]) != 0)
				{
					/* if RTL check for mirrors and create sub-frags */
					Bidi_createFragmentMirrors(&text[startOfFragment],
								i - startOfFragment,
								callback,
								arg);
				}
				else
				{
					/* otherwise create 1 fragment */
					(*callback)(&text[startOfFragment],
							i - startOfFragment,
							ODD(levels[startOfFragment]),
							UNICODE_EOS,
							arg);
				}
				startOfFragment = i;
			}
		}
		/* Now i == textlen.  Deal with the final (or maybe only) fragment. */
		if(ODD(levels[startOfFragment]) != 0)
		{
			/* if RTL check for mirrors and create sub-frags */
			Bidi_createFragmentMirrors(&text[startOfFragment],
					i - startOfFragment,
					callback,
					arg);
		}
		else
		{
			/* otherwise create 1 fragment */
			(*callback)(&text[startOfFragment],
					i - startOfFragment,
					ODD(levels[startOfFragment]),
					UNICODE_EOS,
					arg);
		}
	}
	fz_always(ctx)
	{
		fz_free(ctx, levels);
	}
	fz_catch(ctx)
	{
		fz_rethrow(ctx);
	}
}
