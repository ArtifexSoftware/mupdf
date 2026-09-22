/* ANSI-C code produced by gperf version 3.2.1 */
/* Command-line: gperf source/html/svg-properties.gperf  */
/* Computed positions: -k'3,8' */

#if !((' ' == 32) && ('!' == 33) && ('"' == 34) && ('#' == 35) \
      && ('%' == 37) && ('&' == 38) && ('\'' == 39) && ('(' == 40) \
      && (')' == 41) && ('*' == 42) && ('+' == 43) && (',' == 44) \
      && ('-' == 45) && ('.' == 46) && ('/' == 47) && ('0' == 48) \
      && ('1' == 49) && ('2' == 50) && ('3' == 51) && ('4' == 52) \
      && ('5' == 53) && ('6' == 54) && ('7' == 55) && ('8' == 56) \
      && ('9' == 57) && (':' == 58) && (';' == 59) && ('<' == 60) \
      && ('=' == 61) && ('>' == 62) && ('?' == 63) && ('A' == 65) \
      && ('B' == 66) && ('C' == 67) && ('D' == 68) && ('E' == 69) \
      && ('F' == 70) && ('G' == 71) && ('H' == 72) && ('I' == 73) \
      && ('J' == 74) && ('K' == 75) && ('L' == 76) && ('M' == 77) \
      && ('N' == 78) && ('O' == 79) && ('P' == 80) && ('Q' == 81) \
      && ('R' == 82) && ('S' == 83) && ('T' == 84) && ('U' == 85) \
      && ('V' == 86) && ('W' == 87) && ('X' == 88) && ('Y' == 89) \
      && ('Z' == 90) && ('[' == 91) && ('\\' == 92) && (']' == 93) \
      && ('^' == 94) && ('_' == 95) && ('a' == 97) && ('b' == 98) \
      && ('c' == 99) && ('d' == 100) && ('e' == 101) && ('f' == 102) \
      && ('g' == 103) && ('h' == 104) && ('i' == 105) && ('j' == 106) \
      && ('k' == 107) && ('l' == 108) && ('m' == 109) && ('n' == 110) \
      && ('o' == 111) && ('p' == 112) && ('q' == 113) && ('r' == 114) \
      && ('s' == 115) && ('t' == 116) && ('u' == 117) && ('v' == 118) \
      && ('w' == 119) && ('x' == 120) && ('y' == 121) && ('z' == 122) \
      && ('{' == 123) && ('|' == 124) && ('}' == 125) && ('~' == 126))
/* The character set is not based on ISO-646.  */
#error "gperf generated tables don't work with this execution character set. Please report a bug to <bug-gperf@gnu.org>."
#endif

#line 1 "source/html/svg-properties.gperf"
struct css_property_info;

#define TOTAL_KEYWORDS 20
#define MIN_WORD_LENGTH 4
#define MAX_WORD_LENGTH 17
#define MIN_HASH_VALUE 4
#define MAX_HASH_VALUE 32
/* maximum key range = 29, duplicates = 0 */

#ifdef __GNUC__
__inline
#else
#ifdef __cplusplus
inline
#endif
#endif
static unsigned int
svg_property_hash (register const char *str, register size_t len)
{
  static unsigned char asso_values[] =
    {
      33, 33, 33, 33, 33, 33, 33, 33, 33, 33,
      33, 33, 33, 33, 33, 33, 33, 33, 33, 33,
      33, 33, 33, 33, 33, 33, 33, 33, 33, 33,
      33, 33, 33, 33, 33, 33, 33, 33, 33, 33,
      33, 33, 33, 33, 33, 33, 33, 33, 33, 33,
      33, 33, 33, 33, 33, 33, 33, 33, 33, 33,
      33, 33, 33, 33, 33, 33, 33, 33, 33, 33,
      33, 33, 33, 33, 33, 33, 33, 33, 33, 33,
      33, 33, 33, 33, 33, 33, 33, 33, 33, 33,
      33, 33, 33, 33, 33, 33, 33, 10, 33, 10,
       0, 33, 33, 33, 33,  5, 33, 33,  0, 10,
       0, 10, 33, 33,  0, 33, 33, 33, 33,  0,
       5,  0, 20, 33, 33, 33, 33, 33, 33, 33,
      33, 33, 33, 33, 33, 33, 33, 33, 33, 33,
      33, 33, 33, 33, 33, 33, 33, 33, 33, 33,
      33, 33, 33, 33, 33, 33, 33, 33, 33, 33,
      33, 33, 33, 33, 33, 33, 33, 33, 33, 33,
      33, 33, 33, 33, 33, 33, 33, 33, 33, 33,
      33, 33, 33, 33, 33, 33, 33, 33, 33, 33,
      33, 33, 33, 33, 33, 33, 33, 33, 33, 33,
      33, 33, 33, 33, 33, 33, 33, 33, 33, 33,
      33, 33, 33, 33, 33, 33, 33, 33, 33, 33,
      33, 33, 33, 33, 33, 33, 33, 33, 33, 33,
      33, 33, 33, 33, 33, 33, 33, 33, 33, 33,
      33, 33, 33, 33, 33, 33, 33, 33, 33, 33,
      33, 33, 33, 33, 33, 33
    };
  register unsigned int hval = len;

  switch (hval)
    {
      default:
        hval += asso_values[(unsigned char)str[7]];
#if (defined __cplusplus && (__cplusplus >= 201703L || (__cplusplus >= 201103L && defined __clang__ && __clang_major__ + (__clang_minor__ >= 9) > 3))) || (defined __STDC_VERSION__ && __STDC_VERSION__ >= 202000L && ((defined __GNUC__ && __GNUC__ >= 10) || (defined __clang__ && __clang_major__ >= 9)))
      [[fallthrough]];
#elif (defined __GNUC__ && __GNUC__ >= 7) || (defined __clang__ && __clang_major__ >= 10)
      __attribute__ ((__fallthrough__));
#endif
      /*FALLTHROUGH*/
      case 7:
      case 6:
      case 5:
      case 4:
      case 3:
        hval += asso_values[(unsigned char)str[2]];
        break;
    }
  return hval;
}

#if (defined __GNUC__ && __GNUC__ + (__GNUC_MINOR__ >= 6) > 4) || (defined __clang__ && __clang_major__ >= 3)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmissing-field-initializers"
#endif
static struct css_property_info svg_property_list[] =
  {
    {""}, {""}, {""}, {""},
#line 8 "source/html/svg-properties.gperf"
    {"fill",SVG_ATT_FILL},
#line 27 "source/html/svg-properties.gperf"
    {"width",SVG_ATT_WIDTH},
#line 19 "source/html/svg-properties.gperf"
    {"stroke",SVG_ATT_STROKE},
    {""}, {""},
#line 10 "source/html/svg-properties.gperf"
    {"fill-rule",SVG_ATT_FILL_RULE},
#line 13 "source/html/svg-properties.gperf"
    {"font-style",SVG_ATT_FONT_STYLE},
#line 15 "source/html/svg-properties.gperf"
    {"height",SVG_ATT_HEIGHT},
#line 24 "source/html/svg-properties.gperf"
    {"stroke-width",SVG_ATT_STROKE_WIDTH},
    {""},
#line 20 "source/html/svg-properties.gperf"
    {"stroke-linecap",SVG_ATT_STROKE_LINECAP},
#line 21 "source/html/svg-properties.gperf"
    {"stroke-linejoin",SVG_ATT_STROKE_LINEJOIN},
#line 14 "source/html/svg-properties.gperf"
    {"font-weight",SVG_ATT_FONT_WEIGHT},
#line 16 "source/html/svg-properties.gperf"
    {"opacity",SVG_ATT_OPACITY},
    {""},
#line 26 "source/html/svg-properties.gperf"
    {"transform",SVG_ATT_TRANSFORM},
#line 17 "source/html/svg-properties.gperf"
    {"stop-color",SVG_ATT_STOP_COLOR},
#line 11 "source/html/svg-properties.gperf"
    {"font-family",SVG_ATT_FONT_FAMILY},
#line 9 "source/html/svg-properties.gperf"
    {"fill-opacity",SVG_ATT_FILL_OPACITY},
    {""},
#line 23 "source/html/svg-properties.gperf"
    {"stroke-opacity",SVG_ATT_STROKE_OPACITY},
    {""},
#line 25 "source/html/svg-properties.gperf"
    {"text-anchor",SVG_ATT_TEXT_ANCHOR},
#line 22 "source/html/svg-properties.gperf"
    {"stroke-miterlimit",SVG_ATT_STROKE_MITERLIMIT},
    {""},
#line 12 "source/html/svg-properties.gperf"
    {"font-size",SVG_ATT_FONT_SIZE},
    {""}, {""},
#line 18 "source/html/svg-properties.gperf"
    {"stop-opacity",SVG_ATT_STOP_OPACITY}
  };
#if (defined __GNUC__ && __GNUC__ + (__GNUC_MINOR__ >= 6) > 4) || (defined __clang__ && __clang_major__ >= 3)
#pragma GCC diagnostic pop
#endif

struct css_property_info *
svg_property_lookup (register const char *str, register size_t len)
{
  if (len <= MAX_WORD_LENGTH && len >= MIN_WORD_LENGTH)
    {
      register unsigned int key = svg_property_hash (str, len);

      if (key <= MAX_HASH_VALUE)
        {
          register const char *s = svg_property_list[key].name;

          if (*str == *s && !strcmp (str + 1, s + 1))
            return &svg_property_list[key];
        }
    }
  return (struct css_property_info *) 0;
}
