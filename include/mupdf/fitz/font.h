#ifndef MUPDF_FITZ_FONT_H
#define MUPDF_FITZ_FONT_H

#include "mupdf/fitz/system.h"
#include "mupdf/fitz/context.h"
#include "mupdf/fitz/geometry.h"
#include "mupdf/fitz/buffer.h"

/* forward declaration for circular dependency */
struct fz_device_s;

/*
	An abstract font handle.
*/
typedef struct fz_font_s fz_font;

/*
 * Fonts come in two variants:
 *	Regular fonts are handled by FreeType.
 *	Type 3 fonts have callbacks to the interpreter.
 */

/*
	fz_font_ft_face: Retrieve the FT_Face handle
	for the font.

	font: The font to query

	Returns the FT_Face handle for the font, or NULL
	if not a freetype handled font. (Cast to void *
	to avoid nasty header exposure).
*/
void *fz_font_ft_face(fz_context *ctx, fz_font *font);

/*
	fz_font_t3_procs: Retrieve the Type3 procs
	for a font.

	font: The font to query

	Returns the t3_procs pointer. Will be NULL for a
	non type-3 font.
*/
fz_buffer **fz_font_t3_procs(fz_context *ctx, fz_font *font);

/*
	ft_error_string: map an FT error number to a
	static string.

	err: The error number to lookup.

	Returns a pointer to a static textual representation
	of a freetype error.
*/
const char *ft_error_string(int err);

/* common CJK font collections */
enum { FZ_ADOBE_CNS_1, FZ_ADOBE_GB_1, FZ_ADOBE_JAPAN_1, FZ_ADOBE_KOREA_1 };

/*
	fz_font_flags_t: Every fz_font carries a set of flags
	within it, in a fz_font_flags_t structure.
*/
typedef struct
{
	unsigned int is_mono : 1;
	unsigned int is_serif : 1;
	unsigned int is_bold : 1;
	unsigned int is_italic : 1;
	unsigned int ft_substitute : 1; /* use substitute metrics */
	unsigned int ft_stretch : 1; /* stretch to match PDF metrics */

	unsigned int fake_bold : 1; /* synthesize bold */
	unsigned int fake_italic : 1; /* synthesize italic */
	unsigned int force_hinting : 1; /* force hinting for DynaLab fonts */
	unsigned int has_opentype : 1; /* has opentype shaping tables */
	unsigned int invalid_bbox : 1;
} fz_font_flags_t;

/*
	fz_font_flags: Retrieve a pointer to the font flags
	for a given font. These can then be updated as required.

	font: The font to query

	Returns a pointer to the flags structure (or NULL, if
	the font is NULL).
*/
fz_font_flags_t *fz_font_flags(fz_font *font);

/*
	fz_shaper_data_t: In order to shape a given font, we need to
	declare it to a shaper library (harfbuzz, by default, but others
	are possible). To avoid redeclaring it every time we need to
	shape, we hold a shaper handle and the destructor for it within
	the font itself. The handle is initialised by the caller when
	first required and the destructor is called when the fz_font is
	destroyed.
*/
typedef struct
{
	void *shaper_handle;
	void (*destroy)(fz_context *ctx, void *); /* Destructor for shape_handle */
} fz_shaper_data_t;

/*
	fz_shaper_data_t: Retrieve a pointer to the shaper data
	structure for the given font.

	font: The font to query.

	Returns a pointer to the shaper data structure (or NULL if
	font is NULL).
*/
fz_shaper_data_t *fz_font_shaper_data(fz_context *ctx, fz_font *font);

/*
	fz_font_name: Retrieve a pointer to the name of the font.

	font: The font to query.

	Returns a pointer to an internal copy of the font name.
	Will never be NULL, but may be the empty string.
*/
const char *fz_font_name(fz_context *ctx, fz_font *font);

/*
	fz_font_is_bold: Returns true if the font is bold.
*/
int fz_font_is_bold(fz_context *ctx, fz_font *font);

/*
	fz_font_is_italic: Returns true if the font is italic.
*/
int fz_font_is_italic(fz_context *ctx, fz_font *font);

/*
	fz_font_is_serif: Returns true if the font is serif.
*/
int fz_font_is_serif(fz_context *ctx, fz_font *font);

/*
	fz_font_is_monospaced: Returns true if the font is monospaced.
*/
int fz_font_is_monospaced(fz_context *ctx, fz_font *font);

/*
	fz_font_bbox: Retrieve a pointer to the font bbox.

	font: The font to query.

	Returns a pointer to the font bbox (or NULL if the
	font is NULL).
*/
fz_rect *fz_font_bbox(fz_context *ctx, fz_font *font);

/*
	fz_load_system_font_fn: Type for user supplied system font loading hook.

	name: The name of the font to load.
	bold: 1 if a bold font desired, 0 otherwise.
	italic: 1 if an italic font desired, 0 otherwise.
	needs_exact_metrics: 1 if an exact metric match is required for the font requested.

	Returns a new font handle, or NULL if no font found (or on error).
*/
typedef fz_font *(fz_load_system_font_fn)(fz_context *ctx, const char *name, int bold, int italic, int needs_exact_metrics);

/*
	fz_load_system_cjk_font_fn: Type for user supplied cjk font loading hook.

	name: The name of the font to load.
	ros: The registry from which to load the font (e.g. FZ_ADOBE_KOREA_1)
	serif: 1 if a serif font is desired, 0 otherwise.

	Returns a new font handle, or NULL if no font found (or on error).
*/
typedef fz_font *(fz_load_system_cjk_font_fn)(fz_context *ctx, const char *name, int ros, int serif);

/*
	fz_load_system_fallback_font_fn: Type for user supplied fallback font loading hook.

	name: The name of the font to load.
	script: UCDN script enum.
	language: FZ_LANG enum.
	serif, bold, italic: boolean style flags.

	Returns a new font handle, or NULL if no font found (or on error).
*/
typedef fz_font *(fz_load_system_fallback_font_fn)(fz_context *ctx, int script, int language, int serif, int bold, int italic);

/*
	fz_install_load_system_font_fn: Install functions to allow
	MuPDF to request fonts from the system.

	Only one set of hooks can be in use at a time.
*/
void fz_install_load_system_font_funcs(fz_context *ctx,
	fz_load_system_font_fn *f,
	fz_load_system_cjk_font_fn *f_cjk,
	fz_load_system_fallback_font_fn *f_fallback);

/* fz_load_*_font returns NULL if no font could be loaded (also on error) */
/*
	fz_load_system_font: Attempt to load a given font from the
	system.

	name: The name of the desired font.

	bold: 1 if bold desired, 0 otherwise.

	italic: 1 if italic desired, 0 otherwise.

	needs_exact_metrics: 1 if an exact metrical match is required,
	0 otherwise.

	Returns a new font handle, or NULL if no matching font was found
	(or on error).
*/
fz_font *fz_load_system_font(fz_context *ctx, const char *name, int bold, int italic, int needs_exact_metrics);

/*
	fz_load_system_cjk_font: Attempt to load a given font from
	the system.

	name: The name of the desired font.

	ros: The registry to load the font from (e.g. FZ_ADOBE_KOREA_1)

	serif: 1 if serif desired, 0 otherwise.

	Returns a new font handle, or NULL if no matching font was found
	(or on error).
*/
fz_font *fz_load_system_cjk_font(fz_context *ctx, const char *name, int ros, int serif);

/*
	fz_lookup_builtin_font: Search the builtin fonts for a match.
	Whether a given font is present or not will depend on the
	configuration in which MuPDF is built.

	name: The name of the font desired.

	bold: 1 if bold desired, 0 otherwise.

	italic: 1 if italic desired, 0 otherwise.

	len: Pointer to a place to receive the length of the discovered
	font buffer.

	Returns a pointer to the font file data, or NULL if not present.
*/
const unsigned char *fz_lookup_builtin_font(fz_context *ctx, const char *name, int bold, int italic, int *len);

/*
	fz_lookup_base14_font: Search the builtin base14 fonts for a match.
	Whether a given font is present or not will depend on the
	configuration in which MuPDF is built.

	name: The name of the font desired.

	len: Pointer to a place to receive the length of the discovered
	font buffer.

	Returns a pointer to the font file data, or NULL if not present.
*/
const unsigned char *fz_lookup_base14_font(fz_context *ctx, const char *name, int *len);

/* ToDo:  Share fz_lookup_builtin_font and fz_lookup_icc?  Check with Tor */
/*
	fz_lookup_icc: Search for icc profile.

	name: The name of the profile desired (gray-icc, rgb-icc, cmyk-icc or lab-icc).

	len: Pointer to a place to receive the length of the discovered.

	Returns a pointer to the icc file data, or NULL if not present.
*/
const unsigned char *fz_lookup_icc(fz_context *ctx, const char *name, size_t *len);

/*
	fz_lookup_cjk_font: Search the builtin cjk fonts for a match.
	Whether a font is present or not will depend on the
	configuration in which MuPDF is built.

	registry: The desired registry to lookup in (e.g.
	FZ_ADOBE_KOREA_1).

	serif: 1 if serif desired, 0 otherwise.

	wmode: 1 for vertical mode, 0 for horizontal.

	len: Pointer to a place to receive the length of the discovered
	font buffer.

	index: Pointer to a place to store the index of the discovered
	font.

	Returns a pointer to the font file data, or NULL if not present.
*/
const unsigned char *fz_lookup_cjk_font(fz_context *ctx, int registry, int serif, int wmode, int *len, int *index);

/*
	fz_lookup_noto_font: Search the builtin noto fonts for a match.
	Whether a font is present or not will depend on the
	configuration in which MuPDF is built.

	script: The script desired (e.g. UCDN_SCRIPT_KATAKANA).

	lang: The language desired (e.g. FZ_LANG_ja).

	serif: 1 if serif desired, 0 otherwise.

	len: Pointer to a place to receive the length of the discovered
	font buffer.

	Returns a pointer to the font file data, or NULL if not present.
*/
const unsigned char *fz_lookup_noto_font(fz_context *ctx, int script, int lang, int serif, int *len);

/*
	fz_lookup_noto_symbol_font: Search the builtin noto fonts
	for a symbol font. Whether a font is present or not will
	depend on the configuration in which MuPDF is built.

	len: Pointer to a place to receive the length of the discovered
	font buffer.

	Returns a pointer to the font file data, or NULL if not present.
*/
const unsigned char *fz_lookup_noto_symbol_font(fz_context *ctx, int *len);

/*
	fz_lookup_noto_emoji_font: Search the builtin noto fonts
	for an emoji font. Whether a font is present or not will
	depend on the configuration in which MuPDF is built.

	len: Pointer to a place to receive the length of the discovered
	font buffer.

	Returns a pointer to the font file data, or NULL if not present.
*/
const unsigned char *fz_lookup_noto_emoji_font(fz_context *ctx, int *len);

/*
	fz_load_fallback_font: Try to load a fallback font for the
	given combination of font attributes. Whether a font is
	present or not will depend on the configuration in which
	MuPDF is built.

	script: The script desired (e.g. UCDN_SCRIPT_KATAKANA).

	language: The language desired (e.g. FZ_LANG_ja).

	serif: 1 if serif desired, 0 otherwise.

	bold: 1 if bold desired, 0 otherwise.

	italic: 1 if italic desired, 0 otherwise.

	Returns a new font handle, or NULL if not available.
*/
fz_font *fz_load_fallback_font(fz_context *ctx, int script, int language, int serif, int bold, int italic);

/*
	fz_load_fallback_symbol_font: Try to load a fallback
	symbol font. Whether a font is present or not will
	depend on the configuration in which MuPDF is built.

	Returns a new font handle, or NULL if not available.
*/
fz_font *fz_load_fallback_symbol_font(fz_context *ctx);

/*
	fz_load_fallback_emoji_font: Try to load a fallback
	emoji font. Whether a font is present or not will
	depend on the configuration in which MuPDF is built.

	Returns a new font handle, or NULL if not available.
*/
fz_font *fz_load_fallback_emoji_font(fz_context *ctx);

/*
	fz_new_type3_font: Create a new (empty) type3 font.

	name: Name of font (or NULL).

	matrix: Font matrix.

	Returns a new font handle, or throws exception on
	allocation failure.
*/
fz_font *fz_new_type3_font(fz_context *ctx, const char *name, const fz_matrix *matrix);

/*
	fz_new_font_from_memory: Create a new font from a font
	file in memory.

	name: Name of font (leave NULL to use name from font).

	data: Pointer to the font file data.

	len: Length of the font file data.

	index: Which font from the file to load (0 for default).

	use_glyph_box: 1 if we should use the glyph bbox, 0 otherwise.

	Returns new font handle, or throws exception on error.
*/
fz_font *fz_new_font_from_memory(fz_context *ctx, const char *name, const unsigned char *data, int len, int index, int use_glyph_bbox);

/*
	fz_new_font_from_buffer: Create a new font from a font
	file in a fz_buffer.

	name: Name of font (leave NULL to use name from font).

	buffer: Buffer to load from.

	index: Which font from the file to load (0 for default).

	use_glyph_box: 1 if we should use the glyph bbox, 0 otherwise.

	Returns new font handle, or throws exception on error.
*/
fz_font *fz_new_font_from_buffer(fz_context *ctx, const char *name, fz_buffer *buffer, int index, int use_glyph_bbox);

/*
	fz_new_font_from_file: Create a new font from a font
	file.

	name: Name of font (leave NULL to use name from font).

	path: File path to load from.

	index: Which font from the file to load (0 for default).

	use_glyph_box: 1 if we should use the glyph bbox, 0 otherwise.

	Returns new font handle, or throws exception on error.
*/
fz_font *fz_new_font_from_file(fz_context *ctx, const char *name, const char *path, int index, int use_glyph_bbox);

/*
	Add a reference to an existing fz_font.

	font: The font to add a reference to.

	Returns the same font.
*/
fz_font *fz_keep_font(fz_context *ctx, fz_font *font);

/*
	Drop a reference to a fz_font, destroying the
	font when the last reference is dropped.

	font: The font to drop a reference to.
*/
void fz_drop_font(fz_context *ctx, fz_font *font);

/*
	fz_set_font_bbox: Set the font bbox.

	font: The font to set the bbox for.

	xmin, ymin, xmax, ymax: The bounding box.
*/
void fz_set_font_bbox(fz_context *ctx, fz_font *font, float xmin, float ymin, float xmax, float ymax);

/*
	fz_bound_glyph: Return a bbox for a given glyph in a font.

	font: The font to look for the glyph in.

	gid: The glyph to bound.

	trm: The matrix to apply to the glyph before bounding.

	r: Pointer to a fz_rect to use for storage.

	Returns r, after filling it in with the bounds of the given glyph.
*/
fz_rect *fz_bound_glyph(fz_context *ctx, fz_font *font, int gid, const fz_matrix *trm, fz_rect *r);

/*
	fz_glyph_cacheable: Determine if a given glyph in a font
	is cacheable. Certain glyphs in a type 3 font cannot safely
	be cached, as their appearance depends on the enclosing
	graphic state.

	font: The font to look for the glyph in.

	gif: The glyph to query.

	Returns non-zero if cacheable, 0 if not.
*/
int fz_glyph_cacheable(fz_context *ctx, fz_font *font, int gid);

/*
	fz_run_t3_glyph: Run a glyph from a Type3 font to
	a given device.

	font: The font to find the glyph in.

	gid: The glyph to run.

	trm: The transform to apply.

	dev: The device to render onto.
*/
void fz_run_t3_glyph(fz_context *ctx, fz_font *font, int gid, const fz_matrix *trm, struct fz_device_s *dev);

/*
	fz_decouple_type3_font: Internal function to remove the
	references to a document held by a Type3 font. This is
	called during document destruction to ensure that Type3
	fonts clean up properly.

	Without this call being made, Type3 fonts can be left
	holding pdf_obj references for the sake of interpretation
	operations that will never come. These references
	cannot be freed after the document, hence this function
	forces them to be freed earlier in the process.

	font: The font to decouple.

	t3doc: The document to which the font may refer.
*/
void fz_decouple_type3_font(fz_context *ctx, fz_font *font, void *t3doc);

/*
	fz_advance_glyph: Return the advance for a given glyph.

	font: The font to look for the glyph in.

	glyph: The glyph to find the advance for.

	wmode: 1 for vertical mode, 0 for horizontal.

	Returns the advance for the glyph.
*/
float fz_advance_glyph(fz_context *ctx, fz_font *font, int glyph, int wmode);

/*
	fz_encode_character: Find the glyph id for a given unicode
	character within a font.

	font: The font to look for the unicode character in.

	unicode: The unicode character to encode.

	Returns the glyph id for the given unicode value, or 0 if
	unknown.
*/
int fz_encode_character(fz_context *ctx, fz_font *font, int unicode);

/*
	fz_encode_character_with_fallback: Find the glyph id for
	a given unicode character within a font, falling back to
	an alternative if not found.

	font: The font to look for the unicode character in.

	unicode: The unicode character to encode.

	script: The script in use.

	language: The language in use.

	out_font: The font handle in which the given glyph represents
	the requested unicode character. The caller does not own the
	reference it is passed, so should call fz_keep_font if it is
	not simply to be used immediately.

	Returns the glyph id for the given unicode value in the supplied
	font (and sets *out_font to font) if it is present. Otherwise
	an alternative fallback font (based on script/language) is
	searched for. If the glyph is found therein, *out_font is set
	to this reference, and the glyph reference is returned. If it
	cannot be found anywhere, the function returns 0.
*/
int fz_encode_character_with_fallback(fz_context *ctx, fz_font *font, int unicode, int script, int language, fz_font **out_font);

/*
	fz_get_glyph_name: Find the name of a glyph

	font: The font to look for the glyph in.

	glyph: The glyph id to look for.

	buf: Pointer to a buffer for the name to be inserted into.

	size: The size of the buffer.

	If a font contains a name table, then the name of the glyph
	will be returned in the supplied buffer. Otherwise a name
	is synthesised. The name will be truncated to fit in
	the buffer.
*/
void fz_get_glyph_name(fz_context *ctx, fz_font *font, int glyph, char *buf, int size);

/*
	Get font ascender and descender values.
*/
float fz_font_ascender(fz_context *ctx, fz_font *font);
float fz_font_descender(fz_context *ctx, fz_font *font);

/*
	Internal functions for our Harfbuzz integration
	to work around the lack of thread safety.
*/

/*
	fz_hb_lock: Lock against Harfbuzz being called
	simultaneously in several threads. This reuses
	FZ_LOCK_FREETYPE.
*/
void fz_hb_lock(fz_context *ctx);

/*
	fz_hb_unlock: Unlock after a Harfbuzz call. This reuses
	FZ_LOCK_FREETYPE.
*/
void fz_hb_unlock(fz_context *ctx);

#endif
