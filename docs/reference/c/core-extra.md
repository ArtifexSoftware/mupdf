# Core (Extra)

The following sections describe various data types and functions that are
used internally to implement the other features. These are not usually of
interest to users of the MuPDF library, but are provided anyway because
why not?

## Strings

All text strings in MuPDF use the `UTF-8` encoding.

The following functions encode and decode `UTF-8` characters, and return the
number of bytes used by the `UTF-8` character (at most `FZ_UTFMAX`).

	int fz_chartorune(int *rune, const char *str);
	int fz_runetochar(char *str, int rune);

### Text Locale Independency

Since many of the C string functions are locale dependent, we also provide our
own locale independent versions of these functions. We also have a couple of
semi-standard functions like `strsep` and `strlcpy` that we can't rely on the
system providing. These should be pretty self explanatory:

	char *fz_strdup(fz_context *ctx, const char *s);
	float fz_strtof(const char *s, char **es);
	char *fz_strsep(char **stringp, const char *delim);
	size_t fz_strlcpy(char *dst, const char *src, size_t n);
	size_t fz_strlcat(char *dst, const char *src, size_t n);
	void *fz_memmem(const void *haystack, size_t haystacklen, const void *needle, size_t needlelen);
	int fz_strcasecmp(const char *a, const char *b);

There are also a couple of functions to process filenames and URLs:

`char *fz_cleanname(char *path);`
:	Rewrite path in-place to the shortest string that names the same path.
	Interprets "." and "..", and eliminates multiple and trailing slashes.

`void fz_dirname(char *dir, const char *path, size_t dir_size);`
:	Extract the directory component from a path.

`char *fz_urldecode(char *url);`
:	Decode URL escapes in-place.

### Text Formatting

Our `printf` family handles the common `printf` formatting characters, with a
few minor differences. We also support several non-standard formatting
characters. The same `printf` syntax is used in the `printf` functions in the
I/O module as well.

	size_t fz_vsnprintf(char *buffer, size_t space, const char *fmt, va_list args);
	size_t fz_snprintf(char *buffer, size_t space, const char *fmt, ...);
	char *fz_asprintf(fz_context *ctx, const char *fmt, ...);
	char *fz_pool_asprintf(fz_context *ctx, fz_pool *pool, const char *fmt, ...);

`%%`, `%c`, `%e`, `%f`, `%p`, `%x`, `%d`, `%u`, `%s`
:	These behave as usual, but only take padding (+,0,space), width, and precision arguments.

`%g float`
:	Prints the `float` in the shortest possible format that won't lose precision, except `NaN` to `0`, `+Inf` to `FLT_MAX`, `-Inf` to `-FLT_MAX`.

`%M fz_matrix*`
:	Prints all 6 coefficients in the matrix as `%g` separated by spaces.

`%R fz_rect*`
:	Prints all `x0`, `y0`, `x1`, `y1` in the rectangle as `%g` separated by spaces.

`%P fz_point*`
:	Prints `x`, `y` in the point as `%g` separated by spaces.

`%C int`
:	Formats character as `UTF-8`. Useful to print unicode text.

`%q char*`
:	Formats string using double quotes and C escapes.

`%( char*`
:	Formats string using parenthesis quotes and Postscript escapes.

`%n char*`
:	Formats string using prefix `/` and PDF name hex-escapes.

## Hash Table

We have a generic hash table structure with fixed length keys.

The keys and values are not reference counted by the hash table. Callers are responsible for manually taking care of reference counting when inserting and removing values from the table, should that be desired.

`fz_hash_table *fz_new_hash_table(fz_context *ctx, int initial_size, int key_length, int lock, void (*drop_value)(fz_context *ctx, void *value));`
:	The lock parameter should be zero, any other value will result in
	unpredictable behavior. The `drop_value` callback function to the
	constructor is only used to release values when the hash table is
	destroyed.

`void fz_drop_hash_table(fz_context *ctx, fz_hash_table *table);`
:	Free the hash table and call the `drop_value` function on all the
	values in the table.

`void *fz_hash_find(fz_context *ctx, fz_hash_table *table, const void *key);`
:	Find the value associated with the key. Returns `NULL` if not found.

`void *fz_hash_insert(fz_context *ctx, fz_hash_table *table, const void *key, void *value);`
:	Insert the value into the hash table. Inserting a duplicate entry will
	**not** overwrite the old value, it will return the old value instead.
	Return `NULL` if the value was inserted for the first time. Does not
	reference count the value!

`void fz_hash_remove(fz_context *ctx, fz_hash_table *table, const void *key);`
:	Remove the associated value from the hash table. This will not
	reference count the value!

`void fz_hash_for_each(fz_context *ctx, fz_hash_table *table, void *state, void (*callback)(fz_context *ctx, void *state, void *key, int key_length, void *value);`
:	Iterate and call a function for each key-value pair in the table.

## Binary Tree

The `fz_tree` structure is a self-balancing binary tree that maps text strings to values.

`void *fz_tree_lookup(fz_context *ctx, fz_tree *node, const char *key);`
:	Look up an entry in the tree. Returns `NULL` if not found.

`fz_tree *fz_tree_insert(fz_context *ctx, fz_tree *root, const char *key, void *value);`
:	Insert a new entry into the tree. Do not insert duplicate entries.
	Returns the new root object.

`void fz_drop_tree(fz_context *ctx, fz_tree *node, void (*dropfunc)(fz_context *ctx, void *value));`
:	Free the tree and all the values in it.

There is no constructor for this structure, since there is no containing root
structure. Instead, the insert function returns the new root node. Use `NULL`
for the initial empty tree.

	fz_tree *tree = NULL;
	tree = fz_tree_insert(ctx, tree, "A", my_a_obj);
	tree = fz_tree_insert(ctx, tree, "B", my_b_obj);
	tree = fz_tree_insert(ctx, tree, "C", my_c_obj);
	assert(fz_tree_lookup(ctx, tree, "B") == my_b_obj);


## XML Parser

We have a rudimentary XML parser that handles well formed XML. It does not do
any namespace processing, and it does not validate the XML syntax.

The parser supports `UTF-8`, `UTF-16`, `iso-8859-1`, `iso-8859-7`, `koi8`,
`windows-1250`, `windows-1251`, and `windows-1252` encoded input.

If `preserve_white` is *false*, we will discard all *whitespace-only* text
elements. This is useful for parsing non-text documents such as XPS and SVG.
Preserving whitespace is useful for parsing XHTML.

	typedef struct { opaque } fz_xml_doc;
	typedef struct { opaque } fz_xml;

	fz_xml_doc *fz_parse_xml(fz_context *ctx, fz_buffer *buf, int preserve_white);
	void fz_drop_xml(fz_context *ctx, fz_xml_doc *xml);
	fz_xml *fz_xml_root(fz_xml_doc *xml);

	fz_xml *fz_xml_prev(fz_xml *item);
	fz_xml *fz_xml_next(fz_xml *item);
	fz_xml *fz_xml_up(fz_xml *item);
	fz_xml *fz_xml_down(fz_xml *item);

`int fz_xml_is_tag(fz_xml *item, const char *name);`
:	Returns *true* if the element is a tag with the given name.

`char *fz_xml_tag(fz_xml *item);`
:	Returns the tag name if the element is a tag, otherwise `NULL`.

`char *fz_xml_att(fz_xml *item, const char *att);`
:	Returns the value of the tag element's attribute, or `NULL` if not a tag or missing.

`char *fz_xml_text(fz_xml *item);`
:	Returns the `UTF-8` text of the text element, or `NULL` if not a text element.

`fz_xml *fz_xml_find(fz_xml *item, const char *tag);`
:	Find the next element with the given tag name. Returns the element
	itself if it matches, or the first sibling if it doesn't. Returns
	`NULL` if there is no sibling with that tag name.

`fz_xml *fz_xml_find_next(fz_xml *item, const char *tag);`
:	Find the next sibling element with the given tag name, or `NULL` if none.

`fz_xml *fz_xml_find_down(fz_xml *item, const char *tag);`
:	Find the first child element with the given tag name, or `NULL` if none.
