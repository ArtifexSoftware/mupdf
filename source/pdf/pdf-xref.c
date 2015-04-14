#include "mupdf/pdf.h"
#include "mupdf/fitz/document.h"

#undef DEBUG_PROGESSIVE_ADVANCE

#ifdef DEBUG_PROGESSIVE_ADVANCE
#define DEBUGMESS(A) do { fz_warn A; } while (0)
#else
#define DEBUGMESS(A) do { } while (0)
#endif

static inline int iswhite(int ch)
{
	return
		ch == '\000' || ch == '\011' || ch == '\012' ||
		ch == '\014' || ch == '\015' || ch == '\040';
}

/*
 * xref tables
 */

static void pdf_drop_xref_sections(fz_context *ctx, pdf_document *doc)
{
	int x, e;

	for (x = 0; x < doc->num_xref_sections; x++)
	{
		pdf_xref *xref = &doc->xref_sections[x];
		pdf_xref_subsec *sub = xref->subsec;

		while (sub != NULL)
		{
			pdf_xref_subsec *next_sub = sub->next;
			for (e = 0; e < sub->len; e++)
			{
				pdf_xref_entry *entry = &sub->table[e];

				if (entry->obj)
				{
					pdf_drop_obj(ctx, entry->obj);
					fz_drop_buffer(ctx, entry->stm_buf);
				}
			}
			fz_free(ctx, sub->table);
			fz_free(ctx, sub);
			sub = next_sub;
		}

		pdf_drop_obj(ctx, xref->pre_repair_trailer);
		pdf_drop_obj(ctx, xref->trailer);
	}

	fz_free(ctx, doc->xref_sections);
	doc->xref_sections = NULL;
	doc->num_xref_sections = 0;
}

static void
extend_xref_index(fz_context *ctx, pdf_document *doc, int newlen)
{
	int i;

	doc->xref_index = fz_resize_array(ctx, doc->xref_index, newlen, sizeof(int));
	for (i = doc->max_xref_len; i < newlen; i++)
	{
		doc->xref_index[i] = 0;
	}
	doc->max_xref_len = newlen;
}

/* This is only ever called when we already have an incremental
 * xref. This means there will only be 1 subsec, and it will be
 * a complete subsec. */
static void pdf_resize_xref(fz_context *ctx, pdf_document *doc, int newlen)
{
	int i;
	pdf_xref *xref = &doc->xref_sections[0];
	pdf_xref_subsec *sub;

	assert(xref != NULL);
	sub = xref->subsec;
	assert(sub->next == NULL && sub->start == 0 && sub->len == xref->num_objects);
	assert(newlen > xref->num_objects);

	sub->table = fz_resize_array(ctx, sub->table, newlen, sizeof(pdf_xref_entry));
	for (i = xref->num_objects; i < newlen; i++)
	{
		sub->table[i].type = 0;
		sub->table[i].ofs = 0;
		sub->table[i].gen = 0;
		sub->table[i].stm_ofs = 0;
		sub->table[i].stm_buf = NULL;
		sub->table[i].obj = NULL;
	}
	xref->num_objects = newlen;
	sub->len = newlen;
	if (doc->max_xref_len < newlen)
		extend_xref_index(ctx, doc, newlen);
}

static void pdf_populate_next_xref_level(fz_context *ctx, pdf_document *doc)
{
	pdf_xref *xref;
	doc->xref_sections = fz_resize_array(ctx, doc->xref_sections, doc->num_xref_sections + 1, sizeof(pdf_xref));
	doc->num_xref_sections++;

	xref = &doc->xref_sections[doc->num_xref_sections - 1];
	xref->subsec = NULL;
	xref->num_objects = 0;
	xref->trailer = NULL;
	xref->pre_repair_trailer = NULL;
}

pdf_obj *pdf_trailer(fz_context *ctx, pdf_document *doc)
{
	/* Return the document's final trailer */
	pdf_xref *xref = &doc->xref_sections[0];

	return xref->trailer;
}

void pdf_set_populating_xref_trailer(fz_context *ctx, pdf_document *doc, pdf_obj *trailer)
{
	/* Update the trailer of the xref section being populated */
	pdf_xref *xref = &doc->xref_sections[doc->num_xref_sections - 1];
	if (xref->trailer)
	{
		pdf_drop_obj(ctx, xref->pre_repair_trailer);
		xref->pre_repair_trailer = xref->trailer;
	}
	xref->trailer = pdf_keep_obj(ctx, trailer);
}

int pdf_xref_len(fz_context *ctx, pdf_document *doc)
{
	return doc->max_xref_len;
}

/* Ensure that the given xref has a single subsection
 * that covers the entire range. */
static void
ensure_solid_xref(fz_context *ctx, pdf_document *doc, int num, int which)
{
	pdf_xref *xref = &doc->xref_sections[which];
	pdf_xref_subsec *sub = xref->subsec;
	pdf_xref_subsec *new_sub;

	if (num < xref->num_objects)
		num = xref->num_objects;

	if (sub != NULL && sub->next == NULL && sub->start == 0 && sub->len >= num)
		return;

	new_sub = fz_malloc_struct(ctx, pdf_xref_subsec);
	fz_try(ctx)
	{
		new_sub->table = fz_calloc(ctx, num, sizeof(pdf_xref_entry));
		new_sub->start = 0;
		new_sub->len = num;
		new_sub->next = NULL;
	}
	fz_catch(ctx)
	{
		fz_free(ctx, new_sub);
		fz_rethrow(ctx);
	}

	/* Move objects over to the new subsection and destroy the old
	 * ones */
	sub = xref->subsec;
	while (sub != NULL)
	{
		pdf_xref_subsec *next = sub->next;
		int i;

		for (i = 0; i < sub->len; i++)
		{
			new_sub->table[i+sub->start] = sub->table[i];
		}
		fz_free(ctx, sub->table);
		fz_free(ctx, sub);
		sub = next;
	}
	xref->num_objects = num;
	xref->subsec = new_sub;
	if (doc->max_xref_len < num)
		extend_xref_index(ctx, doc, num);
}

/* Used while reading the individual xref sections from a file */
pdf_xref_entry *pdf_get_populating_xref_entry(fz_context *ctx, pdf_document *doc, int num)
{
	/* Return an entry within the xref currently being populated */
	pdf_xref *xref;
	pdf_xref_subsec *sub;

	if (doc->num_xref_sections == 0)
	{
		doc->xref_sections = fz_calloc(ctx, 1, sizeof(pdf_xref));
		doc->num_xref_sections = 1;
	}

	/* Prevent accidental heap underflow */
	if (num < 0)
		fz_throw(ctx, FZ_ERROR_GENERIC, "object number must not be negative (%d)", num);

	/* Return the pointer to the entry in the last section. */
	xref = &doc->xref_sections[doc->num_xref_sections-1];

	for (sub = xref->subsec; sub != NULL; sub = sub->next)
	{
		if (num >= sub->start && num < sub->start + sub->len)
			return &sub->table[num-sub->start];
	}

	/* We've been asked for an object that's not in a subsec. */
	ensure_solid_xref(ctx, doc, num+1, doc->num_xref_sections-1);
	xref = &doc->xref_sections[doc->num_xref_sections-1];
	sub = xref->subsec;

	return &sub->table[num-sub->start];
}

/* Used after loading a document to access entries */
/* This will never throw anything, or return NULL if it is
 * only asked to return objects in range within a 'solid'
 * xref. */
pdf_xref_entry *pdf_get_xref_entry(fz_context *ctx, pdf_document *doc, int i)
{
	pdf_xref *xref;
	pdf_xref_subsec *sub;
	int j;

	if (i < 0)
		fz_throw(ctx, FZ_ERROR_GENERIC, "Negative object number requested");

	if (i <= doc->max_xref_len)
		j = doc->xref_index[i];
	else
		j = 0;

	/* Find the first xref section where the entry is defined. */
	for (; j < doc->num_xref_sections; j++)
	{
		xref = &doc->xref_sections[j];

		if (i < xref->num_objects)
		{
			for (sub = xref->subsec; sub != NULL; sub = sub->next)
			{
				pdf_xref_entry *entry;

				if (i < sub->start || i >= sub->start + sub->len)
					continue;

				entry = &sub->table[i - sub->start];
				if (entry->type)
				{
					doc->xref_index[i] = j;
					return entry;
				}
			}
		}
	}

	/* Didn't find the entry in any section. Return the entry from
	 * the final section. */
	doc->xref_index[i] = 0;
	if (i < xref->num_objects)
	{
		xref = &doc->xref_sections[0];
		for (sub = xref->subsec; sub != NULL; sub = sub->next)
		{
			if (i >= sub->start && i < sub->start + sub->len)
				return &sub->table[i - sub->start];
		}
	}

	/* At this point, we solidify the xref. This ensures that we
	 * can return a pointer. This is the only case where this function
	 * might throw an exception, and it will never happen when we are
	 * working within a 'solid' xref. */
	ensure_solid_xref(ctx, doc, i+1, 0);
	xref = &doc->xref_sections[0];
	sub = xref->subsec;
	return &sub->table[i - sub->start];
}

/*
	Ensure we have an incremental xref section where we can store
	updated versions of indirect objects. This is a new xref section
	consisting of a single xref subsection.
*/
static void ensure_incremental_xref(fz_context *ctx, pdf_document *doc)
{

	if (!doc->xref_altered)
	{
		pdf_xref *xref = &doc->xref_sections[0];
		pdf_xref *pxref;
		pdf_xref_entry *new_table = fz_calloc(ctx, xref->num_objects, sizeof(pdf_xref_entry));
		pdf_xref_subsec *sub;
		pdf_obj *trailer = NULL;
		int i;

		fz_var(trailer);
		fz_try(ctx)
		{
			sub = fz_malloc_struct(ctx, pdf_xref_subsec);
			trailer = pdf_copy_dict(ctx, xref->trailer);
			doc->xref_sections = fz_resize_array(ctx, doc->xref_sections, doc->num_xref_sections + 1, sizeof(pdf_xref));
			xref = &doc->xref_sections[0];
			pxref = &doc->xref_sections[1];
			memmove(pxref, xref, doc->num_xref_sections * sizeof(pdf_xref));
			/* xref->num_objects is already correct */
			xref->subsec = sub;
			xref->trailer = trailer;
			xref->pre_repair_trailer = NULL;
			sub->next = NULL;
			sub->len = xref->num_objects;
			sub->start = 0;
			sub->table = new_table;
			doc->num_xref_sections++;
			doc->xref_altered = 1;
		}
		fz_catch(ctx)
		{
			fz_free(ctx, new_table);
			pdf_drop_obj(ctx, trailer);
			fz_rethrow(ctx);
		}

		/* Update the xref_index */
		for (i = 0; i < doc->max_xref_len; i++)
		{
			doc->xref_index[i]++;
		}
	}
}

/* Used when altering a document */
static pdf_xref_entry *pdf_get_incremental_xref_entry(fz_context *ctx, pdf_document *doc, int i)
{
	pdf_xref *xref;
	pdf_xref_subsec *sub;

	/* Make a new final xref section if we haven't already */
	ensure_incremental_xref(ctx, doc);

	xref = &doc->xref_sections[0];
	if (i >= xref->num_objects)
		pdf_resize_xref(ctx, doc, i + 1);

	sub = xref->subsec;
	assert(sub != NULL && sub->next == NULL);
	assert(i >= sub->start && i < sub->start + sub->len);
	doc->xref_index[i] = 0;
	return &sub->table[i - sub->start];
}

int pdf_xref_is_incremental(fz_context *ctx, pdf_document *doc, int num)
{
	pdf_xref *xref = &doc->xref_sections[0];
	pdf_xref_subsec *sub = xref->subsec;

	assert(sub != NULL && sub->next == NULL && sub->len == xref->num_objects && sub->start == 0);

	return doc->xref_altered && num < xref->num_objects && sub->table[num].type;
}

/* Ensure that the current populating xref has a single subsection
 * that covers the entire range. */
void pdf_ensure_solid_xref(fz_context *ctx, pdf_document *doc, int num)
{
	if (doc->num_xref_sections == 0)
		pdf_populate_next_xref_level(ctx, doc);

	ensure_solid_xref(ctx, doc, num, doc->num_xref_sections-1);
}

/* Ensure that an object has been cloned into the incremental xref section */
void pdf_xref_ensure_incremental_object(fz_context *ctx, pdf_document *doc, int num)
{
	pdf_xref_entry *new_entry, *old_entry;
	pdf_xref_subsec *sub = NULL;
	int i;

	/* Make sure we have created an xref section for incremental updates */
	ensure_incremental_xref(ctx, doc);

	/* Search for the section that contains this object */
	for (i = doc->xref_index[num]; i < doc->num_xref_sections; i++)
	{
		pdf_xref *xref = &doc->xref_sections[i];

		if (num < 0 && num >= xref->num_objects)
			break;
		for (sub = xref->subsec; sub != NULL; sub = sub->next)
		{
			if (sub->start <= num && num < sub->start + sub->len && sub->table[num - sub->start].type)
				break;
		}
		if (sub != NULL)
			break;
	}
	/* sub == NULL implies we did not find it */

	/* If we don't find it, or it's already in the incremental section, return */
	if (i == 0 || sub == NULL)
		return;

	/* Move the object to the incremental section */
	doc->xref_index[num] = 0;
	old_entry = &sub->table[num - sub->start];
	new_entry = pdf_get_incremental_xref_entry(ctx, doc, num);
	*new_entry = *old_entry;
	old_entry->obj = NULL;
	old_entry->stm_buf = NULL;
}

void pdf_replace_xref(fz_context *ctx, pdf_document *doc, pdf_xref_entry *entries, int n)
{
	pdf_xref *xref = NULL;
	pdf_xref_subsec *sub;
	pdf_obj *trailer = pdf_keep_obj(ctx, pdf_trailer(ctx, doc));

	fz_var(xref);
	fz_try(ctx)
	{
		doc->xref_index = fz_calloc(ctx, n, sizeof(int));
		xref = fz_malloc_struct(ctx, pdf_xref);
		sub = fz_malloc_struct(ctx, pdf_xref_subsec);

		/* The new table completely replaces the previous separate sections */
		pdf_drop_xref_sections(ctx, doc);

		sub->table = entries;
		sub->start = 0;
		sub->len = n;
		xref->subsec = sub;
		xref->num_objects = n;
		xref->trailer = trailer;
		trailer = NULL;

		doc->xref_sections = xref;
		doc->num_xref_sections = 1;
		doc->max_xref_len = n;

		memset(doc->xref_index, 0, sizeof(int)*doc->max_xref_len);
	}
	fz_catch(ctx)
	{
		fz_free(ctx, xref);
		pdf_drop_obj(ctx, trailer);
		fz_rethrow(ctx);
	}
}

/*
 * magic version tag and startxref
 */

static void
pdf_load_version(fz_context *ctx, pdf_document *doc)
{
	char buf[20];

	fz_seek(ctx, doc->file, 0, SEEK_SET);
	fz_read_line(ctx, doc->file, buf, sizeof buf);
	if (memcmp(buf, "%PDF-", 5) != 0)
		fz_throw(ctx, FZ_ERROR_GENERIC, "cannot recognize version marker");

	doc->version = 10 * (fz_atof(buf+5) + 0.05);
}

static void
pdf_read_start_xref(fz_context *ctx, pdf_document *doc)
{
	unsigned char buf[1024];
	int t, n;
	int i;

	fz_seek(ctx, doc->file, 0, SEEK_END);

	doc->file_size = fz_tell(ctx, doc->file);

	t = fz_maxi(0, doc->file_size - (int)sizeof buf);
	fz_seek(ctx, doc->file, t, SEEK_SET);

	n = fz_read(ctx, doc->file, buf, sizeof buf);

	for (i = n - 9; i >= 0; i--)
	{
		if (memcmp(buf + i, "startxref", 9) == 0)
		{
			i += 9;
			while (i < n && iswhite(buf[i]))
				i ++;
			doc->startxref = 0;
			while (i < n && buf[i] >= '0' && buf[i] <= '9')
				doc->startxref = doc->startxref * 10 + (buf[i++] - '0');
			if (doc->startxref != 0)
				return;
			break;
		}
	}

	fz_throw(ctx, FZ_ERROR_GENERIC, "cannot find startxref");
}

/*
 * trailer dictionary
 */

static int
pdf_xref_size_from_old_trailer(fz_context *ctx, pdf_document *doc, pdf_lexbuf *buf)
{
	int len;
	char *s;
	int t;
	pdf_token tok;
	int c;
	int size;
	int ofs;
	pdf_obj *trailer = NULL;

	fz_var(trailer);

	/* Record the current file read offset so that we can reinstate it */
	ofs = fz_tell(ctx, doc->file);

	fz_read_line(ctx, doc->file, buf->scratch, buf->size);
	if (strncmp(buf->scratch, "xref", 4) != 0)
		fz_throw(ctx, FZ_ERROR_GENERIC, "cannot find xref marker");

	while (1)
	{
		c = fz_peek_byte(ctx, doc->file);
		if (!(c >= '0' && c <= '9'))
			break;

		fz_read_line(ctx, doc->file, buf->scratch, buf->size);
		s = buf->scratch;
		fz_strsep(&s, " "); /* ignore ofs */
		if (!s)
			fz_throw(ctx, FZ_ERROR_GENERIC, "invalid range marker in xref");
		len = fz_atoi(fz_strsep(&s, " "));
		if (len < 0)
			fz_throw(ctx, FZ_ERROR_GENERIC, "xref range marker must be positive");

		/* broken pdfs where the section is not on a separate line */
		if (s && *s != '\0')
			fz_seek(ctx, doc->file, -(2 + (int)strlen(s)), SEEK_CUR);

		t = fz_tell(ctx, doc->file);
		if (t < 0)
			fz_throw(ctx, FZ_ERROR_GENERIC, "cannot tell in file");
		if (len > (INT_MAX - t) / 20)
			fz_throw(ctx, FZ_ERROR_GENERIC, "xref has too many entries");

		fz_seek(ctx, doc->file, t + 20 * len, SEEK_SET);
	}

	fz_try(ctx)
	{
		tok = pdf_lex(ctx, doc->file, buf);
		if (tok != PDF_TOK_TRAILER)
			fz_throw(ctx, FZ_ERROR_GENERIC, "expected trailer marker");

		tok = pdf_lex(ctx, doc->file, buf);
		if (tok != PDF_TOK_OPEN_DICT)
			fz_throw(ctx, FZ_ERROR_GENERIC, "expected trailer dictionary");

		trailer = pdf_parse_dict(ctx, doc, doc->file, buf);

		size = pdf_to_int(ctx, pdf_dict_get(ctx, trailer, PDF_NAME_Size));
		if (!size)
			fz_throw(ctx, FZ_ERROR_GENERIC, "trailer missing Size entry");
	}
	fz_always(ctx)
	{
		pdf_drop_obj(ctx, trailer);
	}
	fz_catch(ctx)
	{
		fz_rethrow_message(ctx, "cannot parse trailer");
	}

	fz_seek(ctx, doc->file, ofs, SEEK_SET);

	return size;
}

pdf_obj *
pdf_new_ref(fz_context *ctx, pdf_document *doc, pdf_obj *obj)
{
	int num = pdf_create_object(ctx, doc);
	pdf_update_object(ctx, doc, num, obj);
	return pdf_new_indirect(ctx, doc, num, 0);
}

static pdf_xref_entry *
pdf_xref_find_subsection(fz_context *ctx, pdf_document *doc, int ofs, int len)
{
	pdf_xref *xref = &doc->xref_sections[doc->num_xref_sections-1];
	pdf_xref_subsec *sub;
	int new_max;

	/* Different cases here. Case 1) We might be asking for a
	 * subsection (or a subset of a subsection) that we already
	 * have -  Just return it. Case 2) We might be asking for a
	 * completely new subsection - Create it and return it.
	 * Case 3) We might have an overlapping one - Create a 'solid'
	 * subsection and return that. */

	/* Sanity check */
	for (sub = xref->subsec; sub != NULL; sub = sub->next)
	{
		if (ofs >= sub->start && ofs + len <= sub->start + sub->len)
			return &sub->table[ofs-sub->start]; /* Case 1 */
		if (ofs + len > sub->start && ofs <= sub->start + sub->len)
			break; /* Case 3 */
	}

	new_max = xref->num_objects;
	if (new_max < ofs + len)
		new_max = ofs + len;

	if (sub == NULL)
	{
		/* Case 2 */
		sub = fz_malloc_struct(ctx, pdf_xref_subsec);
		fz_try(ctx)
		{
			sub->table = fz_calloc(ctx, len, sizeof(pdf_xref_entry));
			sub->start = ofs;
			sub->len = len;
			sub->next = xref->subsec;
			xref->subsec = sub;
		}
		fz_catch(ctx)
		{
			fz_free(ctx, sub);
			fz_rethrow(ctx);
		}
		xref->num_objects = new_max;
		if (doc->max_xref_len < new_max)
			extend_xref_index(ctx, doc, new_max);
	}
	else
	{
		/* Case 3 */
		ensure_solid_xref(ctx, doc, new_max, doc->num_xref_sections-1);
		xref = &doc->xref_sections[doc->num_xref_sections-1];
		sub = xref->subsec;
	}
	return &sub->table[ofs-sub->start];
}

static pdf_obj *
pdf_read_old_xref(fz_context *ctx, pdf_document *doc, pdf_lexbuf *buf)
{
	fz_stream *file = doc->file;

	int ofs, len;
	char *s;
	int n;
	pdf_token tok;
	int i;
	int c;
	pdf_obj *trailer;
	int xref_len = pdf_xref_size_from_old_trailer(ctx, doc, buf);
	pdf_xref_entry *table;

	fz_read_line(ctx, file, buf->scratch, buf->size);
	if (strncmp(buf->scratch, "xref", 4) != 0)
		fz_throw(ctx, FZ_ERROR_GENERIC, "cannot find xref marker");

	while (1)
	{
		c = fz_peek_byte(ctx, file);
		if (!(c >= '0' && c <= '9'))
			break;

		fz_read_line(ctx, file, buf->scratch, buf->size);
		s = buf->scratch;
		ofs = fz_atoi(fz_strsep(&s, " "));
		len = fz_atoi(fz_strsep(&s, " "));

		/* broken pdfs where the section is not on a separate line */
		if (s && *s != '\0')
		{
			fz_warn(ctx, "broken xref section. proceeding anyway.");
			fz_seek(ctx, file, -(2 + (int)strlen(s)), SEEK_CUR);
		}

		if (ofs < 0)
			fz_throw(ctx, FZ_ERROR_GENERIC, "out of range object num in xref: %d", ofs);

		/* broken pdfs where size in trailer undershoots entries in xref sections */
		if (ofs + len > xref_len)
		{
			fz_warn(ctx, "broken xref section, proceeding anyway.");
		}

		table = pdf_xref_find_subsection(ctx, doc, ofs, len);

		for (i = ofs; i < ofs + len; i++)
		{
			pdf_xref_entry *entry = &table[i-ofs];
			n = fz_read(ctx, file, (unsigned char *) buf->scratch, 20);
			if (n != 20)
				fz_throw(ctx, FZ_ERROR_GENERIC, "unexpected EOF in xref table");
			if (!entry->type)
			{
				s = buf->scratch;

				/* broken pdfs where line start with white space */
				while (*s != '\0' && iswhite(*s))
					s++;

				entry->ofs = atoi(s);
				entry->gen = atoi(s + 11);
				entry->type = s[17];
				if (s[17] != 'f' && s[17] != 'n' && s[17] != 'o')
					fz_throw(ctx, FZ_ERROR_GENERIC, "unexpected xref type: %#x (%d %d R)", s[17], i, entry->gen);
			}
		}
	}

	fz_try(ctx)
	{
		tok = pdf_lex(ctx, file, buf);
		if (tok != PDF_TOK_TRAILER)
			fz_throw(ctx, FZ_ERROR_GENERIC, "expected trailer marker");

		tok = pdf_lex(ctx, file, buf);
		if (tok != PDF_TOK_OPEN_DICT)
			fz_throw(ctx, FZ_ERROR_GENERIC, "expected trailer dictionary");

		trailer = pdf_parse_dict(ctx, doc, file, buf);
	}
	fz_catch(ctx)
	{
		fz_rethrow_message(ctx, "cannot parse trailer");
	}
	return trailer;
}

static void
pdf_read_new_xref_section(fz_context *ctx, pdf_document *doc, fz_stream *stm, int i0, int i1, int w0, int w1, int w2)
{
	pdf_xref_entry *table;
	int i, n;

	if (i0 < 0 || i1 < 0)
		fz_throw(ctx, FZ_ERROR_GENERIC, "negative xref stream entry index");
	//if (i0 + i1 > pdf_xref_len(ctx, doc))
	//	fz_throw(ctx, FZ_ERROR_GENERIC, "xref stream has too many entries");

	table = pdf_xref_find_subsection(ctx, doc, i0, i1);
	for (i = i0; i < i0 + i1; i++)
	{
		pdf_xref_entry *entry = &table[i-i0];
		int a = 0;
		int b = 0;
		int c = 0;

		if (fz_is_eof(ctx, stm))
			fz_throw(ctx, FZ_ERROR_GENERIC, "truncated xref stream");

		for (n = 0; n < w0; n++)
			a = (a << 8) + fz_read_byte(ctx, stm);
		for (n = 0; n < w1; n++)
			b = (b << 8) + fz_read_byte(ctx, stm);
		for (n = 0; n < w2; n++)
			c = (c << 8) + fz_read_byte(ctx, stm);

		if (!entry->type)
		{
			int t = w0 ? a : 1;
			entry->type = t == 0 ? 'f' : t == 1 ? 'n' : t == 2 ? 'o' : 0;
			entry->ofs = w1 ? b : 0;
			entry->gen = w2 ? c : 0;
		}
	}

	doc->has_xref_streams = 1;
}

/* Entered with file locked, remains locked throughout. */
static pdf_obj *
pdf_read_new_xref(fz_context *ctx, pdf_document *doc, pdf_lexbuf *buf)
{
	fz_stream *stm = NULL;
	pdf_obj *trailer = NULL;
	pdf_obj *index = NULL;
	pdf_obj *obj = NULL;
	int num, gen, ofs, stm_ofs;
	int size, w0, w1, w2;
	int t;

	fz_var(trailer);
	fz_var(stm);

	fz_try(ctx)
	{
		ofs = fz_tell(ctx, doc->file);
		trailer = pdf_parse_ind_obj(ctx, doc, doc->file, buf, &num, &gen, &stm_ofs, NULL);
	}
	fz_catch(ctx)
	{
		pdf_drop_obj(ctx, trailer);
		fz_rethrow_message(ctx, "cannot parse compressed xref stream object");
	}

	fz_try(ctx)
	{
		pdf_xref_entry *entry;

		obj = pdf_dict_get(ctx, trailer, PDF_NAME_Size);
		if (!obj)
			fz_throw(ctx, FZ_ERROR_GENERIC, "xref stream missing Size entry (%d %d R)", num, gen);

		size = pdf_to_int(ctx, obj);

		obj = pdf_dict_get(ctx, trailer, PDF_NAME_W);
		if (!obj)
			fz_throw(ctx, FZ_ERROR_GENERIC, "xref stream missing W entry (%d %d R)", num, gen);
		w0 = pdf_to_int(ctx, pdf_array_get(ctx, obj, 0));
		w1 = pdf_to_int(ctx, pdf_array_get(ctx, obj, 1));
		w2 = pdf_to_int(ctx, pdf_array_get(ctx, obj, 2));

		if (w0 < 0)
			fz_warn(ctx, "xref stream objects have corrupt type");
		if (w1 < 0)
			fz_warn(ctx, "xref stream objects have corrupt offset");
		if (w2 < 0)
			fz_warn(ctx, "xref stream objects have corrupt generation");

		w0 = w0 < 0 ? 0 : w0;
		w1 = w1 < 0 ? 0 : w1;
		w2 = w2 < 0 ? 0 : w2;

		index = pdf_dict_get(ctx, trailer, PDF_NAME_Index);

		stm = pdf_open_stream_with_offset(ctx, doc, num, gen, trailer, stm_ofs);

		if (!index)
		{
			pdf_read_new_xref_section(ctx, doc, stm, 0, size, w0, w1, w2);
		}
		else
		{
			int n = pdf_array_len(ctx, index);
			for (t = 0; t < n; t += 2)
			{
				int i0 = pdf_to_int(ctx, pdf_array_get(ctx, index, t + 0));
				int i1 = pdf_to_int(ctx, pdf_array_get(ctx, index, t + 1));
				pdf_read_new_xref_section(ctx, doc, stm, i0, i1, w0, w1, w2);
			}
		}
		entry = pdf_get_populating_xref_entry(ctx, doc, num);
		entry->ofs = ofs;
		entry->gen = gen;
		entry->stm_ofs = stm_ofs;
		pdf_drop_obj(ctx, entry->obj);
		entry->obj = pdf_keep_obj(ctx, trailer);
		entry->type = 'n';
	}
	fz_always(ctx)
	{
		fz_drop_stream(ctx, stm);
	}
	fz_catch(ctx)
	{
		pdf_drop_obj(ctx, trailer);
		fz_rethrow(ctx);
	}

	return trailer;
}

static pdf_obj *
pdf_read_xref(fz_context *ctx, pdf_document *doc, int ofs, pdf_lexbuf *buf)
{
	pdf_obj *trailer;
	int c;

	fz_seek(ctx, doc->file, ofs, SEEK_SET);

	while (iswhite(fz_peek_byte(ctx, doc->file)))
		fz_read_byte(ctx, doc->file);

	fz_try(ctx)
	{
		c = fz_peek_byte(ctx, doc->file);
		if (c == 'x')
			trailer = pdf_read_old_xref(ctx, doc, buf);
		else if (c >= '0' && c <= '9')
			trailer = pdf_read_new_xref(ctx, doc, buf);
		else
			fz_throw(ctx, FZ_ERROR_GENERIC, "cannot recognize xref format");
	}
	fz_catch(ctx)
	{
		fz_rethrow_message(ctx, "cannot read xref (ofs=%d)", ofs);
	}
	return trailer;
}

typedef struct ofs_list_s ofs_list;

struct ofs_list_s
{
	int max;
	int len;
	int *list;
};

static int
read_xref_section(fz_context *ctx, pdf_document *doc, int ofs, pdf_lexbuf *buf, ofs_list *offsets)
{
	pdf_obj *trailer = NULL;
	int xrefstmofs = 0;
	int prevofs = 0;

	fz_var(trailer);

	fz_try(ctx)
	{
		int i;
		/* Avoid potential infinite recursion */
		for (i = 0; i < offsets->len; i ++)
		{
			if (offsets->list[i] == ofs)
				break;
		}
		if (i < offsets->len)
		{
			fz_warn(ctx, "ignoring xref recursion with offset %d", ofs);
			break;
		}
		if (offsets->len == offsets->max)
		{
			offsets->list = fz_resize_array(ctx, offsets->list, offsets->max*2, sizeof(int));
			offsets->max *= 2;
		}
		offsets->list[offsets->len++] = ofs;

		trailer = pdf_read_xref(ctx, doc, ofs, buf);

		pdf_set_populating_xref_trailer(ctx, doc, trailer);

		/* FIXME: do we overwrite free entries properly? */
		/* FIXME: Does this work properly with progression? */
		xrefstmofs = pdf_to_int(ctx, pdf_dict_get(ctx, trailer, PDF_NAME_XRefStm));
		if (xrefstmofs)
		{
			if (xrefstmofs < 0)
				fz_throw(ctx, FZ_ERROR_GENERIC, "negative xref stream offset");

			/*
				Read the XRefStm stream, but throw away the resulting trailer. We do not
				follow any Prev tag therein, as specified on Page 108 of the PDF reference
				1.7
			*/
			pdf_drop_obj(ctx, pdf_read_xref(ctx, doc, xrefstmofs, buf));
		}

		prevofs = pdf_to_int(ctx, pdf_dict_get(ctx, trailer, PDF_NAME_Prev));
		if (prevofs < 0)
			fz_throw(ctx, FZ_ERROR_GENERIC, "negative xref stream offset for previous xref stream");
	}
	fz_always(ctx)
	{
		pdf_drop_obj(ctx, trailer);
	}
	fz_catch(ctx)
	{
		fz_rethrow_message(ctx, "cannot read xref at offset %d", ofs);
	}

	return prevofs;
}

static void
pdf_read_xref_sections(fz_context *ctx, pdf_document *doc, int ofs, pdf_lexbuf *buf, int read_previous)
{
	ofs_list list;

	list.len = 0;
	list.max = 10;
	list.list = fz_malloc_array(ctx, 10, sizeof(int));
	fz_try(ctx)
	{
		while(ofs)
		{
			pdf_populate_next_xref_level(ctx, doc);
			ofs = read_xref_section(ctx, doc, ofs, buf, &list);
			if (!read_previous)
				break;
		}
	}
	fz_always(ctx)
	{
		fz_free(ctx, list.list);
	}
	fz_catch(ctx)
	{
		fz_rethrow(ctx);
	}
}

static void
pdf_prime_xref_index(fz_context *ctx, pdf_document *doc)
{
	int i, j;
	int *idx = doc->xref_index;

	for (i = doc->num_xref_sections-1; i >= 0; i--)
	{
		pdf_xref *xref = &doc->xref_sections[i];
		pdf_xref_subsec *subsec = xref->subsec;
		while (subsec != NULL)
		{
			int start = subsec->start;
			int end = subsec->start + subsec->len;
			for (j = start; j < end; j++)
			{
				char t = subsec->table[j-start].type;
				if (t != 0 && t != 'f')
					idx[j] = i;
			}

			subsec = subsec->next;
		}
	}
}

/*
 * load xref tables from pdf
 *
 * File locked on entry, throughout and on exit.
 */

static void
pdf_load_xref(fz_context *ctx, pdf_document *doc, pdf_lexbuf *buf)
{
	int i;
	int xref_len;
	pdf_xref_entry *entry;

	pdf_read_start_xref(ctx, doc);

	pdf_read_xref_sections(ctx, doc, doc->startxref, buf, 1);

	if (pdf_xref_len(ctx, doc) == 0)
		fz_throw(ctx, FZ_ERROR_GENERIC, "found xref was empty");

	pdf_prime_xref_index(ctx, doc);

	entry = pdf_get_xref_entry(ctx, doc, 0);
	/* broken pdfs where first object is missing */
	if (!entry->type)
	{
		entry->type = 'f';
		entry->gen = 65535;
	}
	/* broken pdfs where first object is not free */
	else if (entry->type != 'f')
		fz_throw(ctx, FZ_ERROR_GENERIC, "first object in xref is not free");

	/* broken pdfs where object offsets are out of range */
	xref_len = pdf_xref_len(ctx, doc);
	for (i = 0; i < xref_len; i++)
	{
		pdf_xref_entry *entry = pdf_get_xref_entry(ctx, doc, i);
		if (entry->type == 'n')
		{
			/* Special case code: "0000000000 * n" means free,
			 * according to some producers (inc Quartz) */
			if (entry->ofs == 0)
				entry->type = 'f';
			else if (entry->ofs <= 0 || entry->ofs >= doc->file_size)
				fz_throw(ctx, FZ_ERROR_GENERIC, "object offset out of range: %d (%d 0 R)", entry->ofs, i);
		}
		if (entry->type == 'o')
			if (entry->ofs <= 0 || entry->ofs >= xref_len || pdf_get_xref_entry(ctx, doc, entry->ofs)->type != 'n')
				fz_throw(ctx, FZ_ERROR_GENERIC, "invalid reference to an objstm that does not exist: %d (%d 0 R)", entry->ofs, i);
	}
}

static void
pdf_load_linear(fz_context *ctx, pdf_document *doc)
{
	pdf_obj *dict = NULL;
	pdf_obj *hint = NULL;
	pdf_obj *o;
	int num, gen, stmofs, lin, len;

	fz_var(dict);
	fz_var(hint);

	fz_try(ctx)
	{
		pdf_xref_entry *entry;

		dict = pdf_parse_ind_obj(ctx, doc, doc->file, &doc->lexbuf.base, &num, &gen, &stmofs, NULL);
		if (!pdf_is_dict(ctx, dict))
			fz_throw(ctx, FZ_ERROR_GENERIC, "Failed to read linearized dictionary");
		o = pdf_dict_get(ctx, dict, PDF_NAME_Linearized);
		if (o == NULL)
			fz_throw(ctx, FZ_ERROR_GENERIC, "Failed to read linearized dictionary");
		lin = pdf_to_int(ctx, o);
		if (lin != 1)
			fz_throw(ctx, FZ_ERROR_GENERIC, "Unexpected version of Linearized tag (%d)", lin);
		len = pdf_to_int(ctx, pdf_dict_get(ctx, dict, PDF_NAME_L));
		if (len != doc->file_length)
			fz_throw(ctx, FZ_ERROR_GENERIC, "File has been updated since linearization");

		pdf_read_xref_sections(ctx, doc, fz_tell(ctx, doc->file), &doc->lexbuf.base, 0);

		doc->page_count = pdf_to_int(ctx, pdf_dict_get(ctx, dict, PDF_NAME_N));
		doc->linear_page_refs = fz_resize_array(ctx, doc->linear_page_refs, doc->page_count, sizeof(pdf_obj *));
		memset(doc->linear_page_refs, 0, doc->page_count * sizeof(pdf_obj*));
		doc->linear_obj = dict;
		doc->linear_pos = fz_tell(ctx, doc->file);
		doc->linear_page1_obj_num = pdf_to_int(ctx, pdf_dict_get(ctx, dict, PDF_NAME_O));
		doc->linear_page_refs[0] = pdf_new_indirect(ctx, doc, doc->linear_page1_obj_num, 0);
		doc->linear_page_num = 0;
		hint = pdf_dict_get(ctx, dict, PDF_NAME_H);
		doc->hint_object_offset = pdf_to_int(ctx, pdf_array_get(ctx, hint, 0));
		doc->hint_object_length = pdf_to_int(ctx, pdf_array_get(ctx, hint, 1));

		entry = pdf_get_populating_xref_entry(ctx, doc, 0);
		entry->type = 'f';
	}
	fz_catch(ctx)
	{
		pdf_drop_obj(ctx, dict);
		fz_rethrow_if(ctx, FZ_ERROR_TRYLATER);
		/* Drop back to non linearized reading mode */
		doc->file_reading_linearly = 0;
	}
}

void
pdf_ocg_set_config(fz_context *ctx, pdf_document *doc, int config)
{
	int i, j, len, len2;
	pdf_ocg_descriptor *desc = doc->ocg;
	pdf_obj *obj, *cobj;
	pdf_obj *name;

	obj = pdf_dict_get(ctx, pdf_dict_get(ctx, pdf_trailer(ctx, doc), PDF_NAME_Root), PDF_NAME_OCProperties);
	if (!obj)
	{
		if (config == 0)
			return;
		else
			fz_throw(ctx, FZ_ERROR_GENERIC, "Unknown OCG config (None known!)");
	}
	if (config == 0)
	{
		cobj = pdf_dict_get(ctx, obj, PDF_NAME_D);
		if (!cobj)
			fz_throw(ctx, FZ_ERROR_GENERIC, "No default OCG config");
	}
	else
	{
		cobj = pdf_array_get(ctx, pdf_dict_get(ctx, obj, PDF_NAME_Configs), config);
		if (!cobj)
			fz_throw(ctx, FZ_ERROR_GENERIC, "Illegal OCG config");
	}

	pdf_drop_obj(ctx, desc->intent);
	desc->intent = pdf_dict_get(ctx, cobj, PDF_NAME_Intent);
	if (desc->intent)
		pdf_keep_obj(ctx, desc->intent);

	len = desc->len;
	name = pdf_dict_get(ctx, cobj, PDF_NAME_BaseState);
	if (pdf_name_eq(ctx, name, PDF_NAME_Unchanged))
	{
		/* Do nothing */
	}
	else if (pdf_name_eq(ctx, name, PDF_NAME_OFF))
	{
		for (i = 0; i < len; i++)
		{
			desc->ocgs[i].state = 0;
		}
	}
	else /* Default to ON */
	{
		for (i = 0; i < len; i++)
		{
			desc->ocgs[i].state = 1;
		}
	}

	obj = pdf_dict_get(ctx, cobj, PDF_NAME_ON);
	len2 = pdf_array_len(ctx, obj);
	for (i = 0; i < len2; i++)
	{
		pdf_obj *o = pdf_array_get(ctx, obj, i);
		int n = pdf_to_num(ctx, o);
		int g = pdf_to_gen(ctx, o);
		for (j=0; j < len; j++)
		{
			if (desc->ocgs[j].num == n && desc->ocgs[j].gen == g)
			{
				desc->ocgs[j].state = 1;
				break;
			}
		}
	}

	obj = pdf_dict_get(ctx, cobj, PDF_NAME_OFF);
	len2 = pdf_array_len(ctx, obj);
	for (i = 0; i < len2; i++)
	{
		pdf_obj *o = pdf_array_get(ctx, obj, i);
		int n = pdf_to_num(ctx, o);
		int g = pdf_to_gen(ctx, o);
		for (j=0; j < len; j++)
		{
			if (desc->ocgs[j].num == n && desc->ocgs[j].gen == g)
			{
				desc->ocgs[j].state = 0;
				break;
			}
		}
	}

	/* FIXME: Should make 'num configs' available in the descriptor. */
	/* FIXME: Should copy out 'Intent' here into the descriptor, and remove
	 * csi->intent in favour of that. */
	/* FIXME: Should copy 'AS' into the descriptor, and visibility
	 * decisions should respect it. */
	/* FIXME: Make 'Order' available via the descriptor (when we have an
	 * app that needs it) */
	/* FIXME: Make 'ListMode' available via the descriptor (when we have
	 * an app that needs it) */
	/* FIXME: Make 'RBGroups' available via the descriptor (when we have
	 * an app that needs it) */
	/* FIXME: Make 'Locked' available via the descriptor (when we have
	 * an app that needs it) */
}

static void
pdf_read_ocg(fz_context *ctx, pdf_document *doc)
{
	pdf_obj *obj, *ocg;
	int len, i;
	pdf_ocg_descriptor *desc;

	fz_var(desc);

	obj = pdf_dict_get(ctx, pdf_dict_get(ctx, pdf_trailer(ctx, doc), PDF_NAME_Root), PDF_NAME_OCProperties);
	if (!obj)
		return;
	ocg = pdf_dict_get(ctx, obj, PDF_NAME_OCGs);
	if (!ocg || !pdf_is_array(ctx, ocg))
		/* Not ever supposed to happen, but live with it. */
		return;
	len = pdf_array_len(ctx, ocg);
	fz_try(ctx)
	{
		desc = fz_calloc(ctx, 1, sizeof(*desc));
		desc->len = len;
		desc->ocgs = fz_calloc(ctx, len, sizeof(*desc->ocgs));
		desc->intent = NULL;
		for (i=0; i < len; i++)
		{
			pdf_obj *o = pdf_array_get(ctx, ocg, i);
			desc->ocgs[i].num = pdf_to_num(ctx, o);
			desc->ocgs[i].gen = pdf_to_gen(ctx, o);
			desc->ocgs[i].state = 1;
		}
		doc->ocg = desc;
	}
	fz_catch(ctx)
	{
		if (desc)
			fz_free(ctx, desc->ocgs);
		fz_free(ctx, desc);
		fz_rethrow(ctx);
	}

	pdf_ocg_set_config(ctx, doc, 0);
}

static void
pdf_drop_ocg(fz_context *ctx, pdf_ocg_descriptor *desc)
{
	if (!desc)
		return;

	pdf_drop_obj(ctx, desc->intent);
	fz_free(ctx, desc->ocgs);
	fz_free(ctx, desc);
}

/*
 * Initialize and load xref tables.
 * If password is not null, try to decrypt.
 */

static void
pdf_init_document(fz_context *ctx, pdf_document *doc)
{
	pdf_obj *encrypt, *id;
	pdf_obj *dict = NULL;
	pdf_obj *obj;
	pdf_obj *nobj = NULL;
	int i, repaired = 0;

	fz_var(dict);
	fz_var(nobj);

	fz_try(ctx)
	{
		pdf_load_version(ctx, doc);

		doc->file_length = fz_stream_meta(ctx, doc->file, FZ_STREAM_META_LENGTH, 0, NULL);
		if (doc->file_length < 0)
			doc->file_length = 0;

		/* Check to see if we should work in progressive mode */
		if (fz_stream_meta(ctx, doc->file, FZ_STREAM_META_PROGRESSIVE, 0, NULL) > 0)
			doc->file_reading_linearly = 1;

		/* Try to load the linearized file if we are in progressive
		 * mode. */
		if (doc->file_reading_linearly)
			pdf_load_linear(ctx, doc);

		/* If we aren't in progressive mode (or the linear load failed
		 * and has set us back to non-progressive mode), load normally.
		 */
		if (!doc->file_reading_linearly)
			pdf_load_xref(ctx, doc, &doc->lexbuf.base);
	}
	fz_catch(ctx)
	{
		pdf_drop_xref_sections(ctx, doc);
		fz_rethrow_if(ctx, FZ_ERROR_TRYLATER);
		fz_warn(ctx, "trying to repair broken xref");
		repaired = 1;
	}

	fz_try(ctx)
	{
		int hasroot, hasinfo;

		if (repaired)
		{
			/* pdf_repair_xref may access xref_index, so reset it properly */
			memset(doc->xref_index, 0, sizeof(int) * doc->max_xref_len);
			pdf_repair_xref(ctx, doc);
			pdf_prime_xref_index(ctx, doc);
		}

		encrypt = pdf_dict_get(ctx, pdf_trailer(ctx, doc), PDF_NAME_Encrypt);
		id = pdf_dict_get(ctx, pdf_trailer(ctx, doc), PDF_NAME_ID);
		if (pdf_is_dict(ctx, encrypt))
			doc->crypt = pdf_new_crypt(ctx, encrypt, id);

		/* Allow lazy clients to read encrypted files with a blank password */
		pdf_authenticate_password(ctx, doc, "");

		if (repaired)
		{
			int xref_len = pdf_xref_len(ctx, doc);
			pdf_repair_obj_stms(ctx, doc);

			hasroot = (pdf_dict_get(ctx, pdf_trailer(ctx, doc), PDF_NAME_Root) != NULL);
			hasinfo = (pdf_dict_get(ctx, pdf_trailer(ctx, doc), PDF_NAME_Info) != NULL);

			for (i = 1; i < xref_len; i++)
			{
				pdf_xref_entry *entry = pdf_get_xref_entry(ctx, doc, i);
				if (entry->type == 0 || entry->type == 'f')
					continue;

				fz_try(ctx)
				{
					dict = pdf_load_object(ctx, doc, i, 0);
				}
				fz_catch(ctx)
				{
					fz_rethrow_if(ctx, FZ_ERROR_TRYLATER);
					fz_warn(ctx, "ignoring broken object (%d 0 R)", i);
					continue;
				}

				if (!hasroot)
				{
					obj = pdf_dict_get(ctx, dict, PDF_NAME_Type);
					if (pdf_name_eq(ctx, obj, PDF_NAME_Catalog))
					{
						nobj = pdf_new_indirect(ctx, doc, i, 0);
						pdf_dict_put(ctx, pdf_trailer(ctx, doc), PDF_NAME_Root, nobj);
						pdf_drop_obj(ctx, nobj);
						nobj = NULL;
					}
				}

				if (!hasinfo)
				{
					if (pdf_dict_get(ctx, dict, PDF_NAME_Creator) || pdf_dict_get(ctx, dict, PDF_NAME_Producer))
					{
						nobj = pdf_new_indirect(ctx, doc, i, 0);
						pdf_dict_put(ctx, pdf_trailer(ctx, doc), PDF_NAME_Info, nobj);
						pdf_drop_obj(ctx, nobj);
						nobj = NULL;
					}
				}

				pdf_drop_obj(ctx, dict);
				dict = NULL;
			}

			/* ensure that strings are not used in their repaired, non-decrypted form */
			if (doc->crypt)
				pdf_clear_xref(ctx, doc);
		}
	}
	fz_catch(ctx)
	{
		pdf_drop_obj(ctx, dict);
		pdf_drop_obj(ctx, nobj);
		fz_rethrow_message(ctx, "cannot open document");
	}

	fz_try(ctx)
	{
		pdf_read_ocg(ctx, doc);
	}
	fz_catch(ctx)
	{
		fz_warn(ctx, "Ignoring Broken Optional Content");
	}

	fz_try(ctx)
	{
		char *version_str;
		obj = pdf_dict_getl(ctx, pdf_trailer(ctx, doc), PDF_NAME_Root, PDF_NAME_Version, NULL);
		version_str = pdf_to_name(ctx, obj);
		if (*version_str)
		{
			int version = 10 * (fz_atof(version_str) + 0.05);
			if (version > doc->version)
				doc->version = version;
		}
	}
	fz_catch(ctx) { }
}

void
pdf_close_document(fz_context *ctx, pdf_document *doc)
{
	pdf_unsaved_sig *usig;
	int i;

	if (!doc)
		return;

	/* Type3 glyphs in the glyph cache can contain pdf_obj pointers
	 * that we are about to destroy. Simplest solution is to bin the
	 * glyph cache at this point. */
	fz_purge_glyph_cache(ctx);

	if (doc->js)
		doc->drop_js(doc->js);

	pdf_drop_xref_sections(ctx, doc);
	fz_free(ctx, doc->xref_index);

	if (doc->focus_obj)
		pdf_drop_obj(ctx, doc->focus_obj);
	if (doc->file)
		fz_drop_stream(ctx, doc->file);
	if (doc->crypt)
		pdf_drop_crypt(ctx, doc->crypt);

	pdf_drop_obj(ctx, doc->linear_obj);
	if (doc->linear_page_refs)
	{
		for (i=0; i < doc->page_count; i++)
		{
			pdf_drop_obj(ctx, doc->linear_page_refs[i]);
		}
		fz_free(ctx, doc->linear_page_refs);
	}
	fz_free(ctx, doc->hint_page);
	fz_free(ctx, doc->hint_shared_ref);
	fz_free(ctx, doc->hint_shared);
	fz_free(ctx, doc->hint_obj_offsets);

	while ((usig = doc->unsaved_sigs) != NULL)
	{
		doc->unsaved_sigs = usig->next;
		pdf_drop_obj(ctx, usig->field);
		pdf_drop_signer(ctx, usig->signer);
		fz_free(ctx, usig);
	}

	for (i=0; i < doc->num_type3_fonts; i++)
	{
		fz_decouple_type3_font(ctx, doc->type3_fonts[i], (void *)doc);
		fz_drop_font(ctx, doc->type3_fonts[i]);
	}
	fz_free(ctx, doc->type3_fonts);

	pdf_drop_ocg(ctx, doc->ocg);

	fz_empty_store(ctx);

	pdf_lexbuf_fin(ctx, &doc->lexbuf.base);

	fz_free(ctx, doc);
}

void
pdf_print_xref(fz_context *ctx, pdf_document *doc)
{
	int i;
	int xref_len = pdf_xref_len(ctx, doc);
	printf("xref\n0 %d\n", xref_len);
	for (i = 0; i < xref_len; i++)
	{
		pdf_xref_entry *entry = pdf_get_xref_entry(ctx, doc, i);
		printf("%05d: %010d %05d %c (stm_ofs=%d; stm_buf=%p)\n", i,
			entry->ofs,
			entry->gen,
			entry->type ? entry->type : '-',
			entry->stm_ofs,
			entry->stm_buf);
	}
}

/*
 * compressed object streams
 */

static pdf_xref_entry *
pdf_load_obj_stm(fz_context *ctx, pdf_document *doc, int num, int gen, pdf_lexbuf *buf, int target)
{
	fz_stream *stm = NULL;
	pdf_obj *objstm = NULL;
	int *numbuf = NULL;
	int *ofsbuf = NULL;

	pdf_obj *obj;
	int first;
	int count;
	int i;
	pdf_token tok;
	pdf_xref_entry *ret_entry = NULL;

	fz_var(numbuf);
	fz_var(ofsbuf);
	fz_var(objstm);
	fz_var(stm);

	fz_try(ctx)
	{
		objstm = pdf_load_object(ctx, doc, num, gen);

		count = pdf_to_int(ctx, pdf_dict_get(ctx, objstm, PDF_NAME_N));
		first = pdf_to_int(ctx, pdf_dict_get(ctx, objstm, PDF_NAME_First));

		if (count < 0)
			fz_throw(ctx, FZ_ERROR_GENERIC, "negative number of objects in object stream");
		if (first < 0)
			fz_throw(ctx, FZ_ERROR_GENERIC, "first object in object stream resides outside stream");

		numbuf = fz_calloc(ctx, count, sizeof(int));
		ofsbuf = fz_calloc(ctx, count, sizeof(int));

		stm = pdf_open_stream(ctx, doc, num, gen);
		for (i = 0; i < count; i++)
		{
			tok = pdf_lex(ctx, stm, buf);
			if (tok != PDF_TOK_INT)
				fz_throw(ctx, FZ_ERROR_GENERIC, "corrupt object stream (%d %d R)", num, gen);
			numbuf[i] = buf->i;

			tok = pdf_lex(ctx, stm, buf);
			if (tok != PDF_TOK_INT)
				fz_throw(ctx, FZ_ERROR_GENERIC, "corrupt object stream (%d %d R)", num, gen);
			ofsbuf[i] = buf->i;
		}

		fz_seek(ctx, stm, first, SEEK_SET);

		for (i = 0; i < count; i++)
		{
			int xref_len = pdf_xref_len(ctx, doc);
			pdf_xref_entry *entry;
			fz_seek(ctx, stm, first + ofsbuf[i], SEEK_SET);

			obj = pdf_parse_stm_obj(ctx, doc, stm, buf);

			if (numbuf[i] <= 0 || numbuf[i] >= xref_len)
			{
				pdf_drop_obj(ctx, obj);
				fz_throw(ctx, FZ_ERROR_GENERIC, "object id (%d 0 R) out of range (0..%d)", numbuf[i], xref_len - 1);
			}

			entry = pdf_get_xref_entry(ctx, doc, numbuf[i]);

			pdf_set_obj_parent(ctx, obj, numbuf[i]);

			if (entry->type == 'o' && entry->ofs == num)
			{
				/* If we already have an entry for this object,
				 * we'd like to drop it and use the new one -
				 * but this means that anyone currently holding
				 * a pointer to the old one will be left with a
				 * stale pointer. Instead, we drop the new one
				 * and trust that the old one is correct. */
				if (entry->obj)
				{
					if (pdf_objcmp(ctx, entry->obj, obj))
						fz_warn(ctx, "Encountered new definition for object %d - keeping the original one", numbuf[i]);
					pdf_drop_obj(ctx, obj);
				}
				else
					entry->obj = obj;
				if (numbuf[i] == target)
					ret_entry = entry;
			}
			else
			{
				pdf_drop_obj(ctx, obj);
			}
		}
	}
	fz_always(ctx)
	{
		fz_drop_stream(ctx, stm);
		fz_free(ctx, ofsbuf);
		fz_free(ctx, numbuf);
		pdf_drop_obj(ctx, objstm);
	}
	fz_catch(ctx)
	{
		fz_rethrow_message(ctx, "cannot open object stream (%d %d R)", num, gen);
	}
	return ret_entry;
}

/*
 * object loading
 */
static int
pdf_obj_read(fz_context *ctx, pdf_document *doc, int *offset, int *nump, pdf_obj **page)
{
	pdf_lexbuf *buf = &doc->lexbuf.base;
	int num, numofs, gen, genofs, stmofs, tmpofs, tok;
	int xref_len;
	pdf_xref_entry *entry;
	int newtmpofs;

	numofs = *offset;
	fz_seek(ctx, doc->file, numofs, SEEK_SET);

	/* We expect to read 'num' here */
	tok = pdf_lex(ctx, doc->file, buf);
	genofs = fz_tell(ctx, doc->file);
	if (tok != PDF_TOK_INT)
	{
		/* Failed! */
		DEBUGMESS((ctx, "skipping unexpected data (tok=%d) at %d", tok, *offset));
		*offset = genofs;
		return tok == PDF_TOK_EOF;
	}
	*nump = num = buf->i;

	/* We expect to read 'gen' here */
	tok = pdf_lex(ctx, doc->file, buf);
	tmpofs = fz_tell(ctx, doc->file);
	if (tok != PDF_TOK_INT)
	{
		/* Failed! */
		DEBUGMESS((ctx, "skipping unexpected data after \"%d\" (tok=%d) at %d", num, tok, *offset));
		*offset = tmpofs;
		return tok == PDF_TOK_EOF;
	}
	gen = buf->i;

	/* We expect to read 'obj' here */
	do
	{
		tmpofs = fz_tell(ctx, doc->file);
		tok = pdf_lex(ctx, doc->file, buf);
		if (tok == PDF_TOK_OBJ)
			break;
		if (tok != PDF_TOK_INT)
		{
			DEBUGMESS((ctx, "skipping unexpected data (tok=%d) at %d", tok, tmpofs));
			*offset = fz_tell(ctx, doc->file);
			return tok == PDF_TOK_EOF;
		}
		DEBUGMESS((ctx, "skipping unexpected int %d at %d", num, numofs));
		*nump = num = gen;
		numofs = genofs;
		gen = buf->i;
		genofs = tmpofs;
	}
	while (1);

	/* Now we read the actual object */
	xref_len = pdf_xref_len(ctx, doc);

	/* When we are reading a progressive file, we typically see:
	 *    File Header
	 *    obj m (Linearization params)
	 *    xref #1 (refers to objects m-n)
	 *    obj m+1
	 *    ...
	 *    obj n
	 *    obj 1
	 *    ...
	 *    obj n-1
	 *    xref #2
	 *
	 * The linearisation params are read elsewhere, hence
	 * whenever we read an object it should just go into the
	 * previous xref.
	 */
	tok = pdf_repair_obj(ctx, doc, buf, &stmofs, NULL, NULL, NULL, page, &newtmpofs);

	do /* So we can break out of it */
	{
		if (num <= 0 || num >= xref_len)
		{
			fz_warn(ctx, "Not a valid object number (%d %d obj)", num, gen);
			break;
		}
		if (gen != 0)
		{
			fz_warn(ctx, "Unexpected non zero generation number in linearized file");
		}
		entry = pdf_get_populating_xref_entry(ctx, doc, num);
		if (entry->type != 0)
		{
			DEBUGMESS((ctx, "Duplicate object found (%d %d obj)", num, gen));
			break;
		}
		if (page && *page)
		{
			DEBUGMESS((ctx, "Successfully read object %d @ %d - and found page %d!", num, numofs, doc->linear_page_num));
			if (!entry->obj)
				entry->obj = pdf_keep_obj(ctx, *page);

			if (doc->linear_page_refs[doc->linear_page_num] == NULL)
				doc->linear_page_refs[doc->linear_page_num] = pdf_new_indirect(ctx, doc, num, gen);
		}
		else
		{
			DEBUGMESS((ctx, "Successfully read object %d @ %d", num, numofs));
		}
		entry->type = 'n';
		entry->gen = 0;
		entry->ofs = numofs;
		entry->stm_ofs = stmofs;
	}
	while (0);
	if (page && *page)
		doc->linear_page_num++;

	if (tok == PDF_TOK_ENDOBJ)
	{
		*offset = fz_tell(ctx, doc->file);
	}
	else
	{
		*offset = newtmpofs;
	}
	return 0;
}

static void
pdf_load_hinted_page(fz_context *ctx, pdf_document *doc, int pagenum)
{

	if (!doc->hints_loaded || !doc->linear_page_refs)
		return;

	if (doc->linear_page_refs[pagenum])
		return;

	fz_try(ctx)
	{
		int num = doc->hint_page[pagenum].number;
		pdf_obj *page = pdf_load_object(ctx, doc, num, 0);
		if (pdf_name_eq(ctx, PDF_NAME_Page, pdf_dict_get(ctx, page, PDF_NAME_Type)))
		{
			/* We have found the page object! */
			DEBUGMESS((ctx, "LoadHintedPage pagenum=%d num=%d", pagenum, num));
			doc->linear_page_refs[pagenum] = pdf_new_indirect(ctx, doc, num, 0);
		}
		pdf_drop_obj(ctx, page);
	}
	fz_catch(ctx)
	{
		fz_rethrow_if(ctx, FZ_ERROR_TRYLATER);
		/* Silently swallow the error and proceed as normal */
	}

}

static int
read_hinted_object(fz_context *ctx, pdf_document *doc, int num)
{
	/* Try to find the object using our hint table. Find the closest
	 * object <= the one we want that has a hint and read forward from
	 * there. */
	int expected = num;
	int curr_pos;
	int start, offset;

	while (doc->hint_obj_offsets[expected] == 0 && expected > 0)
		expected--;
	if (expected != num)
		DEBUGMESS((ctx, "object %d is unhinted, will search forward from %d", expected, num));
	if (expected == 0)	/* No hints found, just bale */
		return 0;

	curr_pos = fz_tell(ctx, doc->file);
	offset = doc->hint_obj_offsets[expected];

	fz_var(expected);

	fz_try(ctx)
	{
		int found;

		/* Try to read forward from there */
		do
		{
			start = offset;
			DEBUGMESS((ctx, "Searching for object %d @ %d", expected, offset));
			pdf_obj_read(ctx, doc, &offset, &found, 0);
			DEBUGMESS((ctx, "Found object %d - next will be @ %d", found, offset));
			if (found <= expected)
			{
				/* We found the right one (or one earlier than
				 * we expected). Update the hints. */
				doc->hint_obj_offsets[expected] = offset;
				doc->hint_obj_offsets[found] = start;
				doc->hint_obj_offsets[found+1] = offset;
				/* Retry with the next one */
				expected = found+1;
			}
			else
			{
				/* We found one later than we expected. */
				doc->hint_obj_offsets[expected] = 0;
				doc->hint_obj_offsets[found] = start;
				doc->hint_obj_offsets[found+1] = offset;
				while (doc->hint_obj_offsets[expected] == 0 && expected > 0)
					expected--;
				if (expected == 0)	/* No hints found, just bale */
					return 0;
			}
		}
		while (found != num);
	}
	fz_always(ctx)
	{
		fz_seek(ctx, doc->file, curr_pos, SEEK_SET);
	}
	fz_catch(ctx)
	{
		fz_rethrow_if(ctx, FZ_ERROR_TRYLATER);
		/* FIXME: Currently we ignore the hint. Perhaps we should
		 * drop back to non-hinted operation here. */
		doc->hint_obj_offsets[expected] = 0;
		fz_rethrow(ctx);
	}
	return 1;
}

pdf_xref_entry *
pdf_cache_object(fz_context *ctx, pdf_document *doc, int num, int gen)
{
	pdf_xref_entry *x;
	int rnum, rgen, try_repair;

	fz_var(try_repair);

	if (num <= 0 || num >= pdf_xref_len(ctx, doc))
		fz_throw(ctx, FZ_ERROR_GENERIC, "object out of range (%d %d R); xref size %d", num, gen, pdf_xref_len(ctx, doc));

object_updated:
	try_repair = 0;
	rnum = num;

	x = pdf_get_xref_entry(ctx, doc, num);

	if (x->obj != NULL)
		return x;

	if (x->type == 'f')
	{
		x->obj = pdf_new_null(ctx, doc);
	}
	else if (x->type == 'n')
	{
		fz_seek(ctx, doc->file, x->ofs, SEEK_SET);

		fz_try(ctx)
		{
			x->obj = pdf_parse_ind_obj(ctx, doc, doc->file, &doc->lexbuf.base,
					&rnum, &rgen, &x->stm_ofs, &try_repair);
		}
		fz_catch(ctx)
		{
			if (!try_repair || fz_caught(ctx) == FZ_ERROR_TRYLATER)
				fz_rethrow(ctx);
		}

		if (!try_repair && rnum != num)
		{
			pdf_drop_obj(ctx, x->obj);
			x->obj = NULL;
			try_repair = (doc->repair_attempted == 0);
		}

		if (try_repair)
		{
			fz_try(ctx)
			{
				pdf_repair_xref(ctx, doc);
				pdf_prime_xref_index(ctx, doc);
			}
			fz_catch(ctx)
			{
				if (rnum == num)
					fz_throw(ctx, FZ_ERROR_GENERIC, "cannot parse object (%d %d R)", num, gen);
				else
					fz_throw(ctx, FZ_ERROR_GENERIC, "found object (%d %d R) instead of (%d %d R)", rnum, rgen, num, gen);
			}
			goto object_updated;
		}

		if (doc->crypt)
			pdf_crypt_obj(ctx, doc->crypt, x->obj, num, gen);
	}
	else if (x->type == 'o')
	{
		if (!x->obj)
		{
			fz_try(ctx)
			{
				x = pdf_load_obj_stm(ctx, doc, x->ofs, 0, &doc->lexbuf.base, num);
			}
			fz_catch(ctx)
			{
				fz_rethrow_message(ctx, "cannot load object stream containing object (%d %d R)", num, gen);
			}
			if (x == NULL)
				fz_throw(ctx, FZ_ERROR_GENERIC, "cannot load object stream containing object (%d %d R)", num, gen);
			if (!x->obj)
				fz_throw(ctx, FZ_ERROR_GENERIC, "object (%d %d R) was not found in its object stream", num, gen);
		}
	}
	else if (doc->hint_obj_offsets && read_hinted_object(ctx, doc, num))
	{
		goto object_updated;
	}
	else if (doc->file_length && doc->linear_pos < doc->file_length)
	{
		fz_throw(ctx, FZ_ERROR_TRYLATER, "cannot find object in xref (%d %d R) - not loaded yet?", num, gen);
	}
	else
	{
		fz_throw(ctx, FZ_ERROR_GENERIC, "cannot find object in xref (%d %d R)", num, gen);
	}

	pdf_set_obj_parent(ctx, x->obj, num);
	return x;
}

pdf_obj *
pdf_load_object(fz_context *ctx, pdf_document *doc, int num, int gen)
{
	pdf_xref_entry *entry;

	fz_try(ctx)
	{
		entry = pdf_cache_object(ctx, doc, num, gen);
	}
	fz_catch(ctx)
	{
		fz_rethrow_message(ctx, "cannot load object (%d %d R) into cache", num, gen);
	}

	assert(entry->obj != NULL);

	return pdf_keep_obj(ctx, entry->obj);
}

pdf_obj *
pdf_resolve_indirect(fz_context *ctx, pdf_obj *ref)
{
	int sanity = 10;
	int num;
	int gen;
	pdf_xref_entry *entry;

	while (pdf_is_indirect(ctx, ref))
	{
		pdf_document *doc;

		if (--sanity == 0)
		{
			fz_warn(ctx, "too many indirections (possible indirection cycle involving %d %d R)", num, gen);
			return NULL;
		}

		doc = pdf_get_indirect_document(ctx, ref);
		if (!doc)
			return NULL;
		num = pdf_to_num(ctx, ref);
		gen = pdf_to_gen(ctx, ref);

		if (num <= 0 || gen < 0)
		{
			fz_warn(ctx, "invalid indirect reference (%d %d R)", num, gen);
			return NULL;
		}

		fz_try(ctx)
		{
			entry = pdf_cache_object(ctx, doc, num, gen);
		}
		fz_catch(ctx)
		{
			fz_rethrow_if(ctx, FZ_ERROR_TRYLATER);
			fz_warn(ctx, "cannot load object (%d %d R) into cache", num, gen);
			return NULL;
		}

		if (entry->obj == NULL)
			return NULL;
		ref = entry->obj;
	}

	return ref;
}

int
pdf_count_objects(fz_context *ctx, pdf_document *doc)
{
	return pdf_xref_len(ctx, doc);
}

int
pdf_create_object(fz_context *ctx, pdf_document *doc)
{
	/* TODO: reuse free object slots by properly linking free object chains in the ofs field */
	pdf_xref_entry *entry;
	int num = pdf_xref_len(ctx, doc);
	entry = pdf_get_incremental_xref_entry(ctx, doc, num);
	entry->type = 'f';
	entry->ofs = -1;
	entry->gen = 0;
	entry->stm_ofs = 0;
	entry->stm_buf = NULL;
	entry->obj = NULL;
	return num;
}

void
pdf_delete_object(fz_context *ctx, pdf_document *doc, int num)
{
	pdf_xref_entry *x;

	if (num <= 0 || num >= pdf_xref_len(ctx, doc))
	{
		fz_warn(ctx, "object out of range (%d 0 R); xref size %d", num, pdf_xref_len(ctx, doc));
		return;
	}

	x = pdf_get_incremental_xref_entry(ctx, doc, num);

	fz_drop_buffer(ctx, x->stm_buf);
	pdf_drop_obj(ctx, x->obj);

	x->type = 'f';
	x->ofs = 0;
	x->gen = 0;
	x->stm_ofs = 0;
	x->stm_buf = NULL;
	x->obj = NULL;
}

void
pdf_update_object(fz_context *ctx, pdf_document *doc, int num, pdf_obj *newobj)
{
	pdf_xref_entry *x;

	if (num <= 0 || num >= pdf_xref_len(ctx, doc))
	{
		fz_warn(ctx, "object out of range (%d 0 R); xref size %d", num, pdf_xref_len(ctx, doc));
		return;
	}

	x = pdf_get_incremental_xref_entry(ctx, doc, num);

	pdf_drop_obj(ctx, x->obj);

	x->type = 'n';
	x->ofs = 0;
	x->obj = pdf_keep_obj(ctx, newobj);

	pdf_set_obj_parent(ctx, newobj, num);
}

void
pdf_update_stream(fz_context *ctx, pdf_document *doc, pdf_obj *obj, fz_buffer *newbuf, int compressed)
{
	int num;
	pdf_xref_entry *x;

	if (pdf_is_indirect(ctx, obj))
		num = pdf_to_num(ctx, obj);
	else
		num = pdf_obj_parent_num(ctx, obj);
	if (num <= 0 || num >= pdf_xref_len(ctx, doc))
	{
		fz_warn(ctx, "object out of range (%d 0 R); xref size %d", num, pdf_xref_len(ctx, doc));
		return;
	}

	x = pdf_get_xref_entry(ctx, doc, num);

	fz_drop_buffer(ctx, x->stm_buf);
	x->stm_buf = fz_keep_buffer(ctx, newbuf);

	pdf_dict_puts_drop(ctx, obj, "Length", pdf_new_int(ctx, doc, newbuf->len));
	if (!compressed)
	{
		pdf_dict_dels(ctx, obj, "Filter");
		pdf_dict_dels(ctx, obj, "DecodeParms");
	}
}

int
pdf_lookup_metadata(fz_context *ctx, pdf_document *doc, const char *key, char *buf, int size)
{
	if (!strcmp(key, "format"))
		return fz_snprintf(buf, size, "PDF %d.%d", doc->version/10, doc->version % 10);

	if (!strcmp(key, "encryption"))
	{
		if (doc->crypt)
			return fz_snprintf(buf, size, "Standard V%d R%d %d-bit %s",
					pdf_crypt_version(ctx, doc),
					pdf_crypt_revision(ctx, doc),
					pdf_crypt_length(ctx, doc),
					pdf_crypt_method(ctx, doc));
		else
			return fz_strlcpy(buf, "None", size);
	}

	if (strstr(key, "info:") == key)
	{
		pdf_obj *info;
		char *s;
		int n;

		info = pdf_dict_get(ctx, pdf_trailer(ctx, doc), PDF_NAME_Info);
		if (!info)
			return -1;

		info = pdf_dict_gets(ctx, info, key + 5);
		if (!info)
			return -1;

		s = pdf_to_utf8(ctx, doc, info);
		n = fz_strlcpy(buf, s, size);
		fz_free(ctx, s);
		return n;
	}

	return -1;
}

fz_transition *
pdf_page_presentation(fz_context *ctx, pdf_page *page, float *duration)
{
	*duration = page->duration;
	if (!page->transition_present)
		return NULL;
	return &page->transition;
}

/*
	Initializers for the fz_document interface.

	The functions are split across two files to allow calls to a
	version of the constructor that does not link in the interpreter.
	The interpreter references the built-in font and cmap resources
	which are quite big. Not linking those into the mubusy binary
	saves roughly 6MB of space.
*/

static pdf_document *
pdf_new_document(fz_context *ctx, fz_stream *file)
{
	pdf_document *doc = fz_malloc_struct(ctx, pdf_document);

	doc->super.refs = 1;
	doc->super.close = (fz_document_close_fn *)pdf_close_document;
	doc->super.needs_password = (fz_document_needs_password_fn *)pdf_needs_password;
	doc->super.authenticate_password = (fz_document_authenticate_password_fn *)pdf_authenticate_password;
	doc->super.has_permission = (fz_document_has_permission_fn *)pdf_has_permission;
	doc->super.load_outline = (fz_document_load_outline_fn *)pdf_load_outline;
	doc->super.count_pages = (fz_document_count_pages_fn *)pdf_count_pages;
	doc->super.load_page = (fz_document_load_page_fn *)pdf_load_page;
	doc->super.lookup_metadata = (fz_document_lookup_metadata_fn *)pdf_lookup_metadata;
	doc->super.write = (fz_document_write_fn *)pdf_write_document;
	doc->update_appearance = pdf_update_appearance;

	pdf_lexbuf_init(ctx, &doc->lexbuf.base, PDF_LEXBUF_LARGE);
	doc->file = fz_keep_stream(ctx, file);

	return doc;
}

pdf_document *
pdf_open_document_with_stream(fz_context *ctx, fz_stream *file)
{
	pdf_document *doc = pdf_new_document(ctx, file);
	fz_try(ctx)
	{
		pdf_init_document(ctx, doc);
	}
	fz_catch(ctx)
	{
		pdf_close_document(ctx, doc);
		fz_rethrow_message(ctx, "cannot load document from stream");
	}
	return doc;
}

pdf_document *
pdf_open_document(fz_context *ctx, const char *filename)
{
	fz_stream *file = NULL;
	pdf_document *doc = NULL;

	fz_var(file);
	fz_var(doc);

	fz_try(ctx)
	{
		file = fz_open_file(ctx, filename);
		doc = pdf_new_document(ctx, file);
		pdf_init_document(ctx, doc);
	}
	fz_always(ctx)
	{
		fz_drop_stream(ctx, file);
	}
	fz_catch(ctx)
	{
		pdf_close_document(ctx, doc);
		fz_rethrow_message(ctx, "cannot load document '%s'", filename);
	}
	return doc;
}

static void
pdf_load_hints(fz_context *ctx, pdf_document *doc, int objnum, int gennum)
{
	fz_stream *stream = NULL;
	pdf_obj *dict;

	fz_var(stream);
	fz_var(dict);

	fz_try(ctx)
	{
		int i, j, least_num_page_objs, page_obj_num_bits;
		int least_page_len, page_len_num_bits, shared_hint_offset;
		/* int least_page_offset, page_offset_num_bits; */
		/* int least_content_stream_len, content_stream_len_num_bits; */
		int num_shared_obj_num_bits, shared_obj_num_bits;
		/* int numerator_bits, denominator_bits; */
		int shared;
		int shared_obj_num, shared_obj_offset, shared_obj_count_page1;
		int shared_obj_count_total;
		int least_shared_group_len, shared_group_len_num_bits;
		int max_object_num = pdf_xref_len(ctx, doc);

		stream = pdf_open_stream(ctx, doc, objnum, gennum);
		dict = pdf_get_xref_entry(ctx, doc, objnum)->obj;
		if (dict == NULL || !pdf_is_dict(ctx, dict))
			fz_throw(ctx, FZ_ERROR_GENERIC, "malformed hint object");

		shared_hint_offset = pdf_to_int(ctx, pdf_dict_get(ctx, dict, PDF_NAME_S));

		/* Malloc the structures (use realloc to cope with the fact we
		 * may try this several times before enough data is loaded) */
		doc->hint_page = fz_resize_array(ctx, doc->hint_page, doc->page_count+1, sizeof(*doc->hint_page));
		memset(doc->hint_page, 0, sizeof(*doc->hint_page) * (doc->page_count+1));
		doc->hint_obj_offsets = fz_resize_array(ctx, doc->hint_obj_offsets, max_object_num, sizeof(*doc->hint_obj_offsets));
		memset(doc->hint_obj_offsets, 0, sizeof(*doc->hint_obj_offsets) * max_object_num);
		doc->hint_obj_offsets_max = max_object_num;

		/* Read the page object hints table: Header first */
		least_num_page_objs = fz_read_bits(ctx, stream, 32);
		/* The following is sometimes a lie, but we read this version,
		 * as other table values are built from it. In
		 * pdf_reference17.pdf, this points to 2 objects before the
		 * first pages page object. */
		doc->hint_page[0].offset = fz_read_bits(ctx, stream, 32);
		if (doc->hint_page[0].offset > doc->hint_object_offset)
			doc->hint_page[0].offset += doc->hint_object_length;
		page_obj_num_bits = fz_read_bits(ctx, stream, 16);
		least_page_len = fz_read_bits(ctx, stream, 32);
		page_len_num_bits = fz_read_bits(ctx, stream, 16);
		/* least_page_offset = */ (void) fz_read_bits(ctx, stream, 32);
		/* page_offset_num_bits = */ (void) fz_read_bits(ctx, stream, 16);
		/* least_content_stream_len = */ (void) fz_read_bits(ctx, stream, 32);
		/* content_stream_len_num_bits = */ (void) fz_read_bits(ctx, stream, 16);
		num_shared_obj_num_bits = fz_read_bits(ctx, stream, 16);
		shared_obj_num_bits = fz_read_bits(ctx, stream, 16);
		/* numerator_bits = */ (void) fz_read_bits(ctx, stream, 16);
		/* denominator_bits = */ (void) fz_read_bits(ctx, stream, 16);

		/* Item 1: Page object numbers */
		doc->hint_page[0].number = doc->linear_page1_obj_num;
		/* We don't care about the number of objects in the first page */
		(void)fz_read_bits(ctx, stream, page_obj_num_bits);
		j = 1;
		for (i = 1; i < doc->page_count; i++)
		{
			int delta_page_objs = fz_read_bits(ctx, stream, page_obj_num_bits);

			doc->hint_page[i].number = j;
			j += least_num_page_objs + delta_page_objs;
		}
		doc->hint_page[i].number = j; /* Not a real page object */
		fz_sync_bits(ctx, stream);
		/* Item 2: Page lengths */
		j = doc->hint_page[0].offset;
		for (i = 0; i < doc->page_count; i++)
		{
			int delta_page_len = fz_read_bits(ctx, stream, page_len_num_bits);
			int old = j;

			doc->hint_page[i].offset = j;
			j += least_page_len + delta_page_len;
			if (old <= doc->hint_object_offset && j > doc->hint_object_offset)
				j += doc->hint_object_length;
		}
		doc->hint_page[i].offset = j;
		fz_sync_bits(ctx, stream);
		/* Item 3: Shared references */
		shared = 0;
		for (i = 0; i < doc->page_count; i++)
		{
			int num_shared_objs = fz_read_bits(ctx, stream, num_shared_obj_num_bits);
			doc->hint_page[i].index = shared;
			shared += num_shared_objs;
		}
		doc->hint_page[i].index = shared;
		doc->hint_shared_ref = fz_resize_array(ctx, doc->hint_shared_ref, shared, sizeof(*doc->hint_shared_ref));
		memset(doc->hint_shared_ref, 0, sizeof(*doc->hint_shared_ref) * shared);
		fz_sync_bits(ctx, stream);
		/* Item 4: Shared references */
		for (i = 0; i < shared; i++)
		{
			int ref = fz_read_bits(ctx, stream, shared_obj_num_bits);
			doc->hint_shared_ref[i] = ref;
		}
		/* Skip items 5,6,7 as we don't use them */

		fz_seek(ctx, stream, shared_hint_offset, SEEK_SET);

		/* Read the shared object hints table: Header first */
		shared_obj_num = fz_read_bits(ctx, stream, 32);
		shared_obj_offset = fz_read_bits(ctx, stream, 32);
		if (shared_obj_offset > doc->hint_object_offset)
			shared_obj_offset += doc->hint_object_length;
		shared_obj_count_page1 = fz_read_bits(ctx, stream, 32);
		shared_obj_count_total = fz_read_bits(ctx, stream, 32);
		shared_obj_num_bits = fz_read_bits(ctx, stream, 16);
		least_shared_group_len = fz_read_bits(ctx, stream, 32);
		shared_group_len_num_bits = fz_read_bits(ctx, stream, 16);

		/* Sanity check the references in Item 4 above to ensure we
		 * don't access out of range with malicious files. */
		for (i = 0; i < shared; i++)
		{
			if (doc->hint_shared_ref[i] >= shared_obj_count_total)
			{
				fz_throw(ctx, FZ_ERROR_GENERIC, "malformed hint stream (shared refs)");
			}
		}

		doc->hint_shared = fz_resize_array(ctx, doc->hint_shared, shared_obj_count_total+1, sizeof(*doc->hint_shared));
		memset(doc->hint_shared, 0, sizeof(*doc->hint_shared) * (shared_obj_count_total+1));

		/* Item 1: Shared references */
		j = doc->hint_page[0].offset;
		for (i = 0; i < shared_obj_count_page1; i++)
		{
			int off = fz_read_bits(ctx, stream, shared_group_len_num_bits);
			int old = j;
			doc->hint_shared[i].offset = j;
			j += off + least_shared_group_len;
			if (old <= doc->hint_object_offset && j > doc->hint_object_offset)
				j += doc->hint_object_length;
		}
		/* FIXME: We would have problems recreating the length of the
		 * last page 1 shared reference group. But we'll never need
		 * to, so ignore it. */
		j = shared_obj_offset;
		for (; i < shared_obj_count_total; i++)
		{
			int off = fz_read_bits(ctx, stream, shared_group_len_num_bits);
			int old = j;
			doc->hint_shared[i].offset = j;
			j += off + least_shared_group_len;
			if (old <= doc->hint_object_offset && j > doc->hint_object_offset)
				j += doc->hint_object_length;
		}
		doc->hint_shared[i].offset = j;
		fz_sync_bits(ctx, stream);
		/* Item 2: Signature flags: read these just so we can skip */
		for (i = 0; i < shared_obj_count_total; i++)
		{
			doc->hint_shared[i].number = fz_read_bits(ctx, stream, 1);
		}
		fz_sync_bits(ctx, stream);
		/* Item 3: Signatures: just skip */
		for (i = 0; i < shared_obj_count_total; i++)
		{
			if (doc->hint_shared[i].number)
			{
				(void) fz_read_bits(ctx, stream, 128);
			}
		}
		fz_sync_bits(ctx, stream);
		/* Item 4: Shared object object numbers */
		j = doc->linear_page1_obj_num; /* FIXME: This is a lie! */
		for (i = 0; i < shared_obj_count_page1; i++)
		{
			doc->hint_shared[i].number = j;
			j += fz_read_bits(ctx, stream, shared_obj_num_bits) + 1;
		}
		j = shared_obj_num;
		for (; i < shared_obj_count_total; i++)
		{
			doc->hint_shared[i].number = j;
			j += fz_read_bits(ctx, stream, shared_obj_num_bits) + 1;
		}
		doc->hint_shared[i].number = j;

		/* Now, actually use the data we have gathered. */
		for (i = 0 /*shared_obj_count_page1*/; i < shared_obj_count_total; i++)
		{
			doc->hint_obj_offsets[doc->hint_shared[i].number] = doc->hint_shared[i].offset;
		}
		for (i = 0; i < doc->page_count; i++)
		{
			doc->hint_obj_offsets[doc->hint_page[i].number] = doc->hint_page[i].offset;
		}
	}
	fz_always(ctx)
	{
		fz_drop_stream(ctx, stream);
	}
	fz_catch(ctx)
	{
		fz_rethrow_if(ctx, FZ_ERROR_TRYLATER);
		/* Don't try to load hints again */
		doc->hints_loaded = 1;
		/* We won't use the linearized object any more. */
		doc->file_reading_linearly = 0;
		/* Any other error becomes a TRYLATER */
		fz_throw(ctx, FZ_ERROR_TRYLATER, "malformed hints object");
	}
	doc->hints_loaded = 1;
}

static void
pdf_load_hint_object(fz_context *ctx, pdf_document *doc)
{
	pdf_lexbuf *buf = &doc->lexbuf.base;
	int curr_pos;

	curr_pos = fz_tell(ctx, doc->file);
	fz_seek(ctx, doc->file, doc->hint_object_offset, SEEK_SET);
	fz_try(ctx)
	{
		while (1)
		{
			pdf_obj *page = NULL;
			int tmpofs, num, gen, tok;

			tok = pdf_lex(ctx, doc->file, buf);
			if (tok != PDF_TOK_INT)
				break;
			num = buf->i;
			tok = pdf_lex(ctx, doc->file, buf);
			if (tok != PDF_TOK_INT)
				break;
			gen = buf->i;
			tok = pdf_lex(ctx, doc->file, buf);
			if (tok != PDF_TOK_OBJ)
				break;
			(void)pdf_repair_obj(ctx, doc, buf, &tmpofs, NULL, NULL, NULL, &page, &tmpofs);
			pdf_load_hints(ctx, doc, num, gen);
		}
	}
	fz_always(ctx)
	{
		fz_seek(ctx, doc->file, curr_pos, SEEK_SET);
	}
	fz_catch(ctx)
	{
		fz_rethrow(ctx);
	}
}

pdf_obj *pdf_progressive_advance(fz_context *ctx, pdf_document *doc, int pagenum)
{
	pdf_lexbuf *buf = &doc->lexbuf.base;
	int curr_pos;
	pdf_obj *page;

	pdf_load_hinted_page(ctx, doc, pagenum);

	if (pagenum < 0 || pagenum >= doc->page_count)
		fz_throw(ctx, FZ_ERROR_GENERIC, "page load out of range (%d of %d)", pagenum, doc->page_count);

	if (doc->linear_pos == doc->file_length)
		return doc->linear_page_refs[pagenum];

	/* Only load hints once, and then only after we have got page 0 */
	if (pagenum > 0 && !doc->hints_loaded && doc->hint_object_offset > 0 && doc->linear_pos >= doc->hint_object_offset)
	{
		/* Found hint object */
		pdf_load_hint_object(ctx, doc);
	}

	DEBUGMESS((ctx, "continuing to try to advance from %d", doc->linear_pos));
	curr_pos = fz_tell(ctx, doc->file);

	fz_var(page);

	fz_try(ctx)
	{
		int eof;
		do
		{
			int num;
			page = NULL;
			eof = pdf_obj_read(ctx, doc, &doc->linear_pos, &num, &page);
			pdf_drop_obj(ctx, page);
			page = NULL;
		}
		while (!eof);

		{
			pdf_obj *catalog;
			pdf_obj *pages;
			doc->linear_pos = doc->file_length;
			pdf_load_xref(ctx, doc, buf);
			catalog = pdf_dict_get(ctx, pdf_trailer(ctx, doc), PDF_NAME_Root);
			pages = pdf_dict_get(ctx, catalog, PDF_NAME_Pages);

			if (!pdf_is_dict(ctx, pages))
				fz_throw(ctx, FZ_ERROR_GENERIC, "missing page tree");
			break;
		}
	}
	fz_always(ctx)
	{
		fz_seek(ctx, doc->file, curr_pos, SEEK_SET);
	}
	fz_catch(ctx)
	{
		pdf_drop_obj(ctx, page);
		if (fz_caught(ctx) == FZ_ERROR_TRYLATER)
		{
			if (doc->linear_page_refs[pagenum] == NULL)
			{
				/* Still not got a page */
				fz_rethrow(ctx);
			}
		}
		else
			fz_rethrow(ctx);
	}

	return doc->linear_page_refs[pagenum];
}

pdf_document *pdf_specifics(fz_context *ctx, fz_document *doc)
{
	return (pdf_document *)((doc && doc->close == (fz_document_close_fn *)pdf_close_document) ? doc : NULL);
}

pdf_document *pdf_create_document(fz_context *ctx)
{
	pdf_document *doc;
	pdf_obj *o = NULL;
	pdf_obj *root;
	pdf_obj *pages;
	pdf_obj *trailer = NULL;

	fz_var(o);
	fz_var(trailer);

	doc = pdf_new_document(ctx, NULL);
	fz_try(ctx)
	{
		doc->version = 14;
		doc->file_size = 0;
		doc->startxref = 0;
		doc->num_xref_sections = 0;
		pdf_get_populating_xref_entry(ctx, doc, 0);
		doc->xref_altered = 1;
		trailer = pdf_new_dict(ctx, doc, 2);
		pdf_dict_put_drop(ctx, trailer, PDF_NAME_Size, pdf_new_int(ctx, doc, 3));
		o = root = pdf_new_dict(ctx, doc, 2);
		pdf_dict_put_drop(ctx, trailer, PDF_NAME_Root, pdf_new_ref(ctx, doc, o));
		pdf_drop_obj(ctx, o);
		o = NULL;
		pdf_dict_put_drop(ctx, root, PDF_NAME_Type, PDF_NAME_Catalog);
		o = pages = pdf_new_dict(ctx, doc, 3);
		pdf_dict_put_drop(ctx, root, PDF_NAME_Pages, pdf_new_ref(ctx, doc, o));
		pdf_drop_obj(ctx, o);
		o = NULL;
		pdf_dict_put_drop(ctx, pages, PDF_NAME_Type, PDF_NAME_Pages);
		pdf_dict_put_drop(ctx, pages, PDF_NAME_Count, pdf_new_int(ctx, doc, 0));
		pdf_dict_put_drop(ctx, pages, PDF_NAME_Kids, pdf_new_array(ctx, doc, 1));
		pdf_set_populating_xref_trailer(ctx, doc, trailer);
		pdf_drop_obj(ctx, trailer);
	}
	fz_catch(ctx)
	{
		pdf_drop_obj(ctx, trailer);
		pdf_drop_obj(ctx, o);
		fz_rethrow_message(ctx, "Failed to create empty document");
	}
	return doc;
}

int
pdf_recognize(fz_context *doc, const char *magic)
{
	char *ext = strrchr(magic, '.');

	if (ext)
	{
		if (!fz_strcasecmp(ext, ".pdf"))
			return 100;
	}
	if (!strcmp(magic, "pdf") || !strcmp(magic, "application/pdf"))
		return 100;

	return 1;
}

fz_document_handler pdf_document_handler =
{
	(fz_document_recognize_fn *)&pdf_recognize,
	(fz_document_open_fn *)&pdf_open_document,
	(fz_document_open_with_stream_fn *)&pdf_open_document_with_stream
};

void pdf_mark_xref(fz_context *ctx, pdf_document *doc)
{
	int x, e;

	for (x = 0; x < doc->num_xref_sections; x++)
	{
		pdf_xref *xref = &doc->xref_sections[x];
		pdf_xref_subsec *sub;

		for (sub = xref->subsec; sub != NULL; sub = sub->next)
		{
			for (e = 0; e < sub->len; e++)
			{
				pdf_xref_entry *entry = &sub->table[e];
				if (entry->obj)
				{
					entry->flags |= PDF_OBJ_FLAG_MARK;
				}
			}
		}
	}
}

void pdf_clear_xref(fz_context *ctx, pdf_document *doc)
{
	int x, e;

	for (x = 0; x < doc->num_xref_sections; x++)
	{
		pdf_xref *xref = &doc->xref_sections[x];
		pdf_xref_subsec *sub;

		for (sub = xref->subsec; sub != NULL; sub = sub->next)
		{
			for (e = 0; e < sub->len; e++)
			{
				pdf_xref_entry *entry = &sub->table[e];
				/* We cannot drop objects if the stream
				 * buffer has been updated */
				if (entry->obj != NULL && entry->stm_buf == NULL)
				{
					if (pdf_obj_refs(ctx, entry->obj) == 1)
					{
						pdf_drop_obj(ctx, entry->obj);
						entry->obj = NULL;
					}
				}
			}
		}
	}
}

void pdf_clear_xref_to_mark(fz_context *ctx, pdf_document *doc)
{
	int x, e;

	for (x = 0; x < doc->num_xref_sections; x++)
	{
		pdf_xref *xref = &doc->xref_sections[x];
		pdf_xref_subsec *sub;

		for (sub = xref->subsec; sub != NULL; sub = sub->next)
		{
			for (e = 0; e < sub->len; e++)
			{
				pdf_xref_entry *entry = &sub->table[e];

				/* We cannot drop objects if the stream buffer has
				 * been updated */
				if (entry->obj != NULL && entry->stm_buf == NULL)
				{
					if ((entry->flags & PDF_OBJ_FLAG_MARK) == 0 && pdf_obj_refs(ctx, entry->obj) == 1)
					{
						pdf_drop_obj(ctx, entry->obj);
						entry->obj = NULL;
					}
				}
			}
		}
	}
}
