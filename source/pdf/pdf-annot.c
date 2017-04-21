#include "mupdf/fitz.h"
#include "mupdf/pdf.h"

#include <string.h>

static pdf_obj *
resolve_dest_rec(fz_context *ctx, pdf_document *doc, pdf_obj *dest, int depth)
{
	if (depth > 10) /* Arbitrary to avoid infinite recursion */
		return NULL;

	if (pdf_is_name(ctx, dest) || pdf_is_string(ctx, dest))
	{
		dest = pdf_lookup_dest(ctx, doc, dest);
		dest = resolve_dest_rec(ctx, doc, dest, depth+1);
		return dest;
	}

	else if (pdf_is_array(ctx, dest))
	{
		return dest;
	}

	else if (pdf_is_dict(ctx, dest))
	{
		dest = pdf_dict_get(ctx, dest, PDF_NAME_D);
		return resolve_dest_rec(ctx, doc, dest, depth+1);
	}

	else if (pdf_is_indirect(ctx, dest))
		return dest;

	return NULL;
}

static pdf_obj *
resolve_dest(fz_context *ctx, pdf_document *doc, pdf_obj *dest)
{
	return resolve_dest_rec(ctx, doc, dest, 0);
}

char *
pdf_parse_link_dest(fz_context *ctx, pdf_document *doc, pdf_obj *dest)
{
	pdf_obj *obj;
	char buf[256];
	char *ld;
	int page;
	int x, y;

	dest = resolve_dest(ctx, doc, dest);
	if (dest == NULL)
	{
		fz_warn(ctx, "undefined link destination");
		return NULL;
	}

	if (pdf_is_name(ctx, dest))
	{
		ld = pdf_to_name(ctx, dest);
		return fz_strdup(ctx, ld);
	}
	else if (pdf_is_string(ctx, dest))
	{
		ld = pdf_to_str_buf(ctx, dest);
		return fz_strdup(ctx, ld);
	}

	obj = pdf_array_get(ctx, dest, 0);
	if (pdf_is_int(ctx, obj))
		page = pdf_to_int(ctx, obj);
	else
	{
		fz_try(ctx)
			page = pdf_lookup_page_number(ctx, doc, obj);
		fz_catch(ctx)
			page = -1;
	}

	x = y = 0;
	obj = pdf_array_get(ctx, dest, 1);
	if (pdf_name_eq(ctx, obj, PDF_NAME_XYZ))
	{
		x = pdf_to_int(ctx, pdf_array_get(ctx, dest, 2));
		y = pdf_to_int(ctx, pdf_array_get(ctx, dest, 3));
	}
	else if (pdf_name_eq(ctx, obj, PDF_NAME_FitR))
	{
		x = pdf_to_int(ctx, pdf_array_get(ctx, dest, 2));
		y = pdf_to_int(ctx, pdf_array_get(ctx, dest, 5));
	}
	else if (pdf_name_eq(ctx, obj, PDF_NAME_FitH) || pdf_name_eq(ctx, obj, PDF_NAME_FitBH))
		y = pdf_to_int(ctx, pdf_array_get(ctx, dest, 2));
	else if (pdf_name_eq(ctx, obj, PDF_NAME_FitV) || pdf_name_eq(ctx, obj, PDF_NAME_FitBV))
		x = pdf_to_int(ctx, pdf_array_get(ctx, dest, 2));

	if (page >= 0)
	{
		if (x != 0 || y != 0)
			fz_snprintf(buf, sizeof buf, "#%d,%d,%d", page + 1, x, y);
		else
			fz_snprintf(buf, sizeof buf, "#%d", page + 1);
		return fz_strdup(ctx, buf);
	}

	return NULL;
}

char *
pdf_parse_file_spec(fz_context *ctx, pdf_document *doc, pdf_obj *file_spec, pdf_obj *dest)
{
	pdf_obj *filename=NULL;
	char *path = NULL;
	char *uri = NULL;
	char buf[256];
	size_t n;

	if (pdf_is_string(ctx, file_spec))
		filename = file_spec;

	if (pdf_is_dict(ctx, file_spec)) {
#if defined(_WIN32) || defined(_WIN64)
		filename = pdf_dict_get(ctx, file_spec, PDF_NAME_DOS);
#else
		filename = pdf_dict_get(ctx, file_spec, PDF_NAME_Unix);
#endif
		if (!filename)
			filename = pdf_dict_geta(ctx, file_spec, PDF_NAME_UF, PDF_NAME_F);
	}

	if (!pdf_is_string(ctx, filename))
	{
		fz_warn(ctx, "cannot parse file specification");
		return NULL;
	}

	path = pdf_to_utf8(ctx, filename);
#if defined(_WIN32) || defined(_WIN64)
	if (strcmp(pdf_to_name(ctx, pdf_dict_gets(ctx, file_spec, "FS")), "URL") != 0)
	{
		/* move the file name into the expected place and use the expected path separator */
		char *c;
		if (path[0] == '/' && (('A' <= path[1] && path[1] <= 'Z') || ('a' <= path[1] && path[1] <= 'z')) && path[2] == '/')
		{
			path[0] = path[1];
			path[1] = ':';
		}
		for (c = path; *c; c++)
		{
			if (*c == '/')
				*c = '\\';
		}
	}
#endif

	if (pdf_is_array(ctx, dest))
		fz_snprintf(buf, sizeof buf, "#page=%d", pdf_to_int(ctx, pdf_array_get(ctx, dest, 0)) + 1);
	else if (pdf_is_name(ctx, dest))
		fz_snprintf(buf, sizeof buf, "#%s", pdf_to_name(ctx, dest));
	else if (pdf_is_string(ctx, dest))
		fz_snprintf(buf, sizeof buf, "#%s", pdf_to_str_buf(ctx, dest));
	else
		buf[0] = 0;

	n = 7 + strlen(path) + strlen(buf) + 1;
	uri = fz_malloc(ctx, n);
	fz_strlcpy(uri, "file://", n);
	fz_strlcat(uri, path, n);
	fz_strlcat(uri, buf, n);
	fz_free(ctx, path);
	return uri;
}

char *
pdf_parse_link_action(fz_context *ctx, pdf_document *doc, pdf_obj *action, int pagenum)
{
	pdf_obj *obj, *dest, *file_spec;

	if (!action)
		return NULL;

	obj = pdf_dict_get(ctx, action, PDF_NAME_S);
	if (pdf_name_eq(ctx, PDF_NAME_GoTo, obj))
	{
		dest = pdf_dict_get(ctx, action, PDF_NAME_D);
		return pdf_parse_link_dest(ctx, doc, dest);
	}
	else if (pdf_name_eq(ctx, PDF_NAME_URI, obj))
	{
		/* URI entries are ASCII strings */
		const char *uri = pdf_to_str_buf(ctx, pdf_dict_get(ctx, action, PDF_NAME_URI));
		if (!fz_is_external_link(ctx, uri))
		{
			pdf_obj *uri_base_obj = pdf_dict_getp(ctx, pdf_trailer(ctx, doc), "Root/URI/Base");
			const char *uri_base = uri_base_obj ? pdf_to_str_buf(ctx, uri_base_obj) : "file://";
			char *new_uri = fz_malloc(ctx, strlen(uri_base) + strlen(uri) + 1);
			strcpy(new_uri, uri_base);
			strcat(new_uri, uri);
			return new_uri;
		}
		return fz_strdup(ctx, uri);
	}
	else if (pdf_name_eq(ctx, PDF_NAME_Launch, obj))
	{
		file_spec = pdf_dict_get(ctx, action, PDF_NAME_F);
		return pdf_parse_file_spec(ctx, doc, file_spec, NULL);
	}
	else if (pdf_name_eq(ctx, PDF_NAME_GoToR, obj))
	{
		dest = pdf_dict_get(ctx, action, PDF_NAME_D);
		file_spec = pdf_dict_get(ctx, action, PDF_NAME_F);
		return pdf_parse_file_spec(ctx, doc, file_spec, dest);
	}
	else if (pdf_name_eq(ctx, PDF_NAME_Named, obj))
	{
		dest = pdf_dict_get(ctx, action, PDF_NAME_N);

		if (pdf_name_eq(ctx, PDF_NAME_FirstPage, dest))
			pagenum = 0;
		else if (pdf_name_eq(ctx, PDF_NAME_LastPage, dest))
			pagenum = pdf_count_pages(ctx, doc) - 1;
		else if (pdf_name_eq(ctx, PDF_NAME_PrevPage, dest) && pagenum >= 0)
		{
			if (pagenum > 0)
				pagenum--;
		}
		else if (pdf_name_eq(ctx, PDF_NAME_NextPage, dest) && pagenum >= 0)
		{
			if (pagenum < pdf_count_pages(ctx, doc) - 1)
				pagenum++;
		}
		else
			return NULL;

		return fz_asprintf(ctx, "#%d", pagenum + 1);
	}

	return NULL;
}

static fz_link *
pdf_load_link(fz_context *ctx, pdf_document *doc, pdf_obj *dict, int pagenum, const fz_matrix *page_ctm)
{
	pdf_obj *action;
	pdf_obj *obj;
	fz_rect bbox;
	char *uri;
	fz_link *link;

	obj = pdf_dict_get(ctx, dict, PDF_NAME_Subtype);
	if (!pdf_name_eq(ctx, obj, PDF_NAME_Link))
		return NULL;

	obj = pdf_dict_get(ctx, dict, PDF_NAME_Rect);
	if (!obj)
		return NULL;

	pdf_to_rect(ctx, obj, &bbox);
	fz_transform_rect(&bbox, page_ctm);

	obj = pdf_dict_get(ctx, dict, PDF_NAME_Dest);
	if (obj)
		uri = pdf_parse_link_dest(ctx, doc, obj);
	else
	{
		action = pdf_dict_get(ctx, dict, PDF_NAME_A);
		/* fall back to additional action button's down/up action */
		if (!action)
			action = pdf_dict_geta(ctx, pdf_dict_get(ctx, dict, PDF_NAME_AA), PDF_NAME_U, PDF_NAME_D);
		uri = pdf_parse_link_action(ctx, doc, action, pagenum);
	}

	if (!uri)
		return NULL;

	link = fz_new_link(ctx, &bbox, doc, uri);
	fz_free(ctx, uri);
	return link;
}

fz_link *
pdf_load_link_annots(fz_context *ctx, pdf_document *doc, pdf_obj *annots, int pagenum, const fz_matrix *page_ctm)
{
	fz_link *link, *head, *tail;
	pdf_obj *obj;
	int i, n;

	head = tail = NULL;
	link = NULL;

	n = pdf_array_len(ctx, annots);
	for (i = 0; i < n; i++)
	{
		/* FIXME: Move the try/catch out of the loop for performance? */
		fz_try(ctx)
		{
			obj = pdf_array_get(ctx, annots, i);
			link = pdf_load_link(ctx, doc, obj, pagenum, page_ctm);
		}
		fz_catch(ctx)
		{
			fz_rethrow_if(ctx, FZ_ERROR_TRYLATER);
			link = NULL;
		}

		if (link)
		{
			if (!head)
				head = tail = link;
			else
			{
				tail->next = link;
				tail = link;
			}
		}
	}

	return head;
}

int
pdf_resolve_link(fz_context *ctx, pdf_document *doc, const char *uri, float *xp, float *yp)
{
	if (uri && uri[0] == '#')
	{
		int page = fz_atoi(uri + 1) - 1;
		if (xp || yp)
		{
			const char *x = strchr(uri, ',');
			const char *y = strrchr(uri, ',');
			if (x && y)
			{
				pdf_obj *obj;
				fz_matrix ctm;
				fz_point p;

				p.x = x ? fz_atoi(x + 1) : 0;
				p.y = y ? fz_atoi(y + 1) : 0;
				obj = pdf_lookup_page_obj(ctx, doc, page);
				pdf_page_obj_transform(ctx, obj, NULL, &ctm);
				fz_transform_point(&p, &ctm);

				if (xp) *xp = p.x;
				if (yp) *yp = p.y;
			}
		}
		return page;
	}
	fz_warn(ctx, "unknown link uri '%s'", uri);
	return -1;
}

static void
pdf_drop_annot_imp(fz_context *ctx, pdf_annot *annot)
{
	pdf_drop_xobject(ctx, annot->ap);
	pdf_drop_obj(ctx, annot->obj);
}

void
pdf_drop_annots(fz_context *ctx, pdf_annot *annot)
{
	while (annot)
	{
		pdf_annot *next = annot->next;
		fz_drop_annot(ctx, &annot->super);
		annot = next;
	}
}

/* Create transform to fit appearance stream to annotation Rect */
void
pdf_annot_transform(fz_context *ctx, pdf_annot *annot, fz_matrix *annot_ctm)
{
	fz_rect bbox, rect;
	fz_matrix matrix;
	float w, h, x, y;

	pdf_to_rect(ctx, pdf_dict_get(ctx, annot->obj, PDF_NAME_Rect), &rect);
	pdf_xobject_bbox(ctx, annot->ap, &bbox);
	pdf_xobject_matrix(ctx, annot->ap, &matrix);

	fz_transform_rect(&bbox, &matrix);
	if (bbox.x1 == bbox.x0)
		w = 0;
	else
		w = (rect.x1 - rect.x0) / (bbox.x1 - bbox.x0);
	if (bbox.y1 == bbox.y0)
		h = 0;
	else
		h = (rect.y1 - rect.y0) / (bbox.y1 - bbox.y0);
	x = rect.x0 - bbox.x0;
	y = rect.y0 - bbox.y0;

	fz_pre_scale(fz_translate(annot_ctm, x, y), w, h);
}

pdf_annot *pdf_new_annot(fz_context *ctx, pdf_page *page)
{
	pdf_annot *annot = fz_new_derived_annot(ctx, pdf_annot);

	annot->super.drop_annot = (fz_annot_drop_fn*)pdf_drop_annot_imp;
	annot->super.bound_annot = (fz_annot_bound_fn*)pdf_bound_annot;
	annot->super.run_annot = (fz_annot_run_fn*)pdf_run_annot;
	annot->super.next_annot = (fz_annot_next_fn*)pdf_next_annot;

	annot->page = page;

	return annot;
}

void
pdf_load_annots(fz_context *ctx, pdf_page *page, pdf_obj *annots)
{
	pdf_document *doc = page->doc;
	pdf_annot *annot, **itr;
	pdf_obj *obj, *ap, *as, *n;
	int i, len, keep_annot;

	fz_var(annot);
	fz_var(itr);
	fz_var(keep_annot);

	itr = &page->annots;

	len = pdf_array_len(ctx, annots);
	/*
	Create an initial linked list of pdf_annot structures with only the obj field
	filled in. We do this because update_appearance has the potential to change
	the annot array, so we don't want to be iterating through the array while
	that happens.
	*/
	fz_try(ctx)
	{
		for (i = 0; i < len; i++)
		{
			obj = pdf_array_get(ctx, annots, i);

			annot = pdf_new_annot(ctx, page);
			*itr = annot;
			annot->obj = pdf_keep_obj(ctx, obj);
			itr = &annot->next;
		}
	}
	fz_catch(ctx)
	{
		pdf_drop_annots(ctx, page->annots);
		page->annots = NULL;
		fz_rethrow(ctx);
	}

	/*
	Iterate through the newly created annot linked list, using a double pointer to
	facilitate deleting broken annotations.
	*/
	itr = &page->annots;
	while (*itr)
	{
		annot = *itr;

		fz_try(ctx)
		{
			pdf_hotspot *hp = &doc->hotspot;

			n = NULL;

			if (doc->update_appearance)
				doc->update_appearance(ctx, doc, annot);

			obj = annot->obj;
			ap = pdf_dict_get(ctx, obj, PDF_NAME_AP);
			as = pdf_dict_get(ctx, obj, PDF_NAME_AS);

			/* We only collect annotations with an appearance
			 * stream into this list, so remove any that don't
			 * (such as links) and continue. */
			keep_annot = pdf_is_dict(ctx, ap);
			if (!keep_annot)
				break;

			if (hp->num == pdf_to_num(ctx, obj) && (hp->state & HOTSPOT_POINTER_DOWN))
			{
				n = pdf_dict_get(ctx, ap, PDF_NAME_D); /* down state */
			}

			if (n == NULL)
				n = pdf_dict_get(ctx, ap, PDF_NAME_N); /* normal state */

			/* lookup current state in sub-dictionary */
			if (!pdf_is_stream(ctx, n))
				n = pdf_dict_get(ctx, n, as);

			annot->ap = NULL;

			if (pdf_is_stream(ctx, n))
			{
				annot->ap = pdf_load_xobject(ctx, doc, n);
				annot->ap_iteration = annot->ap->iteration;
			}
			else
				fz_warn(ctx, "no appearance stream for annotation %d 0 R", pdf_to_num(ctx, annot->obj));

			if (obj == doc->focus_obj)
				doc->focus = annot;

			/* Move to next item in the linked list */
			itr = &annot->next;
		}
		fz_catch(ctx)
		{
			if (fz_caught(ctx) == FZ_ERROR_TRYLATER)
			{
				pdf_drop_annots(ctx, page->annots);
				page->annots = NULL;
				fz_rethrow(ctx);
			}
			keep_annot = 0;
			fz_warn(ctx, "ignoring broken annotation");
		}
		if (!keep_annot)
		{
			/* Move to next item in the linked list, dropping this one */
			*itr = annot->next;
			annot->next = NULL; /* Required because pdf_drop_annots follows the "next" chain */
			pdf_drop_annots(ctx, annot);
		}
	}

	page->annot_tailp = itr;
}

pdf_annot *
pdf_first_annot(fz_context *ctx, pdf_page *page)
{
	return page ? page->annots : NULL;
}

pdf_annot *
pdf_next_annot(fz_context *ctx, pdf_annot *annot)
{
	return annot ? annot->next : NULL;
}

fz_rect *
pdf_bound_annot(fz_context *ctx, pdf_annot *annot, fz_rect *rect)
{
	pdf_obj *obj = pdf_dict_get(ctx, annot->obj, PDF_NAME_Rect);
	fz_rect mediabox;
	fz_matrix page_ctm;
	pdf_to_rect(ctx, obj, rect);
	pdf_page_transform(ctx, annot->page, &mediabox, &page_ctm);
	fz_transform_rect(rect, &page_ctm);
	return rect;
}
