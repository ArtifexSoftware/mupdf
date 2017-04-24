#include "mupdf/fitz.h"
#include "mupdf/pdf.h"

#include <stdlib.h>
#include <string.h>
#include <limits.h>

int
pdf_count_pages(fz_context *ctx, pdf_document *doc)
{
	if (doc->page_count == 0)
		doc->page_count = pdf_to_int(ctx, pdf_dict_getp(ctx, pdf_trailer(ctx, doc), "Root/Pages/Count"));
	return doc->page_count;
}

static int
pdf_load_page_tree_imp(fz_context *ctx, pdf_document *doc, pdf_obj *node, int idx)
{
	pdf_obj *type = pdf_dict_get(ctx, node, PDF_NAME_Type);
	if (pdf_name_eq(ctx, type, PDF_NAME_Pages))
	{
		pdf_obj *kids = pdf_dict_get(ctx, node, PDF_NAME_Kids);
		int count = pdf_to_int(ctx, pdf_dict_get(ctx, node, PDF_NAME_Count));
		int i, n = pdf_array_len(ctx, kids);

		/* if Kids length is same as Count, all children must be page objects */
		if (n == count)
		{
			for (i = 0; i < n; ++i)
			{
				if (idx >= doc->page_count)
					fz_throw(ctx, FZ_ERROR_GENERIC, "too many kids in page tree");
				doc->rev_page_map[idx].page = idx;
				doc->rev_page_map[idx].object = pdf_to_num(ctx, pdf_array_get(ctx, kids, i));
				++idx;
			}
		}

		/* else Kids may contain intermediate nodes */
		else
		{
			if (pdf_mark_obj(ctx, node))
				fz_throw(ctx, FZ_ERROR_GENERIC, "cycle in page tree");
			fz_try(ctx)
				for (i = 0; i < n; ++i)
					idx = pdf_load_page_tree_imp(ctx, doc, pdf_array_get(ctx, kids, i), idx);
			fz_always(ctx)
				pdf_unmark_obj(ctx, node);
			fz_catch(ctx)
				fz_rethrow(ctx);
		}
	}
	else if (pdf_name_eq(ctx, type, PDF_NAME_Page))
	{
		if (idx >= doc->page_count)
			fz_throw(ctx, FZ_ERROR_GENERIC, "too many kids in page tree");
		doc->rev_page_map[idx].page = idx;
		doc->rev_page_map[idx].object = pdf_to_num(ctx, node);
		++idx;
	}
	else
	{
		fz_throw(ctx, FZ_ERROR_GENERIC, "non-page object in page tree");
	}
	return idx;
}

static int
cmp_rev_page_map(const void *va, const void *vb)
{
	const pdf_rev_page_map *a = va;
	const pdf_rev_page_map *b = vb;
	return a->object - b->object;
}

void
pdf_load_page_tree(fz_context *ctx, pdf_document *doc)
{
	if (!doc->rev_page_map)
	{
		int n = pdf_count_pages(ctx, doc);
		doc->rev_page_map = fz_malloc_array(ctx, n, sizeof *doc->rev_page_map);
		pdf_load_page_tree_imp(ctx, doc, pdf_dict_getp(ctx, pdf_trailer(ctx, doc), "Root/Pages"), 0);
		qsort(doc->rev_page_map, n, sizeof *doc->rev_page_map, cmp_rev_page_map);
	}
}

void
pdf_drop_page_tree(fz_context *ctx, pdf_document *doc)
{
	fz_free(ctx, doc->rev_page_map);
	doc->rev_page_map = NULL;
}

enum
{
	LOCAL_STACK_SIZE = 16
};

static pdf_obj *
pdf_lookup_page_loc_imp(fz_context *ctx, pdf_document *doc, pdf_obj *node, int *skip, pdf_obj **parentp, int *indexp)
{
	pdf_obj *kids;
	pdf_obj *hit = NULL;
	int i, len;
	pdf_obj *local_stack[LOCAL_STACK_SIZE];
	pdf_obj **stack = &local_stack[0];
	int stack_max = LOCAL_STACK_SIZE;
	int stack_len = 0;

	fz_var(hit);
	fz_var(stack);
	fz_var(stack_len);
	fz_var(stack_max);

	fz_try(ctx)
	{
		do
		{
			kids = pdf_dict_get(ctx, node, PDF_NAME_Kids);
			len = pdf_array_len(ctx, kids);

			if (len == 0)
				fz_throw(ctx, FZ_ERROR_GENERIC, "malformed page tree");

			/* Every node we need to unmark goes into the stack */
			if (stack_len == stack_max)
			{
				if (stack == &local_stack[0])
				{
					stack = fz_malloc_array(ctx, stack_max * 2, sizeof(*stack));
					memcpy(stack, &local_stack[0], stack_max * sizeof(*stack));
				}
				else
					stack = fz_resize_array(ctx, stack, stack_max * 2, sizeof(*stack));
				stack_max *= 2;
			}
			stack[stack_len++] = node;

			if (pdf_mark_obj(ctx, node))
				fz_throw(ctx, FZ_ERROR_GENERIC, "cycle in page tree");

			for (i = 0; i < len; i++)
			{
				pdf_obj *kid = pdf_array_get(ctx, kids, i);
				pdf_obj *type = pdf_dict_get(ctx, kid, PDF_NAME_Type);
				if (type ? pdf_name_eq(ctx, type, PDF_NAME_Pages) : pdf_dict_get(ctx, kid, PDF_NAME_Kids) && !pdf_dict_get(ctx, kid, PDF_NAME_MediaBox))
				{
					int count = pdf_to_int(ctx, pdf_dict_get(ctx, kid, PDF_NAME_Count));
					if (*skip < count)
					{
						node = kid;
						break;
					}
					else
					{
						*skip -= count;
					}
				}
				else
				{
					if (type ? !pdf_name_eq(ctx, type, PDF_NAME_Page) : !pdf_dict_get(ctx, kid, PDF_NAME_MediaBox))
						fz_warn(ctx, "non-page object in page tree (%s)", pdf_to_name(ctx, type));
					if (*skip == 0)
					{
						if (parentp) *parentp = node;
						if (indexp) *indexp = i;
						hit = kid;
						break;
					}
					else
					{
						(*skip)--;
					}
				}
			}
		}
		while (hit == NULL);
	}
	fz_always(ctx)
	{
		for (i = stack_len; i > 0; i--)
			pdf_unmark_obj(ctx, stack[i-1]);
		if (stack != &local_stack[0])
			fz_free(ctx, stack);
	}
	fz_catch(ctx)
	{
		fz_rethrow(ctx);
	}

	return hit;
}

pdf_obj *
pdf_lookup_page_loc(fz_context *ctx, pdf_document *doc, int needle, pdf_obj **parentp, int *indexp)
{
	pdf_obj *root = pdf_dict_get(ctx, pdf_trailer(ctx, doc), PDF_NAME_Root);
	pdf_obj *node = pdf_dict_get(ctx, root, PDF_NAME_Pages);
	int skip = needle;
	pdf_obj *hit;

	if (!node)
		fz_throw(ctx, FZ_ERROR_GENERIC, "cannot find page tree");

	hit = pdf_lookup_page_loc_imp(ctx, doc, node, &skip, parentp, indexp);
	if (!hit)
		fz_throw(ctx, FZ_ERROR_GENERIC, "cannot find page %d in page tree", needle);
	return hit;
}

pdf_obj *
pdf_lookup_page_obj(fz_context *ctx, pdf_document *doc, int needle)
{
	return pdf_lookup_page_loc(ctx, doc, needle, NULL, NULL);
}

static int
pdf_count_pages_before_kid(fz_context *ctx, pdf_document *doc, pdf_obj *parent, int kid_num)
{
	pdf_obj *kids = pdf_dict_get(ctx, parent, PDF_NAME_Kids);
	int i, total = 0, len = pdf_array_len(ctx, kids);
	for (i = 0; i < len; i++)
	{
		pdf_obj *kid = pdf_array_get(ctx, kids, i);
		if (pdf_to_num(ctx, kid) == kid_num)
			return total;
		if (pdf_name_eq(ctx, pdf_dict_get(ctx, kid, PDF_NAME_Type), PDF_NAME_Pages))
		{
			pdf_obj *count = pdf_dict_get(ctx, kid, PDF_NAME_Count);
			int n = pdf_to_int(ctx, count);
			if (!pdf_is_int(ctx, count) || n < 0)
				fz_throw(ctx, FZ_ERROR_GENERIC, "illegal or missing count in pages tree");
			total += n;
		}
		else
			total++;
	}
	fz_throw(ctx, FZ_ERROR_GENERIC, "kid not found in parent's kids array");
}

static int
pdf_lookup_page_number_slow(fz_context *ctx, pdf_document *doc, pdf_obj *node)
{
	int needle = pdf_to_num(ctx, node);
	int total = 0;
	pdf_obj *parent, *parent2;

	if (!pdf_name_eq(ctx, pdf_dict_get(ctx, node, PDF_NAME_Type), PDF_NAME_Page))
		fz_throw(ctx, FZ_ERROR_GENERIC, "invalid page object");

	parent2 = parent = pdf_dict_get(ctx, node, PDF_NAME_Parent);
	fz_var(parent);
	fz_try(ctx)
	{
		while (pdf_is_dict(ctx, parent))
		{
			if (pdf_mark_obj(ctx, parent))
				fz_throw(ctx, FZ_ERROR_GENERIC, "cycle in page tree (parents)");
			total += pdf_count_pages_before_kid(ctx, doc, parent, needle);
			needle = pdf_to_num(ctx, parent);
			parent = pdf_dict_get(ctx, parent, PDF_NAME_Parent);
		}
	}
	fz_always(ctx)
	{
		/* Run back and unmark */
		while (parent2)
		{
			pdf_unmark_obj(ctx, parent2);
			if (parent2 == parent)
				break;
			parent2 = pdf_dict_get(ctx, parent2, PDF_NAME_Parent);
		}
	}
	fz_catch(ctx)
	{
		fz_rethrow(ctx);
	}

	return total;
}

static int
pdf_lookup_page_number_fast(fz_context *ctx, pdf_document *doc, int needle)
{
	int l = 0;
	int r = doc->page_count - 1;
	while (l <= r)
	{
		int m = (l + r) >> 1;
		int c = needle - doc->rev_page_map[m].object;
		if (c < 0)
			r = m - 1;
		else if (c > 0)
			l = m + 1;
		else
			return doc->rev_page_map[m].page;
	}
	return -1;
}

int
pdf_lookup_page_number(fz_context *ctx, pdf_document *doc, pdf_obj *page)
{
	if (doc->rev_page_map)
		return pdf_lookup_page_number_fast(ctx, doc, pdf_to_num(ctx, page));
	else
		return pdf_lookup_page_number_slow(ctx, doc, page);
}

int
pdf_lookup_anchor(fz_context *ctx, pdf_document *doc, const char *name, float *xp, float *yp)
{
	pdf_obj *needle, *dest;
	char *uri;

	if (xp) *xp = 0;
	if (yp) *yp = 0;

	needle = pdf_new_string(ctx, doc, name, strlen(name));
	fz_try(ctx)
		dest = pdf_lookup_dest(ctx, doc, needle);
	fz_always(ctx)
		pdf_drop_obj(ctx, needle);
	fz_catch(ctx)
		fz_rethrow(ctx);

	if (dest)
	{
		uri = pdf_parse_link_dest(ctx, doc, dest);
		return pdf_resolve_link(ctx, doc, uri, xp, yp);
	}

	if (!strncmp(name, "page=", 5))
		return fz_atoi(name + 5) - 1;

	return fz_atoi(name) - 1;
}

static pdf_obj *
pdf_lookup_inherited_page_item(fz_context *ctx, pdf_obj *node, pdf_obj *key)
{
	pdf_obj *node2 = node;
	pdf_obj *val;

	/* fz_var(node); Not required as node passed in */

	fz_try(ctx)
	{
		do
		{
			val = pdf_dict_get(ctx, node, key);
			if (val)
				break;
			if (pdf_mark_obj(ctx, node))
				fz_throw(ctx, FZ_ERROR_GENERIC, "cycle in page tree (parents)");
			node = pdf_dict_get(ctx, node, PDF_NAME_Parent);
		}
		while (node);
	}
	fz_always(ctx)
	{
		do
		{
			pdf_unmark_obj(ctx, node2);
			if (node2 == node)
				break;
			node2 = pdf_dict_get(ctx, node2, PDF_NAME_Parent);
		}
		while (node2);
	}
	fz_catch(ctx)
	{
		fz_rethrow(ctx);
	}

	return val;
}

static void
pdf_flatten_inheritable_page_item(fz_context *ctx, pdf_obj *page, pdf_obj *key)
{
	pdf_obj *val = pdf_lookup_inherited_page_item(ctx, page, key);
	if (val)
		pdf_dict_put(ctx, page, key, val);
}

void
pdf_flatten_inheritable_page_items(fz_context *ctx, pdf_obj *page)
{
	pdf_flatten_inheritable_page_item(ctx, page, PDF_NAME_MediaBox);
	pdf_flatten_inheritable_page_item(ctx, page, PDF_NAME_CropBox);
	pdf_flatten_inheritable_page_item(ctx, page, PDF_NAME_Rotate);
	pdf_flatten_inheritable_page_item(ctx, page, PDF_NAME_Resources);
}

/* We need to know whether to install a page-level transparency group */

static int pdf_resources_use_blending(fz_context *ctx, pdf_obj *rdb);

static int
pdf_extgstate_uses_blending(fz_context *ctx, pdf_obj *dict)
{
	pdf_obj *obj = pdf_dict_get(ctx, dict, PDF_NAME_BM);
	if (obj && !pdf_name_eq(ctx, obj, PDF_NAME_Normal))
		return 1;
	return 0;
}

static int
pdf_pattern_uses_blending(fz_context *ctx, pdf_obj *dict)
{
	pdf_obj *obj;
	obj = pdf_dict_get(ctx, dict, PDF_NAME_Resources);
	if (pdf_resources_use_blending(ctx, obj))
		return 1;
	obj = pdf_dict_get(ctx, dict, PDF_NAME_ExtGState);
	return pdf_extgstate_uses_blending(ctx, obj);
}

static int
pdf_xobject_uses_blending(fz_context *ctx, pdf_obj *dict)
{
	pdf_obj *obj = pdf_dict_get(ctx, dict, PDF_NAME_Resources);
	if (pdf_name_eq(ctx, pdf_dict_getp(ctx, dict, "Group/S"), PDF_NAME_Transparency))
		return 1;
	return pdf_resources_use_blending(ctx, obj);
}

static int
pdf_resources_use_blending(fz_context *ctx, pdf_obj *rdb)
{
	pdf_obj *obj;
	int i, n, useBM = 0;

	if (!rdb)
		return 0;

	/* Have we been here before and remembered an answer? */
	if (pdf_obj_memo(ctx, rdb, &useBM))
		return useBM;

	/* stop on cyclic resource dependencies */
	if (pdf_mark_obj(ctx, rdb))
		return 0;

	fz_try(ctx)
	{
		obj = pdf_dict_get(ctx, rdb, PDF_NAME_ExtGState);
		n = pdf_dict_len(ctx, obj);
		for (i = 0; i < n; i++)
			if (pdf_extgstate_uses_blending(ctx, pdf_dict_get_val(ctx, obj, i)))
				goto found;

		obj = pdf_dict_get(ctx, rdb, PDF_NAME_Pattern);
		n = pdf_dict_len(ctx, obj);
		for (i = 0; i < n; i++)
			if (pdf_pattern_uses_blending(ctx, pdf_dict_get_val(ctx, obj, i)))
				goto found;

		obj = pdf_dict_get(ctx, rdb, PDF_NAME_XObject);
		n = pdf_dict_len(ctx, obj);
		for (i = 0; i < n; i++)
			if (pdf_xobject_uses_blending(ctx, pdf_dict_get_val(ctx, obj, i)))
				goto found;
		if (0)
		{
found:
			useBM = 1;
		}
	}
	fz_always(ctx)
	{
		pdf_unmark_obj(ctx, rdb);
	}
	fz_catch(ctx)
	{
		fz_rethrow(ctx);
	}

	pdf_set_obj_memo(ctx, rdb, useBM);
	return useBM;
}

fz_transition *
pdf_page_presentation(fz_context *ctx, pdf_page *page, fz_transition *transition, float *duration)
{
	pdf_obj *obj, *transdict;

	*duration = pdf_to_real(ctx, pdf_dict_get(ctx, page->obj, PDF_NAME_Dur));

	transdict = pdf_dict_get(ctx, page->obj, PDF_NAME_Trans);
	if (!transdict)
		return NULL;

	obj = pdf_dict_get(ctx, transdict, PDF_NAME_D);

	transition->duration = (obj ? pdf_to_real(ctx, obj) : 1);

	transition->vertical = !pdf_name_eq(ctx, pdf_dict_get(ctx, transdict, PDF_NAME_Dm), PDF_NAME_H);
	transition->outwards = !pdf_name_eq(ctx, pdf_dict_get(ctx, transdict, PDF_NAME_M), PDF_NAME_I);
	/* FIXME: If 'Di' is None, it should be handled differently, but
	 * this only affects Fly, and we don't implement that currently. */
	transition->direction = (pdf_to_int(ctx, pdf_dict_get(ctx, transdict, PDF_NAME_Di)));
	/* FIXME: Read SS for Fly when we implement it */
	/* FIXME: Read B for Fly when we implement it */

	obj = pdf_dict_get(ctx, transdict, PDF_NAME_S);
	if (pdf_name_eq(ctx, obj, PDF_NAME_Split))
		transition->type = FZ_TRANSITION_SPLIT;
	else if (pdf_name_eq(ctx, obj, PDF_NAME_Blinds))
		transition->type = FZ_TRANSITION_BLINDS;
	else if (pdf_name_eq(ctx, obj, PDF_NAME_Box))
		transition->type = FZ_TRANSITION_BOX;
	else if (pdf_name_eq(ctx, obj, PDF_NAME_Wipe))
		transition->type = FZ_TRANSITION_WIPE;
	else if (pdf_name_eq(ctx, obj, PDF_NAME_Dissolve))
		transition->type = FZ_TRANSITION_DISSOLVE;
	else if (pdf_name_eq(ctx, obj, PDF_NAME_Glitter))
		transition->type = FZ_TRANSITION_GLITTER;
	else if (pdf_name_eq(ctx, obj, PDF_NAME_Fly))
		transition->type = FZ_TRANSITION_FLY;
	else if (pdf_name_eq(ctx, obj, PDF_NAME_Push))
		transition->type = FZ_TRANSITION_PUSH;
	else if (pdf_name_eq(ctx, obj, PDF_NAME_Cover))
		transition->type = FZ_TRANSITION_COVER;
	else if (pdf_name_eq(ctx, obj, PDF_NAME_Uncover))
		transition->type = FZ_TRANSITION_UNCOVER;
	else if (pdf_name_eq(ctx, obj, PDF_NAME_Fade))
		transition->type = FZ_TRANSITION_FADE;
	else
		transition->type = FZ_TRANSITION_NONE;

	return transition;
}

fz_rect *
pdf_bound_page(fz_context *ctx, pdf_page *page, fz_rect *mediabox)
{
	fz_matrix page_ctm;
	pdf_page_transform(ctx, page, mediabox, &page_ctm);
	fz_transform_rect(mediabox, &page_ctm);
	return mediabox;
}

fz_link *
pdf_load_links(fz_context *ctx, pdf_page *page)
{
	return fz_keep_link(ctx, page->links);
}

pdf_obj *
pdf_page_resources(fz_context *ctx, pdf_page *page)
{
	return pdf_lookup_inherited_page_item(ctx, page->obj, PDF_NAME_Resources);
}

pdf_obj *
pdf_page_contents(fz_context *ctx, pdf_page *page)
{
	return pdf_dict_get(ctx, page->obj, PDF_NAME_Contents);
}

void
pdf_page_obj_transform(fz_context *ctx, pdf_obj *pageobj, fz_rect *page_mediabox, fz_matrix *page_ctm)
{
	pdf_obj *obj;
	fz_rect mediabox, cropbox, realbox, pagebox;
	fz_matrix tmp;
	float userunit = 1;
	int rotate;

	if (!page_mediabox)
		page_mediabox = &pagebox;

	obj = pdf_dict_get(ctx, pageobj, PDF_NAME_UserUnit);
	if (pdf_is_real(ctx, obj))
		userunit = pdf_to_real(ctx, obj);

	pdf_to_rect(ctx, pdf_lookup_inherited_page_item(ctx, pageobj, PDF_NAME_MediaBox), &mediabox);
	if (fz_is_empty_rect(&mediabox))
	{
		mediabox.x0 = 0;
		mediabox.y0 = 0;
		mediabox.x1 = 612;
		mediabox.y1 = 792;
	}

	pdf_to_rect(ctx, pdf_lookup_inherited_page_item(ctx, pageobj, PDF_NAME_CropBox), &cropbox);
	if (!fz_is_empty_rect(&cropbox))
		fz_intersect_rect(&mediabox, &cropbox);

	page_mediabox->x0 = fz_min(mediabox.x0, mediabox.x1);
	page_mediabox->y0 = fz_min(mediabox.y0, mediabox.y1);
	page_mediabox->x1 = fz_max(mediabox.x0, mediabox.x1);
	page_mediabox->y1 = fz_max(mediabox.y0, mediabox.y1);

	if (page_mediabox->x1 - page_mediabox->x0 < 1 || page_mediabox->y1 - page_mediabox->y0 < 1)
		*page_mediabox = fz_unit_rect;

	rotate = pdf_to_int(ctx, pdf_lookup_inherited_page_item(ctx, pageobj, PDF_NAME_Rotate));

	/* Snap page rotation to 0, 90, 180 or 270 */
	if (rotate < 0)
		rotate = 360 - ((-rotate) % 360);
	if (rotate >= 360)
		rotate = rotate % 360;
	rotate = 90*((rotate + 45)/90);
	if (rotate >= 360)
		rotate = 0;

	/* Compute transform from fitz' page space (upper left page origin, y descending, 72 dpi)
	 * to PDF user space (arbitrary page origin, y ascending, UserUnit dpi). */

	/* Make left-handed and scale by UserUnit */
	fz_scale(page_ctm, userunit, -userunit);

	/* Rotate */
	fz_pre_rotate(page_ctm, -rotate);

	/* Translate page origin to 0,0 */
	realbox = *page_mediabox;
	fz_transform_rect(&realbox, page_ctm);
	fz_translate(&tmp, -realbox.x0, -realbox.y0);
	fz_concat(page_ctm, page_ctm, &tmp);
}

void
pdf_page_transform(fz_context *ctx, pdf_page *page, fz_rect *page_mediabox, fz_matrix *page_ctm)
{
	pdf_page_obj_transform(ctx, page->obj, page_mediabox, page_ctm);
}

static void
pdf_drop_page_imp(fz_context *ctx, pdf_page *page)
{
	pdf_document *doc = page->doc;

	fz_drop_link(ctx, page->links);
	pdf_drop_annots(ctx, page->annots);

	/* doc->focus, when not NULL, refers to one of
	 * the annotations and must be NULLed when the
	 * annotations are destroyed. doc->focus_obj
	 * keeps track of the actual annotation object. */
	doc->focus = NULL;

	pdf_drop_obj(ctx, page->obj);

	fz_drop_document(ctx, &page->doc->super);
}

static pdf_page *
pdf_new_page(fz_context *ctx, pdf_document *doc)
{
	pdf_page *page = fz_new_derived_page(ctx, pdf_page);

	page->doc = (pdf_document*) fz_keep_document(ctx, &doc->super);

	page->super.drop_page = (fz_page_drop_page_fn*)pdf_drop_page_imp;
	page->super.load_links = (fz_page_load_links_fn*)pdf_load_links;
	page->super.bound_page = (fz_page_bound_page_fn*)pdf_bound_page;
	page->super.first_annot = (fz_page_first_annot_fn*)pdf_first_annot;
	page->super.run_page_contents = (fz_page_run_page_contents_fn*)pdf_run_page_contents;
	page->super.page_presentation = (fz_page_page_presentation_fn*)pdf_page_presentation;

	page->obj = NULL;

	page->transparency = 0;
	page->links = NULL;
	page->annots = NULL;
	page->annot_tailp = &page->annots;
	page->incomplete = 0;

	return page;
}

pdf_page *
pdf_load_page(fz_context *ctx, pdf_document *doc, int number)
{
	pdf_page *page;
	pdf_annot *annot;
	pdf_obj *pageobj, *obj;

	if (doc->file_reading_linearly)
	{
		pageobj = pdf_progressive_advance(ctx, doc, number);
		if (pageobj == NULL)
			fz_throw(ctx, FZ_ERROR_TRYLATER, "page %d not available yet", number);
	}
	else
		pageobj = pdf_lookup_page_obj(ctx, doc, number);

	page = pdf_new_page(ctx, doc);
	page->obj = pdf_keep_obj(ctx, pageobj);

	/* Pre-load annotations and links */
	fz_try(ctx)
	{
		obj = pdf_dict_get(ctx, pageobj, PDF_NAME_Annots);
		if (obj)
		{
			fz_rect page_mediabox;
			fz_matrix page_ctm;
			pdf_page_transform(ctx, page, &page_mediabox, &page_ctm);
			page->links = pdf_load_link_annots(ctx, doc, obj, number, &page_ctm);
			pdf_load_annots(ctx, page, obj);
		}
	}
	fz_catch(ctx)
	{
		if (fz_caught(ctx) != FZ_ERROR_TRYLATER)
			fz_rethrow(ctx);
		page->incomplete |= PDF_PAGE_INCOMPLETE_ANNOTS;
		fz_drop_link(ctx, page->links);
		page->links = NULL;
	}

	/* Scan for transparency */
	fz_try(ctx)
	{
		pdf_obj *resources = pdf_page_resources(ctx, page);
		if (pdf_resources_use_blending(ctx, resources))
			page->transparency = 1;
		else if (pdf_name_eq(ctx, pdf_dict_getp(ctx, pageobj, "Group/S"), PDF_NAME_Transparency))
			page->transparency = 1;
		for (annot = page->annots; annot && !page->transparency; annot = annot->next)
			if (annot->ap && pdf_resources_use_blending(ctx, pdf_xobject_resources(ctx, annot->ap)))
				page->transparency = 1;
	}
	fz_catch(ctx)
	{
		if (fz_caught(ctx) != FZ_ERROR_TRYLATER)
		{
			fz_drop_page(ctx, &page->super);
			fz_rethrow(ctx);
		}
		page->incomplete |= PDF_PAGE_INCOMPLETE_CONTENTS;
	}

	return page;
}

void
pdf_delete_page(fz_context *ctx, pdf_document *doc, int at)
{
	pdf_obj *parent, *kids;
	int i;

	pdf_lookup_page_loc(ctx, doc, at, &parent, &i);
	kids = pdf_dict_get(ctx, parent, PDF_NAME_Kids);
	pdf_array_delete(ctx, kids, i);

	while (parent)
	{
		int count = pdf_to_int(ctx, pdf_dict_get(ctx, parent, PDF_NAME_Count));
		pdf_dict_put_drop(ctx, parent, PDF_NAME_Count, pdf_new_int(ctx, doc, count - 1));
		parent = pdf_dict_get(ctx, parent, PDF_NAME_Parent);
	}

	doc->page_count = 0; /* invalidate cached value */
}

void
pdf_delete_page_range(fz_context *ctx, pdf_document *doc, int start, int end)
{
	int count = pdf_count_pages(ctx, doc);

	if (end < 0 || end > count)
		end = count+1;
	if (start < 0)
		start = 0;
	while (start < end)
	{
		pdf_delete_page(ctx, doc, start);
		end--;
	}
}

pdf_obj *
pdf_add_page(fz_context *ctx, pdf_document *doc, const fz_rect *mediabox, int rotate, pdf_obj *resources, fz_buffer *contents)
{
	pdf_obj *page_obj = pdf_new_dict(ctx, doc, 5);
	fz_try(ctx)
	{
		pdf_dict_put_drop(ctx, page_obj, PDF_NAME_Type, PDF_NAME_Page);
		pdf_dict_put_drop(ctx, page_obj, PDF_NAME_MediaBox, pdf_new_rect(ctx, doc, mediabox));
		pdf_dict_put_drop(ctx, page_obj, PDF_NAME_Rotate, pdf_new_int(ctx, doc, rotate));

		if (pdf_is_indirect(ctx, resources))
			pdf_dict_put_drop(ctx, page_obj, PDF_NAME_Resources, resources);
		else if (pdf_is_dict(ctx, resources))
			pdf_dict_put_drop(ctx, page_obj, PDF_NAME_Resources, pdf_add_object(ctx, doc, resources));
		else
			pdf_dict_put_drop(ctx, page_obj, PDF_NAME_Resources, pdf_new_dict(ctx, doc, 1));

		if (contents)
			pdf_dict_put_drop(ctx, page_obj, PDF_NAME_Contents, pdf_add_stream(ctx, doc, contents, NULL, 0));
	}
	fz_catch(ctx)
	{
		pdf_drop_obj(ctx, page_obj);
		fz_rethrow(ctx);
	}
	return pdf_add_object_drop(ctx, doc, page_obj);
}

void
pdf_insert_page(fz_context *ctx, pdf_document *doc, int at, pdf_obj *page_ref)
{
	int count = pdf_count_pages(ctx, doc);
	pdf_obj *parent, *kids;
	int i;

	if (at < 0)
		at = count;
	if (at == INT_MAX)
		at = count;
	if (at > count)
		fz_throw(ctx, FZ_ERROR_GENERIC, "cannot insert page beyond end of page tree");

	if (count == 0)
	{
		pdf_obj *root = pdf_dict_get(ctx, pdf_trailer(ctx, doc), PDF_NAME_Root);
		parent = pdf_dict_get(ctx, root, PDF_NAME_Pages);
		if (!parent)
			fz_throw(ctx, FZ_ERROR_GENERIC, "cannot find page tree");
		kids = pdf_dict_get(ctx, parent, PDF_NAME_Kids);
		if (!kids)
			fz_throw(ctx, FZ_ERROR_GENERIC, "malformed page tree");
		pdf_array_insert(ctx, kids, page_ref, 0);
	}
	else if (at == count)
	{
		/* append after last page */
		pdf_lookup_page_loc(ctx, doc, count - 1, &parent, &i);
		kids = pdf_dict_get(ctx, parent, PDF_NAME_Kids);
		pdf_array_insert(ctx, kids, page_ref, i + 1);
	}
	else
	{
		/* insert before found page */
		pdf_lookup_page_loc(ctx, doc, at, &parent, &i);
		kids = pdf_dict_get(ctx, parent, PDF_NAME_Kids);
		pdf_array_insert(ctx, kids, page_ref, i);
	}

	pdf_dict_put(ctx, page_ref, PDF_NAME_Parent, parent);

	/* Adjust page counts */
	while (parent)
	{
		int count = pdf_to_int(ctx, pdf_dict_get(ctx, parent, PDF_NAME_Count));
		pdf_dict_put_drop(ctx, parent, PDF_NAME_Count, pdf_new_int(ctx, doc, count + 1));
		parent = pdf_dict_get(ctx, parent, PDF_NAME_Parent);
	}

	doc->page_count = 0; /* invalidate cached value */
}
