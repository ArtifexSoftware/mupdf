#include "mupdf/pdf.h"

int
pdf_count_pages(fz_context *ctx, pdf_document *doc)
{
	if (doc->page_count == 0)
	{
		pdf_obj *count = pdf_dict_getp(ctx, pdf_trailer(ctx, doc), "Root/Pages/Count");
		doc->page_count = pdf_to_int(ctx, count);
	}
	return doc->page_count;
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
				fz_throw(ctx, FZ_ERROR_GENERIC, "Malformed pages tree");

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
					if (type ? !pdf_name_eq(ctx, type, PDF_NAME_Page) != 0 : !pdf_dict_get(ctx, kid, PDF_NAME_MediaBox))
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

int
pdf_lookup_page_number(fz_context *ctx, pdf_document *doc, pdf_obj *node)
{
	int needle = pdf_to_num(ctx, node);
	int total = 0;
	pdf_obj *parent, *parent2;

	if (!pdf_name_eq(ctx, pdf_dict_get(ctx, node, PDF_NAME_Type), PDF_NAME_Page) != 0)
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

static pdf_obj *
pdf_lookup_inherited_page_item(fz_context *ctx, pdf_document *doc, pdf_obj *node, pdf_obj *key)
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

/* We need to know whether to install a page-level transparency group */

static int pdf_resources_use_blending(fz_context *ctx, pdf_document *doc, pdf_obj *rdb);

static int
pdf_extgstate_uses_blending(fz_context *ctx, pdf_document *doc, pdf_obj *dict)
{
	pdf_obj *obj = pdf_dict_get(ctx, dict, PDF_NAME_BM);
	if (obj && !pdf_name_eq(ctx, obj, PDF_NAME_Normal))
		return 1;
	return 0;
}

static int
pdf_pattern_uses_blending(fz_context *ctx, pdf_document *doc, pdf_obj *dict)
{
	pdf_obj *obj;
	obj = pdf_dict_get(ctx, dict, PDF_NAME_Resources);
	if (pdf_resources_use_blending(ctx, doc, obj))
		return 1;
	obj = pdf_dict_get(ctx, dict, PDF_NAME_ExtGState);
	return pdf_extgstate_uses_blending(ctx, doc, obj);
}

static int
pdf_xobject_uses_blending(fz_context *ctx, pdf_document *doc, pdf_obj *dict)
{
	pdf_obj *obj = pdf_dict_get(ctx, dict, PDF_NAME_Resources);
	if (pdf_name_eq(ctx, pdf_dict_getp(ctx, dict, "Group/S"), PDF_NAME_Transparency))
		return 1;
	return pdf_resources_use_blending(ctx, doc, obj);
}

static int
pdf_resources_use_blending(fz_context *ctx, pdf_document *doc, pdf_obj *rdb)
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
			if (pdf_extgstate_uses_blending(ctx, doc, pdf_dict_get_val(ctx, obj, i)))
				goto found;

		obj = pdf_dict_get(ctx, rdb, PDF_NAME_Pattern);
		n = pdf_dict_len(ctx, obj);
		for (i = 0; i < n; i++)
			if (pdf_pattern_uses_blending(ctx, doc, pdf_dict_get_val(ctx, obj, i)))
				goto found;

		obj = pdf_dict_get(ctx, rdb, PDF_NAME_XObject);
		n = pdf_dict_len(ctx, obj);
		for (i = 0; i < n; i++)
			if (pdf_xobject_uses_blending(ctx, doc, pdf_dict_get_val(ctx, obj, i)))
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

static void
pdf_load_transition(fz_context *ctx, pdf_document *doc, pdf_page *page, pdf_obj *transdict)
{
	pdf_obj *name;
	pdf_obj *obj;
	int type;

	obj = pdf_dict_get(ctx, transdict, PDF_NAME_D);
	page->transition.duration = (obj ? pdf_to_real(ctx, obj) : 1);

	page->transition.vertical = !pdf_name_eq(ctx, pdf_dict_get(ctx, transdict, PDF_NAME_Dm), PDF_NAME_H);
	page->transition.outwards = !pdf_name_eq(ctx, pdf_dict_get(ctx, transdict, PDF_NAME_M), PDF_NAME_I);
	/* FIXME: If 'Di' is None, it should be handled differently, but
	 * this only affects Fly, and we don't implement that currently. */
	page->transition.direction = (pdf_to_int(ctx, pdf_dict_get(ctx, transdict, PDF_NAME_Di)));
	/* FIXME: Read SS for Fly when we implement it */
	/* FIXME: Read B for Fly when we implement it */

	name = pdf_dict_get(ctx, transdict, PDF_NAME_S);
	if (pdf_name_eq(ctx, name, PDF_NAME_Split))
		type = FZ_TRANSITION_SPLIT;
	else if (pdf_name_eq(ctx, name, PDF_NAME_Blinds))
		type = FZ_TRANSITION_BLINDS;
	else if (pdf_name_eq(ctx, name, PDF_NAME_Box))
		type = FZ_TRANSITION_BOX;
	else if (pdf_name_eq(ctx, name, PDF_NAME_Wipe))
		type = FZ_TRANSITION_WIPE;
	else if (pdf_name_eq(ctx, name, PDF_NAME_Dissolve))
		type = FZ_TRANSITION_DISSOLVE;
	else if (pdf_name_eq(ctx, name, PDF_NAME_Glitter))
		type = FZ_TRANSITION_GLITTER;
	else if (pdf_name_eq(ctx, name, PDF_NAME_Fly))
		type = FZ_TRANSITION_FLY;
	else if (pdf_name_eq(ctx, name, PDF_NAME_Push))
		type = FZ_TRANSITION_PUSH;
	else if (pdf_name_eq(ctx, name, PDF_NAME_Cover))
		type = FZ_TRANSITION_COVER;
	else if (pdf_name_eq(ctx, name, PDF_NAME_Uncover))
		type = FZ_TRANSITION_UNCOVER;
	else if (pdf_name_eq(ctx, name, PDF_NAME_Fade))
		type = FZ_TRANSITION_FADE;
	else
		type = FZ_TRANSITION_NONE;
	page->transition.type = type;
}

fz_rect *
pdf_bound_page(fz_context *ctx, pdf_page *page, fz_rect *bounds)
{
	fz_matrix mtx;
	fz_rect mediabox = page->mediabox;
	fz_transform_rect(&mediabox, fz_rotate(&mtx, page->rotate));
	bounds->x0 = bounds->y0 = 0;
	bounds->x1 = mediabox.x1 - mediabox.x0;
	bounds->y1 = mediabox.y1 - mediabox.y0;
	return bounds;
}

fz_link *
pdf_load_links(fz_context *ctx, pdf_page *page)
{
	return fz_keep_link(ctx, page->links);
}

static void
pdf_drop_page_imp(fz_context *ctx, pdf_page *page)
{
	pdf_document *doc = page->doc;

	if (page == NULL)
		return;

	pdf_drop_obj(ctx, page->resources);
	pdf_drop_obj(ctx, page->contents);
	if (page->links)
		fz_drop_link(ctx, page->links);
	if (page->annots)
		pdf_drop_annot(ctx, page->annots);
	if (page->deleted_annots)
		pdf_drop_annot(ctx, page->deleted_annots);
	if (page->tmp_annots)
		pdf_drop_annot(ctx, page->tmp_annots);
	/* doc->focus, when not NULL, refers to one of
	 * the annotations and must be NULLed when the
	 * annotations are destroyed. doc->focus_obj
	 * keeps track of the actual annotation object. */
	doc->focus = NULL;
	pdf_drop_obj(ctx, page->me);

	fz_drop_document(ctx, &page->doc->super);
}

void pdf_drop_page(fz_context *ctx, pdf_page *page)
{
	fz_drop_page(ctx, &page->super);
}

static pdf_page *
pdf_new_page(fz_context *ctx, pdf_document *doc)
{
	pdf_page *page = fz_new_page(ctx, sizeof(*page));

	page->doc = (pdf_document*) fz_keep_document(ctx, &doc->super);

	page->super.drop_page_imp = (fz_page_drop_page_imp_fn *)pdf_drop_page_imp;
	page->super.load_links = (fz_page_load_links_fn *)pdf_load_links;
	page->super.bound_page = (fz_page_bound_page_fn *)pdf_bound_page;
	page->super.first_annot = (fz_page_first_annot_fn *)pdf_first_annot;
	page->super.next_annot = (fz_page_next_annot_fn *)pdf_next_annot;
	page->super.bound_annot = (fz_page_bound_annot_fn *)pdf_bound_annot;
	page->super.run_page_contents = (fz_page_run_page_contents_fn *)pdf_run_page_contents;
	page->super.run_annot = (fz_page_run_annot_fn *)pdf_run_annot;
	page->super.page_presentation = (fz_page_page_presentation_fn *)pdf_page_presentation;

	page->resources = NULL;
	page->contents = NULL;
	page->transparency = 0;
	page->links = NULL;
	page->annots = NULL;
	page->annot_tailp = &page->annots;
	page->deleted_annots = NULL;
	page->tmp_annots = NULL;
	page->incomplete = 0;
	page->me = NULL;

	return page;
}

pdf_page *
pdf_load_page(fz_context *ctx, pdf_document *doc, int number)
{
	pdf_page *page;
	pdf_annot *annot;
	pdf_obj *pageobj, *pageref, *obj;
	fz_rect mediabox, cropbox, realbox;
	float userunit;
	fz_matrix mat;

	if (doc->file_reading_linearly)
	{
		pageref = pdf_progressive_advance(ctx, doc, number);
		if (pageref == NULL)
			fz_throw(ctx, FZ_ERROR_TRYLATER, "page %d not available yet", number);
	}
	else
		pageref = pdf_lookup_page_obj(ctx, doc, number);
	pageobj = pdf_resolve_indirect(ctx, pageref);

	page = pdf_new_page(ctx, doc);
	page->me = pdf_keep_obj(ctx, pageobj);

	obj = pdf_dict_get(ctx, pageobj, PDF_NAME_UserUnit);
	if (pdf_is_real(ctx, obj))
		userunit = pdf_to_real(ctx, obj);
	else
		userunit = 1;

	pdf_to_rect(ctx, pdf_lookup_inherited_page_item(ctx, doc, pageobj, PDF_NAME_MediaBox), &mediabox);
	if (fz_is_empty_rect(&mediabox))
	{
		fz_warn(ctx, "cannot find page size for page %d", number + 1);
		mediabox.x0 = 0;
		mediabox.y0 = 0;
		mediabox.x1 = 612;
		mediabox.y1 = 792;
	}

	pdf_to_rect(ctx, pdf_lookup_inherited_page_item(ctx, doc, pageobj, PDF_NAME_CropBox), &cropbox);
	if (!fz_is_empty_rect(&cropbox))
		fz_intersect_rect(&mediabox, &cropbox);

	page->mediabox.x0 = fz_min(mediabox.x0, mediabox.x1) * userunit;
	page->mediabox.y0 = fz_min(mediabox.y0, mediabox.y1) * userunit;
	page->mediabox.x1 = fz_max(mediabox.x0, mediabox.x1) * userunit;
	page->mediabox.y1 = fz_max(mediabox.y0, mediabox.y1) * userunit;

	if (page->mediabox.x1 - page->mediabox.x0 < 1 || page->mediabox.y1 - page->mediabox.y0 < 1)
	{
		fz_warn(ctx, "invalid page size in page %d", number + 1);
		page->mediabox = fz_unit_rect;
	}

	page->rotate = pdf_to_int(ctx, pdf_lookup_inherited_page_item(ctx, doc, pageobj, PDF_NAME_Rotate));
	/* Snap page->rotate to 0, 90, 180 or 270 */
	if (page->rotate < 0)
		page->rotate = 360 - ((-page->rotate) % 360);
	if (page->rotate >= 360)
		page->rotate = page->rotate % 360;
	page->rotate = 90*((page->rotate + 45)/90);
	if (page->rotate > 360)
		page->rotate = 0;

	fz_pre_rotate(fz_scale(&page->ctm, 1, -1), -page->rotate);
	realbox = page->mediabox;
	fz_transform_rect(&realbox, &page->ctm);
	fz_pre_scale(fz_translate(&mat, -realbox.x0, -realbox.y0), userunit, userunit);
	fz_concat(&page->ctm, &page->ctm, &mat);

	fz_try(ctx)
	{
		obj = pdf_dict_get(ctx, pageobj, PDF_NAME_Annots);
		if (obj)
		{
			page->links = pdf_load_link_annots(ctx, doc, obj, &page->ctm);
			pdf_load_annots(ctx, doc, page, obj);
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

	page->duration = pdf_to_real(ctx, pdf_dict_get(ctx, pageobj, PDF_NAME_Dur));

	obj = pdf_dict_get(ctx, pageobj, PDF_NAME_Trans);
	page->transition_present = (obj != NULL);
	if (obj)
	{
		pdf_load_transition(ctx, doc, page, obj);
	}

	// TODO: inherit
	page->resources = pdf_lookup_inherited_page_item(ctx, doc, pageobj, PDF_NAME_Resources);
	if (page->resources)
		pdf_keep_obj(ctx, page->resources);

	obj = pdf_dict_get(ctx, pageobj, PDF_NAME_Contents);
	fz_try(ctx)
	{
		page->contents = pdf_keep_obj(ctx, obj);

		if (pdf_resources_use_blending(ctx, doc, page->resources))
			page->transparency = 1;
		else if (pdf_name_eq(ctx, pdf_dict_getp(ctx, pageobj, "Group/S"), PDF_NAME_Transparency))
			page->transparency = 1;

		for (annot = page->annots; annot && !page->transparency; annot = annot->next)
			if (annot->ap && pdf_resources_use_blending(ctx, doc, annot->ap->resources))
				page->transparency = 1;
	}
	fz_catch(ctx)
	{
		if (fz_caught(ctx) != FZ_ERROR_TRYLATER)
		{
			fz_drop_page(ctx, &page->super);
			fz_rethrow_message(ctx, "cannot load page %d contents (%d 0 R)", number + 1, pdf_to_num(ctx, pageref));
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
pdf_insert_page(fz_context *ctx, pdf_document *doc, pdf_page *page, int at)
{
	int count = pdf_count_pages(ctx, doc);
	pdf_obj *parent, *kids;
	pdf_obj *page_ref;
	int i;

	page_ref = pdf_new_ref(ctx, doc, page->me);

	fz_try(ctx)
	{
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
		else if (at >= count)
		{
			if (at == INT_MAX)
				at = count;

			if (at > count)
				fz_throw(ctx, FZ_ERROR_GENERIC, "cannot insert page beyond end of page tree");

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

		pdf_dict_put(ctx, page->me, PDF_NAME_Parent, parent);

		/* Adjust page counts */
		while (parent)
		{
			int count = pdf_to_int(ctx, pdf_dict_get(ctx, parent, PDF_NAME_Count));
			pdf_dict_put_drop(ctx, parent, PDF_NAME_Count, pdf_new_int(ctx, doc, count + 1));
			parent = pdf_dict_get(ctx, parent, PDF_NAME_Parent);
		}

	}
	fz_always(ctx)
	{
		pdf_drop_obj(ctx, page_ref);
	}
	fz_catch(ctx)
	{
		fz_rethrow(ctx);
	}

	doc->page_count = 0; /* invalidate cached value */
}

void
pdf_delete_page_range(fz_context *ctx, pdf_document *doc, int start, int end)
{
	while (start < end)
		pdf_delete_page(ctx, doc, start++);
}

pdf_page *
pdf_create_page(fz_context *ctx, pdf_document *doc, fz_rect mediabox, int res, int rotate)
{
	pdf_page *page = NULL;
	pdf_obj *pageobj;
	float userunit = 1;
	fz_matrix ctm, tmp;
	fz_rect realbox;

	page = pdf_new_page(ctx, doc);

	fz_try(ctx)
	{
		page->me = pageobj = pdf_new_dict(ctx, doc, 4);

		pdf_dict_put_drop(ctx, pageobj, PDF_NAME_Type, PDF_NAME_Page);

		page->mediabox.x0 = fz_min(mediabox.x0, mediabox.x1) * userunit;
		page->mediabox.y0 = fz_min(mediabox.y0, mediabox.y1) * userunit;
		page->mediabox.x1 = fz_max(mediabox.x0, mediabox.x1) * userunit;
		page->mediabox.y1 = fz_max(mediabox.y0, mediabox.y1) * userunit;
		pdf_dict_put_drop(ctx, pageobj, PDF_NAME_MediaBox, pdf_new_rect(ctx, doc, &page->mediabox));

		/* Snap page->rotate to 0, 90, 180 or 270 */
		if (page->rotate < 0)
			page->rotate = 360 - ((-page->rotate) % 360);
		if (page->rotate >= 360)
			page->rotate = page->rotate % 360;
		page->rotate = 90*((page->rotate + 45)/90);
		if (page->rotate > 360)
			page->rotate = 0;
		pdf_dict_put_drop(ctx, pageobj, PDF_NAME_Rotate, pdf_new_int(ctx, doc, page->rotate));

		fz_pre_rotate(fz_scale(&ctm, 1, -1), -page->rotate);
		realbox = page->mediabox;
		fz_transform_rect(&realbox, &ctm);
		fz_pre_scale(fz_translate(&tmp, -realbox.x0, -realbox.y0), userunit, userunit);
		fz_concat(&ctm, &ctm, &tmp);
		page->ctm = ctm;
		/* Do not create a Contents, as an empty Contents dict is not
		 * valid. See Bug 694712 */
	}
	fz_catch(ctx)
	{
		pdf_drop_obj(ctx, page->me);
		fz_free(ctx, page);
		fz_rethrow_message(ctx, "Failed to create page");
	}

	return page;
}
