#include "fitz.h"
#include "mupdf.h"

/* we need to combine all sub-streams into one for the content stream interpreter */

static fz_error
pdf_load_page_contents_array(fz_buffer **bigbufp, pdf_xref *xref, fz_obj *list)
{
	fz_error error;
	fz_buffer *big;
	fz_buffer *one;
	int i;

	pdf_log_page("multiple content streams: %d\n", fz_array_len(list));

	/* TODO: openstream, read, close into big buffer at once */

	big = fz_new_buffer(32 * 1024);

	for (i = 0; i < fz_array_len(list); i++)
	{
		fz_obj *stm = fz_array_get(list, i);
		error = pdf_load_stream(&one, xref, fz_to_num(stm), fz_to_gen(stm));
		if (error)
		{
			fz_drop_buffer(big);
			return fz_rethrow(error, "cannot load content stream part %d/%d (%d %d R)", i + 1, fz_array_len(list), fz_to_num(stm), fz_to_gen(stm));
		}

		if (big->len + one->len + 1 > big->cap)
			fz_resize_buffer(big, big->len + one->len + 1);
		memcpy(big->data + big->len, one->data, one->len);
		big->data[big->len + one->len] = ' ';
		big->len += one->len + 1;

		fz_drop_buffer(one);
	}

	*bigbufp = big;
	return fz_okay;
}

static fz_error
pdf_load_page_contents(fz_buffer **bufp, pdf_xref *xref, fz_obj *obj)
{
	fz_error error;

	if (fz_is_array(obj))
	{
		error = pdf_load_page_contents_array(bufp, xref, obj);
		if (error)
			return fz_rethrow(error, "cannot load content stream array (%d 0 R)", fz_to_num(obj));
	}
	else if (pdf_is_stream(xref, fz_to_num(obj), fz_to_gen(obj)))
	{
		error = pdf_load_stream(bufp, xref, fz_to_num(obj), fz_to_gen(obj));
		if (error)
			return fz_rethrow(error, "cannot load content stream (%d 0 R)", fz_to_num(obj));
	}
	else
	{
		fz_warn("page contents missing, leaving page blank");
		*bufp = fz_new_buffer(0);
	}

	return fz_okay;
}

/* We need to know whether to install a page-level transparency group */

static int pdf_resources_use_blending(fz_obj *rdb);

static int
pdf_extgstate_uses_blending(fz_obj *dict)
{
	fz_obj *obj;

	obj = fz_dict_gets(dict, "BM");
	if (fz_is_name(obj) && strcmp(fz_to_name(obj), "Normal"))
		return 1;

	return 0;
}

static int
pdf_pattern_uses_blending(fz_obj *dict)
{
	fz_obj *obj;

	obj = fz_dict_gets(dict, "Resources");
	if (fz_is_dict(obj) && pdf_resources_use_blending(obj))
		return 1;

	obj = fz_dict_gets(dict, "ExtGState");
	if (fz_is_dict(obj) && pdf_extgstate_uses_blending(obj))
		return 1;

	return 0;
}

static int
pdf_xobject_uses_blending(fz_obj *dict)
{
	fz_obj *obj;

	obj = fz_dict_gets(dict, "Resources");
	if (fz_is_dict(obj) && pdf_resources_use_blending(obj))
		return 1;

	return 0;
}

static int
pdf_resources_use_blending(fz_obj *rdb)
{
	fz_obj *dict;
	fz_obj *tmp;
	int i;

	/* stop on cyclic resource dependencies */
	if (fz_dict_gets(rdb, ".useBM"))
		return fz_to_bool(fz_dict_gets(rdb, ".useBM"));

	tmp = fz_new_bool(0);
	fz_dict_puts(rdb, ".useBM", tmp);
	fz_drop_obj(tmp);

	dict = fz_dict_gets(rdb, "ExtGState");
	for (i = 0; i < fz_dict_len(dict); i++)
		if (pdf_extgstate_uses_blending(fz_dict_get_val(dict, i)))
			goto found;

	dict = fz_dict_gets(rdb, "Pattern");
	for (i = 0; i < fz_dict_len(dict); i++)
		if (pdf_pattern_uses_blending(fz_dict_get_val(dict, i)))
			goto found;

	dict = fz_dict_gets(rdb, "XObject");
	for (i = 0; i < fz_dict_len(dict); i++)
		if (pdf_xobject_uses_blending(fz_dict_get_val(dict, i)))
			goto found;

	return 0;

found:
	tmp = fz_new_bool(1);
	fz_dict_puts(rdb, ".useBM", tmp);
	fz_drop_obj(tmp);
	return 1;
}

fz_error
pdf_load_page(pdf_page **pagep, pdf_xref *xref, fz_obj *dict)
{
	fz_error error;
	pdf_page *page;
	fz_obj *obj;
	fz_bbox bbox;

	pdf_log_page("load page {\n");

	// TODO: move this to a more appropriate place
	/* Ensure that we have a store for resource objects */
	if (!xref->store)
		xref->store = pdf_new_store();

	page = fz_malloc(sizeof(pdf_page));
	page->resources = NULL;
	page->contents = NULL;
	page->transparency = 0;
	page->links = NULL;
	page->annots = NULL;

	obj = fz_dict_gets(dict, "MediaBox");
	bbox = fz_round_rect(pdf_to_rect(obj));
	if (fz_is_empty_rect(pdf_to_rect(obj)))
	{
		fz_warn("cannot find page bounds, guessing page bounds.");
		bbox.x0 = 0;
		bbox.y0 = 0;
		bbox.x1 = 612;
		bbox.y1 = 792;
	}

	obj = fz_dict_gets(dict, "CropBox");
	if (fz_is_array(obj))
	{
		fz_bbox cropbox = fz_round_rect(pdf_to_rect(obj));
		bbox = fz_intersect_bbox(bbox, cropbox);
	}

	page->mediabox.x0 = MIN(bbox.x0, bbox.x1);
	page->mediabox.y0 = MIN(bbox.y0, bbox.y1);
	page->mediabox.x1 = MAX(bbox.x0, bbox.x1);
	page->mediabox.y1 = MAX(bbox.y0, bbox.y1);

	if (page->mediabox.x1 - page->mediabox.x0 < 1 || page->mediabox.y1 - page->mediabox.y0 < 1)
		return fz_throw("invalid page size");

	page->rotate = fz_to_int(fz_dict_gets(dict, "Rotate"));

	pdf_log_page("bbox [%d %d %d %d]\n", bbox.x0, bbox.y0, bbox.x1, bbox.y1);
	pdf_log_page("rotate %d\n", page->rotate);

	obj = fz_dict_gets(dict, "Annots");
	if (obj)
	{
		pdf_load_links(&page->links, xref, obj);
		pdf_load_annots(&page->annots, xref, obj);
	}

	page->resources = fz_dict_gets(dict, "Resources");
	if (page->resources)
		fz_keep_obj(page->resources);

	obj = fz_dict_gets(dict, "Contents");
	error = pdf_load_page_contents(&page->contents, xref, obj);
	if (error)
	{
		pdf_free_page(page);
		return fz_rethrow(error, "cannot load page contents (%d %d R)", fz_to_num(obj), fz_to_gen(obj));
	}

	if (page->resources && pdf_resources_use_blending(page->resources))
		page->transparency = 1;

	pdf_log_page("} %p\n", page);

	*pagep = page;
	return fz_okay;
}

void
pdf_free_page(pdf_page *page)
{
	pdf_log_page("drop page %p\n", page);
	if (page->resources)
		fz_drop_obj(page->resources);
	if (page->contents)
		fz_drop_buffer(page->contents);
	if (page->links)
		pdf_free_link(page->links);
	if (page->annots)
		pdf_free_annot(page->annots);
	fz_free(page);
}
