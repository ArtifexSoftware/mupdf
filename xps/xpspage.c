#include "fitz.h"
#include "muxps.h"

void
xps_parse_canvas(xps_context_t *ctx, fz_matrix ctm, char *base_uri, xps_resource_t *dict, xps_item_t *root)
{
	xps_resource_t *new_dict = NULL;
	xps_item_t *node;
	char *opacity_mask_uri;
	int code;

	char *transform_att;
	char *clip_att;
	char *opacity_att;
	char *opacity_mask_att;

	xps_item_t *transform_tag = NULL;
	xps_item_t *clip_tag = NULL;
	xps_item_t *opacity_mask_tag = NULL;

	fz_matrix transform;

	transform_att = xps_att(root, "RenderTransform");
	clip_att = xps_att(root, "Clip");
	opacity_att = xps_att(root, "Opacity");
	opacity_mask_att = xps_att(root, "OpacityMask");

	for (node = xps_down(root); node; node = xps_next(node))
	{
		if (!strcmp(xps_tag(node), "Canvas.Resources") && xps_down(node))
		{
			code = xps_parse_resource_dictionary(ctx, &new_dict, base_uri, xps_down(node));
			if (code)
				fz_catch(code, "cannot load Canvas.Resources");
			else
			{
				new_dict->parent = dict;
				dict = new_dict;
			}
		}

		if (!strcmp(xps_tag(node), "Canvas.RenderTransform"))
			transform_tag = xps_down(node);
		if (!strcmp(xps_tag(node), "Canvas.Clip"))
			clip_tag = xps_down(node);
		if (!strcmp(xps_tag(node), "Canvas.OpacityMask"))
			opacity_mask_tag = xps_down(node);
	}

	opacity_mask_uri = base_uri;
	xps_resolve_resource_reference(ctx, dict, &transform_att, &transform_tag, NULL);
	xps_resolve_resource_reference(ctx, dict, &clip_att, &clip_tag, NULL);
	xps_resolve_resource_reference(ctx, dict, &opacity_mask_att, &opacity_mask_tag, &opacity_mask_uri);

	transform = fz_identity;
	if (transform_att)
		xps_parse_render_transform(ctx, transform_att, &transform);
	if (transform_tag)
		xps_parse_matrix_transform(ctx, transform_tag, &transform);
	ctm = fz_concat(ctm, transform);

	if (clip_att || clip_tag)
	{
		ctx->path = fz_newpath();
		if (clip_att)
			xps_parse_abbreviated_geometry(ctx, clip_att);
		if (clip_tag)
			xps_parse_path_geometry(ctx, dict, clip_tag, 0);
		xps_clip(ctx, ctm);
	}

	xps_begin_opacity(ctx, ctm, opacity_mask_uri, dict, opacity_att, opacity_mask_tag);

	for (node = xps_down(root); node; node = xps_next(node))
	{
		xps_parse_element(ctx, ctm, base_uri, dict, node);
	}

	xps_end_opacity(ctx, opacity_mask_uri, dict, opacity_att, opacity_mask_tag);

	if (clip_att || clip_tag)
		ctx->dev->popclip(ctx->dev->user);

	if (new_dict)
		xps_free_resource_dictionary(ctx, new_dict);
}

void
xps_parse_fixed_page(xps_context_t *ctx, fz_matrix ctm, xps_page_t *page)
{
	xps_item_t *node;
	xps_resource_t *dict;
	char base_uri[1024];
	char *s;
	int code;

	xps_strlcpy(base_uri, page->name, sizeof base_uri);
	s = strrchr(base_uri, '/');
	if (s)
		s[1] = 0;

	dict = NULL;

	for (node = xps_down(page->root); node; node = xps_next(node))
	{
		if (!strcmp(xps_tag(node), "FixedPage.Resources") && xps_down(node))
		{
			code = xps_parse_resource_dictionary(ctx, &dict, base_uri, xps_down(node));
			if (code)
				fz_catch(code, "cannot load FixedPage.Resources");
		}
		xps_parse_element(ctx, ctm, base_uri, dict, node);
	}

	if (dict)
	{
		xps_free_resource_dictionary(ctx, dict);
	}
}

int
xps_load_fixed_page(xps_context_t *ctx, xps_page_t *page)
{
	xps_part_t *part;
	xps_item_t *root;
	char *width_att;
	char *height_att;

	part = xps_read_part(ctx, page->name);
	if (!part)
		return fz_rethrow(-1, "cannot read zip part '%s'", page->name);

	root = xps_parse_xml(ctx, part->data, part->size);
	if (!root)
		return fz_rethrow(-1, "cannot parse xml");

	xps_free_part(ctx, part);

	if (strcmp(xps_tag(root), "FixedPage"))
		return fz_throw("expected FixedPage element (found %s)", xps_tag(root));

	width_att = xps_att(root, "Width");
	if (!width_att)
		return fz_throw("FixedPage missing required attribute: Width");

	height_att = xps_att(root, "Height");
	if (!height_att)
		return fz_throw("FixedPage missing required attribute: Height");

	page->width = atoi(width_att);
	page->height = atoi(height_att);
	page->root = root;

	return 0;
}
