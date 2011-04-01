#include "fitz.h"
#include "muxps.h"

void
xps_parse_canvas(xps_context *ctx, fz_matrix ctm, char *base_uri, xps_resource *dict, xps_item *root)
{
	xps_resource *new_dict = NULL;
	xps_item *node;
	char *opacity_mask_uri;
	int code;

	char *transform_att;
	char *clip_att;
	char *opacity_att;
	char *opacity_mask_att;

	xps_item *transform_tag = NULL;
	xps_item *clip_tag = NULL;
	xps_item *opacity_mask_tag = NULL;

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
	ctm = fz_concat(transform, ctm);

	if (clip_att || clip_tag)
		xps_clip(ctx, ctm, dict, clip_att, clip_tag);

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
xps_parse_fixed_page(xps_context *ctx, fz_matrix ctm, xps_page *page)
{
	xps_item *node;
	xps_resource *dict;
	char base_uri[1024];
	char *s;
	int code;

	fz_strlcpy(base_uri, page->name, sizeof base_uri);
	s = strrchr(base_uri, '/');
	if (s)
		s[1] = 0;

	dict = NULL;

	ctx->opacity_top = 0;
	ctx->opacity[0] = 1;

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
xps_load_fixed_page(xps_context *ctx, xps_page *page)
{
	xps_part *part;
	xps_item *root;
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
