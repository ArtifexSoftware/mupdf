#include "fitz.h"
#include "muxps.h"

void
xps_parse_canvas(xps_context *ctx, fz_matrix ctm, char *base_uri, xps_resource *dict, xml_element *root)
{
	xps_resource *new_dict = NULL;
	xml_element *node;
	char *opacity_mask_uri;
	int code;

	char *transform_att;
	char *clip_att;
	char *opacity_att;
	char *opacity_mask_att;

	xml_element *transform_tag = NULL;
	xml_element *clip_tag = NULL;
	xml_element *opacity_mask_tag = NULL;

	fz_matrix transform;

	transform_att = xml_att(root, "RenderTransform");
	clip_att = xml_att(root, "Clip");
	opacity_att = xml_att(root, "Opacity");
	opacity_mask_att = xml_att(root, "OpacityMask");

	for (node = xml_down(root); node; node = xml_next(node))
	{
		if (!strcmp(xml_tag(node), "Canvas.Resources") && xml_down(node))
		{
			code = xps_parse_resource_dictionary(ctx, &new_dict, base_uri, xml_down(node));
			if (code)
				fz_catch(code, "cannot load Canvas.Resources");
			else
			{
				new_dict->parent = dict;
				dict = new_dict;
			}
		}

		if (!strcmp(xml_tag(node), "Canvas.RenderTransform"))
			transform_tag = xml_down(node);
		if (!strcmp(xml_tag(node), "Canvas.Clip"))
			clip_tag = xml_down(node);
		if (!strcmp(xml_tag(node), "Canvas.OpacityMask"))
			opacity_mask_tag = xml_down(node);
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

	xps_begin_opacity(ctx, ctm, fz_infiniterect, opacity_mask_uri, dict, opacity_att, opacity_mask_tag);

	for (node = xml_down(root); node; node = xml_next(node))
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
	xml_element *node;
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

	if (!page->root)
		return;

	for (node = xml_down(page->root); node; node = xml_next(node))
	{
		if (!strcmp(xml_tag(node), "FixedPage.Resources") && xml_down(node))
		{
			code = xps_parse_resource_dictionary(ctx, &dict, base_uri, xml_down(node));
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
	xml_element *root;
	char *width_att;
	char *height_att;

	part = xps_read_part(ctx, page->name);
	if (!part)
		return fz_rethrow(-1, "cannot read zip part '%s'", page->name);

	root = xml_parse_document(part->data, part->size);
	if (!root)
		return fz_rethrow(-1, "cannot parse xml part '%s'", page->name);

	xps_free_part(ctx, part);

	if (strcmp(xml_tag(root), "FixedPage"))
		return fz_throw("expected FixedPage element (found %s)", xml_tag(root));

	width_att = xml_att(root, "Width");
	if (!width_att)
		return fz_throw("FixedPage missing required attribute: Width");

	height_att = xml_att(root, "Height");
	if (!height_att)
		return fz_throw("FixedPage missing required attribute: Height");

	page->width = atoi(width_att);
	page->height = atoi(height_att);
	page->root = root;

	return 0;
}
