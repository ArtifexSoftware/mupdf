/* Copyright (C) 2006-2010 Artifex Software, Inc.
   All Rights Reserved.

   This software is provided AS-IS with no warranty, either express or
   implied.

   This software is distributed under license and may not be copied, modified
   or distributed except as expressly authorized under the terms of that
   license.  Refer to licensing information at http://www.artifex.com/
   or contact Artifex Software, Inc.,  7 Mt. Lassen  Drive - Suite A-134,
   San Rafael, CA  94903, U.S.A., +1(415)492-9861, for further information.
*/

/* XPS interpreter - page parsing */

#include "ghostxps.h"

int
xps_parse_canvas(xps_context_t *ctx, char *base_uri, xps_resource_t *dict, xps_item_t *root)
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

	gs_matrix transform;

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
				return gs_rethrow(code, "cannot load Canvas.Resources");
			new_dict->parent = dict;
			dict = new_dict;
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

	gs_gsave(ctx->pgs);

	gs_make_identity(&transform);
	if (transform_att)
		xps_parse_render_transform(ctx, transform_att, &transform);
	if (transform_tag)
		xps_parse_matrix_transform(ctx, transform_tag, &transform);
	gs_concat(ctx->pgs, &transform);

	if (clip_att || clip_tag)
	{
		if (clip_att)
			xps_parse_abbreviated_geometry(ctx, clip_att);
		if (clip_tag)
			xps_parse_path_geometry(ctx, dict, clip_tag, 0);
		xps_clip(ctx);
	}

	code = xps_begin_opacity(ctx, opacity_mask_uri, dict, opacity_att, opacity_mask_tag);
	if (code)
	{
		gs_grestore(ctx->pgs);
		return gs_rethrow(code, "cannot create transparency group");
	}

	for (node = xps_down(root); node; node = xps_next(node))
	{
		code = xps_parse_element(ctx, base_uri, dict, node);
		if (code)
		{
			xps_end_opacity(ctx, opacity_mask_uri, dict, opacity_att, opacity_mask_tag);
			gs_grestore(ctx->pgs);
			return gs_rethrow(code, "cannot parse child of Canvas");
		}
	}

	xps_end_opacity(ctx, opacity_mask_uri, dict, opacity_att, opacity_mask_tag);

	gs_grestore(ctx->pgs);

	if (new_dict)
		xps_free_resource_dictionary(ctx, new_dict);

	return 0;
}

int
xps_parse_fixed_page(xps_context_t *ctx, xps_part_t *part)
{
	xps_item_t *root, *node;
	xps_resource_t *dict;
	char *width_att;
	char *height_att;
	int has_transparency;
	char base_uri[1024];
	char *s;
	int code;

	if_debug1('|', "doc: parsing page %s\n", part->name);

	xps_strlcpy(base_uri, part->name, sizeof base_uri);
	s = strrchr(base_uri, '/');
	if (s)
		s[1] = 0;

	root = xps_parse_xml(ctx, part->data, part->size);
	if (!root)
		return gs_rethrow(-1, "cannot parse xml");

	if (strcmp(xps_tag(root), "FixedPage"))
		return gs_throw1(-1, "expected FixedPage element (found %s)", xps_tag(root));

	width_att = xps_att(root, "Width");
	height_att = xps_att(root, "Height");

	if (!width_att)
		return gs_throw(-1, "FixedPage missing required attribute: Width");
	if (!height_att)
		return gs_throw(-1, "FixedPage missing required attribute: Height");

	dict = NULL;

	/* Setup new page */
	{
		gs_memory_t *mem = ctx->memory;
		gs_state *pgs = ctx->pgs;
		gx_device *dev = gs_currentdevice(pgs);
		gs_param_float_array fa;
		float fv[2];
		gs_c_param_list list;

		gs_c_param_list_write(&list, mem);

		fv[0] = atoi(width_att) / 96.0 * 72.0;
		fv[1] = atoi(height_att) / 96.0 * 72.0;
		fa.persistent = false;
		fa.data = fv;
		fa.size = 2;

		code = param_write_float_array((gs_param_list *)&list, ".MediaSize", &fa);
		if ( code >= 0 )
		{
			gs_c_param_list_read(&list);
			code = gs_putdeviceparams(dev, (gs_param_list *)&list);
		}
		gs_c_param_list_release(&list);

		/* nb this is for the demo it is wrong and should be removed */
		gs_initgraphics(pgs);

		/* 96 dpi default - and put the origin at the top of the page */

		gs_initmatrix(pgs);

		code = gs_scale(pgs, 72.0/96.0, -72.0/96.0);
		if (code < 0)
			return gs_rethrow(code, "cannot set page transform");

		code = gs_translate(pgs, 0.0, -atoi(height_att));
		if (code < 0)
			return gs_rethrow(code, "cannot set page transform");

		code = gs_erasepage(pgs);
		if (code < 0)
			return gs_rethrow(code, "cannot clear page");
	}

	/* Pre-parse looking for transparency */

	has_transparency = 0;

	for (node = xps_down(root); node; node = xps_next(node))
	{
		if (!strcmp(xps_tag(node), "FixedPage.Resources") && xps_down(node))
			if (xps_resource_dictionary_has_transparency(ctx, base_uri, xps_down(node)))
				has_transparency = 1;
		if (xps_element_has_transparency(ctx, base_uri, node))
			has_transparency = 1;
	}

	/* save the state with the original device before we push */
	gs_gsave(ctx->pgs);

	if (ctx->use_transparency && has_transparency)
	{
		code = gs_push_pdf14trans_device(ctx->pgs);
		if (code < 0)
		{
			gs_grestore(ctx->pgs);
			return gs_rethrow(code, "cannot install transparency device");
		}
	}

	/* Initialize the default profiles in the ctx to what is in the manager */
	ctx->gray->cmm_icc_profile_data = ctx->pgs->icc_manager->default_gray;
	ctx->srgb->cmm_icc_profile_data = ctx->pgs->icc_manager->default_rgb;
	/* scrgb really needs to be a bit different.
	 * Unless we are handling nonlinearity before conversion from float. ToDo. */
	ctx->scrgb->cmm_icc_profile_data = ctx->pgs->icc_manager->default_rgb;
	ctx->cmyk->cmm_icc_profile_data = ctx->pgs->icc_manager->default_cmyk;

	/* Draw contents */

	for (node = xps_down(root); node; node = xps_next(node))
	{
		if (!strcmp(xps_tag(node), "FixedPage.Resources") && xps_down(node))
		{
			code = xps_parse_resource_dictionary(ctx, &dict, base_uri, xps_down(node));
			if (code)
			{
				gs_pop_pdf14trans_device(ctx->pgs);
				gs_grestore(ctx->pgs);
				return gs_rethrow(code, "cannot load FixedPage.Resources");
			}
		}
		code = xps_parse_element(ctx, base_uri, dict, node);
		if (code)
		{
			gs_pop_pdf14trans_device(ctx->pgs);
			gs_grestore(ctx->pgs);
			return gs_rethrow(code, "cannot parse child of FixedPage");
		}
	}

	if (ctx->use_transparency && has_transparency)
	{
		code = gs_pop_pdf14trans_device(ctx->pgs);
		if (code < 0)
		{
			gs_grestore(ctx->pgs);
			return gs_rethrow(code, "cannot uninstall transparency device");
		}
	}

	/* Flush page */
	{
		code = xps_show_page(ctx, 1, true); /* copies, flush */
		if (code < 0)
		{
			gs_grestore(ctx->pgs);
			return gs_rethrow(code, "cannot flush page");
		}
	}

	/* restore the original device, discarding the pdf14 compositor */
	gs_grestore(ctx->pgs);

	if (dict)
	{
		xps_free_resource_dictionary(ctx, dict);
	}

	xps_free_item(ctx, root);

	return 0;
}
