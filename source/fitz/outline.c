#include "mupdf/fitz.h"

void
fz_drop_outline(fz_context *ctx, fz_outline *outline)
{
	while (outline)
	{
		fz_outline *next = outline->next;
		fz_drop_outline(ctx, outline->down);
		fz_free(ctx, outline->title);
		fz_drop_link_dest(ctx, &outline->dest);
		fz_free(ctx, outline);
		outline = next;
	}
}

static void
fz_debug_outline_xml_imp(fz_context *ctx, fz_output *out, fz_outline *outline, int level)
{
	while (outline)
	{
		fz_printf(ctx, out, "<outline title=%q page=\"%d\"", outline->title, outline->dest.kind == FZ_LINK_GOTO ? outline->dest.ld.gotor.page + 1 : 0);
		if (outline->down)
		{
			fz_printf(ctx, out, ">\n");
			fz_debug_outline_xml_imp(ctx, out, outline->down, level + 1);
			fz_printf(ctx, out, "</outline>\n");
		}
		else
		{
			fz_printf(ctx, out, " />\n");
		}
		outline = outline->next;
	}
}

void
fz_print_outline_xml(fz_context *ctx, fz_output *out, fz_outline *outline)
{
	fz_debug_outline_xml_imp(ctx, out, outline, 0);
}

static void
fz_print_outline_imp(fz_context *ctx, fz_output *out, fz_outline *outline, int level)
{
	int i;
	while (outline)
	{
		for (i = 0; i < level; i++)
			fz_printf(ctx, out, "\t");
		fz_printf(ctx, out, "%s\t%d\n", outline->title, outline->dest.kind == FZ_LINK_GOTO ? outline->dest.ld.gotor.page + 1 : 0);
		if (outline->down)
			fz_print_outline_imp(ctx, out, outline->down, level + 1);
		outline = outline->next;
	}
}

void
fz_print_outline(fz_context *ctx, fz_output *out, fz_outline *outline)
{
	fz_print_outline_imp(ctx, out, outline, 0);
}
