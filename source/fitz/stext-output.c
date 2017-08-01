#include "fitz-imp.h"

#define SUBSCRIPT_OFFSET 0.2f
#define SUPERSCRIPT_OFFSET -0.2f

#include <ft2build.h>
#include FT_FREETYPE_H

/* HTML output (visual formatting with preserved layout) */

static void
fz_print_style_begin_html(fz_context *ctx, fz_output *out, fz_stext_style *style)
{
	int is_bold = fz_font_is_bold(ctx, style->font);
	int is_italic = fz_font_is_italic(ctx, style->font);
	int is_serif = fz_font_is_serif(ctx, style->font);
	int is_mono = fz_font_is_monospaced(ctx, style->font);
	int script = style->script;

	fz_write_printf(ctx, out, "<span style=\"font-family:%s;font-size:%gpt;\">", is_serif ? "serif" : "sans-serif", style->size);
	if (is_mono)
		fz_write_string(ctx, out, "<tt>");
	if (is_bold)
		fz_write_string(ctx, out, "<b>");
	if (is_italic)
		fz_write_string(ctx, out, "<i>");

	while (script-- > 0)
		fz_write_string(ctx, out, "<sup>");
	while (++script < 0)
		fz_write_string(ctx, out, "<sub>");
}

static void
fz_print_style_end_html(fz_context *ctx, fz_output *out, fz_stext_style *style)
{
	int is_mono = fz_font_is_monospaced(ctx, style->font);
	int is_bold = fz_font_is_bold(ctx, style->font);
	int is_italic = fz_font_is_italic(ctx, style->font);
	int script = style->script;

	while (script-- > 0)
		fz_write_string(ctx, out, "</sup>");
	while (++script < 0)
		fz_write_string(ctx, out, "</sub>");

	if (is_italic)
		fz_write_string(ctx, out, "</i>");
	if (is_bold)
		fz_write_string(ctx, out, "</b>");
	if (is_mono)
		fz_write_string(ctx, out, "</tt>");
	fz_write_string(ctx, out, "</span>");
}

static void
fz_print_stext_image_as_html(fz_context *ctx, fz_output *out, fz_image_block *block)
{
	int x = block->bbox.x0;
	int y = block->bbox.y0;
	int w = block->bbox.x1 - block->bbox.x0;
	int h = block->bbox.y1 - block->bbox.y0;

	fz_write_printf(ctx, out, "<img style=\"top:%dpt;left:%dpt;width:%dpt;height:%dpt\" src=\"data:", y, x, w, h);
	fz_write_image_as_data_uri(ctx, out, block->image);
	fz_write_string(ctx, out, "\">\n");
}

void
fz_print_stext_block_as_html(fz_context *ctx, fz_output *out, fz_stext_block *block)
{
	fz_stext_style *style = NULL;
	fz_stext_line *line;
	fz_stext_span *span;
	fz_stext_char *ch;
	int x, y;

	style = NULL;

	for (line = block->lines; line < block->lines + block->len; ++line)
	{
		for (span = line->first_span; span; span = span->next)
		{
			if (span == line->first_span || span->spacing > 1)
			{
				if (style)
				{
					fz_print_style_end_html(ctx, out, style);
					fz_write_string(ctx, out, "</p>\n");
					style = NULL;
				}
				x = span->bbox.x0;
				y = span->bbox.y0;
				fz_write_printf(ctx, out, "<p style=\"top:%dpt;left:%dpt;\">", y, x);
			}

			for (ch = span->text; ch < span->text + span->len; ++ch)
			{
				if (ch->style != style)
				{
					if (style)
						fz_print_style_end_html(ctx, out, style);
					style = ch->style;
					fz_print_style_begin_html(ctx, out, style);
				}

				switch (ch->c)
				{
				default:
					if (ch->c >= 32 && ch->c <= 127)
						fz_write_byte(ctx, out, ch->c);
					else
						fz_write_printf(ctx, out, "&#x%x;", ch->c);
					break;
				case '<': fz_write_string(ctx, out, "&lt;"); break;
				case '>': fz_write_string(ctx, out, "&gt;"); break;
				case '&': fz_write_string(ctx, out, "&amp;"); break;
				case '"': fz_write_string(ctx, out, "&quot;"); break;
				case '\'': fz_write_string(ctx, out, "&apos;"); break;
				}
			}
		}

		if (style)
		{
			fz_print_style_end_html(ctx, out, style);
			fz_write_string(ctx, out, "</p>\n");
			style = NULL;
		}
	}
}

void
fz_print_stext_page_as_html(fz_context *ctx, fz_output *out, fz_stext_page *page)
{
	fz_page_block *block;

	int w = page->mediabox.x1 - page->mediabox.x0;
	int h = page->mediabox.y1 - page->mediabox.y0;

	fz_write_printf(ctx, out, "<div style=\"width:%dpt;height:%dpt\">\n", w, h);

	for (block = page->blocks; block < page->blocks + page->len; ++block)
	{
		if (block->type == FZ_PAGE_BLOCK_IMAGE)
			fz_print_stext_image_as_html(ctx, out, block->u.image);
		else if (block->type == FZ_PAGE_BLOCK_TEXT)
			fz_print_stext_block_as_html(ctx, out, block->u.text);
	}

	fz_write_string(ctx, out, "</div>\n");
}

void
fz_print_stext_header_as_html(fz_context *ctx, fz_output *out)
{
	fz_write_string(ctx, out, "<!DOCTYPE html>\n");
	fz_write_string(ctx, out, "<html>\n");
	fz_write_string(ctx, out, "<head>\n");
	fz_write_string(ctx, out, "<style>\n");
	fz_write_string(ctx, out, "body{background-color:gray}\n");
	fz_write_string(ctx, out, "div{position:relative;background-color:white;margin:1em auto}\n");
	fz_write_string(ctx, out, "p{position:absolute;margin:0}\n");
	fz_write_string(ctx, out, "img{position:absolute}\n");
	fz_write_string(ctx, out, "</style>\n");
	fz_write_string(ctx, out, "</head>\n");
	fz_write_string(ctx, out, "<body>\n");
}

void
fz_print_stext_trailer_as_html(fz_context *ctx, fz_output *out)
{
	fz_write_string(ctx, out, "</body>\n");
	fz_write_string(ctx, out, "</html>\n");
}

/* XHTML output (semantic, little layout, suitable for reflow) */

static void
fz_print_stext_image_as_xhtml(fz_context *ctx, fz_output *out, fz_image_block *block)
{
	int w = block->bbox.x1 - block->bbox.x0;
	int h = block->bbox.y1 - block->bbox.y0;

	fz_write_printf(ctx, out, "<img width=\"%d\" height=\"%d\" src=\"data:", w, h);
	fz_write_image_as_data_uri(ctx, out, block->image);
	fz_write_string(ctx, out, "\"/>\n");
}

static void
fz_print_style_begin_xhtml(fz_context *ctx, fz_output *out, fz_stext_style *style)
{
	int is_mono = fz_font_is_monospaced(ctx, style->font);
	int is_bold = fz_font_is_bold(ctx, style->font);
	int is_italic = fz_font_is_italic(ctx, style->font);
	int script = style->script;

	if (is_mono)
		fz_write_string(ctx, out, "<tt>");
	if (is_bold)
		fz_write_string(ctx, out, "<b>");
	if (is_italic)
		fz_write_string(ctx, out, "<i>");

	while (script-- > 0)
		fz_write_string(ctx, out, "<sup>");
	while (++script < 0)
		fz_write_string(ctx, out, "<sub>");
}

static void
fz_print_style_end_xhtml(fz_context *ctx, fz_output *out, fz_stext_style *style)
{
	int is_mono = fz_font_is_monospaced(ctx, style->font);
	int is_bold = fz_font_is_bold(ctx, style->font);
	int is_italic = fz_font_is_italic(ctx, style->font);
	int script = style->script;

	while (script-- > 0)
		fz_write_string(ctx, out, "</sup>");
	while (++script < 0)
		fz_write_string(ctx, out, "</sub>");

	if (is_italic)
		fz_write_string(ctx, out, "</i>");
	if (is_bold)
		fz_write_string(ctx, out, "</b>");
	if (is_mono)
		fz_write_string(ctx, out, "</tt>");
}

static void fz_print_stext_block_as_xhtml(fz_context *ctx, fz_output *out, fz_stext_block *block)
{
	fz_stext_line *line;
	fz_stext_span *span;
	fz_stext_char *ch;
	fz_stext_style *style;

	style = NULL;
	fz_write_string(ctx, out, "<p>\n");

	for (line = block->lines; line < block->lines + block->len; ++line)
	{
		if (line > block->lines)
			fz_write_string(ctx, out, "<br/>\n");
		for (span = line->first_span; span; span = span->next)
		{
			if (span->spacing > 1)
				fz_write_byte(ctx, out, ' ');

			for (ch = span->text; ch < span->text + span->len; ++ch)
			{
				if (ch->style != style)
				{
					if (style)
						fz_print_style_end_xhtml(ctx, out, style);
					style = ch->style;
					fz_print_style_begin_xhtml(ctx, out, style);
				}

				switch (ch->c)
				{
				default:
					if (ch->c >= 32 && ch->c <= 127)
						fz_write_byte(ctx, out, ch->c);
					else
						fz_write_printf(ctx, out, "&#x%x;", ch->c);
					break;
				case '<': fz_write_string(ctx, out, "&lt;"); break;
				case '>': fz_write_string(ctx, out, "&gt;"); break;
				case '&': fz_write_string(ctx, out, "&amp;"); break;
				case '"': fz_write_string(ctx, out, "&quot;"); break;
				case '\'': fz_write_string(ctx, out, "&apos;"); break;
				}
			}
		}
	}

	if (style)
		fz_print_style_end_xhtml(ctx, out, style);
	fz_write_string(ctx, out, "\n</p>\n");
}

void
fz_print_stext_page_as_xhtml(fz_context *ctx, fz_output *out, fz_stext_page *page)
{
	fz_page_block *block;

	fz_write_string(ctx, out, "<div>\n");

	for (block = page->blocks; block < page->blocks + page->len; ++block)
	{
		if (block->type == FZ_PAGE_BLOCK_IMAGE)
			fz_print_stext_image_as_xhtml(ctx, out, block->u.image);
		else if (block->type == FZ_PAGE_BLOCK_TEXT)
			fz_print_stext_block_as_xhtml(ctx, out, block->u.text);
	}

	fz_write_string(ctx, out, "</div>\n");
}

void
fz_print_stext_header_as_xhtml(fz_context *ctx, fz_output *out)
{
	fz_write_string(ctx, out, "<?xml version=\"1.0\"?>\n");
	fz_write_string(ctx, out, "<!DOCTYPE html");
	fz_write_string(ctx, out, " PUBLIC \"-//W3C//DTD XHTML 1.0 Strict//EN\"");
	fz_write_string(ctx, out, " \"http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd\">\n");
	fz_write_string(ctx, out, "<html xmlns=\"http://www.w3.org/1999/xhtml\">\n");
	fz_write_string(ctx, out, "<head>\n");
	fz_write_string(ctx, out, "<style>\n");
	fz_write_string(ctx, out, "body{background-color:gray}\n");
	fz_write_string(ctx, out, "div{background-color:white;margin:1em;padding:1em}\n");
	fz_write_string(ctx, out, "p{margin:0 0 1em 0}\n");
	fz_write_string(ctx, out, "</style>\n");
	fz_write_string(ctx, out, "</head>\n");
	fz_write_string(ctx, out, "<body>\n");
}

void
fz_print_stext_trailer_as_xhtml(fz_context *ctx, fz_output *out)
{
	fz_write_string(ctx, out, "</body>\n");
	fz_write_string(ctx, out, "</html>\n");
}

/* Detailed XML dump of the entire structured text data */

void
fz_print_stext_page_as_xml(fz_context *ctx, fz_output *out, fz_stext_page *page)
{
	int block_n;

	fz_write_printf(ctx, out, "<page width=\"%g\" height=\"%g\">\n",
		page->mediabox.x1 - page->mediabox.x0,
		page->mediabox.y1 - page->mediabox.y0);

	for (block_n = 0; block_n < page->len; block_n++)
	{
		switch (page->blocks[block_n].type)
		{
		case FZ_PAGE_BLOCK_TEXT:
		{
			fz_stext_block *block = page->blocks[block_n].u.text;
			fz_stext_line *line;
			const char *s;

			fz_write_printf(ctx, out, "<block bbox=\"%g %g %g %g\">\n",
				block->bbox.x0, block->bbox.y0, block->bbox.x1, block->bbox.y1);
			for (line = block->lines; line < block->lines + block->len; line++)
			{
				fz_stext_span *span;
				fz_write_printf(ctx, out, "<line bbox=\"%g %g %g %g\">\n",
					line->bbox.x0, line->bbox.y0, line->bbox.x1, line->bbox.y1);
				for (span = line->first_span; span; span = span->next)
				{
					fz_stext_style *style = NULL;
					const char *name = NULL;
					int char_num;
					for (char_num = 0; char_num < span->len; char_num++)
					{
						fz_stext_char *ch = &span->text[char_num];
						if (ch->style != style)
						{
							if (style)
							{
								fz_write_string(ctx, out, "</span>\n");
							}
							style = ch->style;
							name = fz_font_name(ctx, style->font);
							s = strchr(name, '+');
							s = s ? s + 1 : name;
							fz_write_printf(ctx, out, "<span bbox=\"%g %g %g %g\" font=\"%s\" size=\"%g\">\n",
								span->bbox.x0, span->bbox.y0, span->bbox.x1, span->bbox.y1,
								s, style->size);
						}
						{
							fz_rect rect;
							fz_stext_char_bbox(ctx, &rect, span, char_num);
							fz_write_printf(ctx, out, "<char bbox=\"%g %g %g %g\" x=\"%g\" y=\"%g\" c=\"",
								rect.x0, rect.y0, rect.x1, rect.y1, ch->p.x, ch->p.y);
						}
						switch (ch->c)
						{
						case '<': fz_write_string(ctx, out, "&lt;"); break;
						case '>': fz_write_string(ctx, out, "&gt;"); break;
						case '&': fz_write_string(ctx, out, "&amp;"); break;
						case '"': fz_write_string(ctx, out, "&quot;"); break;
						case '\'': fz_write_string(ctx, out, "&apos;"); break;
						default:
							if (ch->c >= 32 && ch->c <= 127)
								fz_write_printf(ctx, out, "%c", ch->c);
							else
								fz_write_printf(ctx, out, "&#x%x;", ch->c);
							break;
						}
						fz_write_string(ctx, out, "\"/>\n");
					}
					if (style)
						fz_write_string(ctx, out, "</span>\n");
				}
				fz_write_string(ctx, out, "</line>\n");
			}
			fz_write_string(ctx, out, "</block>\n");
			break;
		}
		case FZ_PAGE_BLOCK_IMAGE:
		{
			break;
		}
	}
	}
	fz_write_string(ctx, out, "</page>\n");
}

/* Plain text */

void
fz_print_stext_page_as_text(fz_context *ctx, fz_output *out, fz_stext_page *page)
{
	fz_page_block *pblock;

	for (pblock = page->blocks; pblock < page->blocks + page->len; ++pblock)
	{
		if (pblock->type == FZ_PAGE_BLOCK_TEXT)
		{
			fz_stext_block *block = pblock->u.text;
			fz_stext_line *line;
			fz_stext_char *ch;
			char utf[10];
			int i, n;

			for (line = block->lines; line < block->lines + block->len; line++)
			{
				fz_stext_span *span;
				for (span = line->first_span; span; span = span->next)
				{
					if (span->spacing > 1)
						fz_write_byte(ctx, out, ' ');
					for (ch = span->text; ch < span->text + span->len; ch++)
					{
						n = fz_runetochar(utf, ch->c);
						for (i = 0; i < n; i++)
							fz_write_byte(ctx, out, utf[i]);
					}
				}
				fz_write_string(ctx, out, "\n");
			}
			fz_write_string(ctx, out, "\n");
		}
	}
}

/* Text output writer */

enum {
	FZ_FORMAT_TEXT,
	FZ_FORMAT_HTML,
	FZ_FORMAT_XHTML,
	FZ_FORMAT_STEXT,
};

typedef struct fz_text_writer_s fz_text_writer;

struct fz_text_writer_s
{
	fz_document_writer super;
	int format;
	fz_stext_options opts;
	fz_stext_sheet *sheet;
	fz_stext_page *page;
	fz_output *out;
};

static fz_device *
text_begin_page(fz_context *ctx, fz_document_writer *wri_, const fz_rect *mediabox)
{
	fz_text_writer *wri = (fz_text_writer*)wri_;

	if (wri->page)
	{
		fz_drop_stext_page(ctx, wri->page);
		wri->page = NULL;
	}

	wri->page = fz_new_stext_page(ctx, mediabox);
	return fz_new_stext_device(ctx, wri->sheet, wri->page, &wri->opts);
}

static void
text_end_page(fz_context *ctx, fz_document_writer *wri_, fz_device *dev)
{
	fz_text_writer *wri = (fz_text_writer*)wri_;
	fz_close_device(ctx, dev);
	fz_drop_device(ctx, dev);

	switch (wri->format)
	{
	default:
	case FZ_FORMAT_TEXT:
		fz_print_stext_page_as_text(ctx, wri->out, wri->page);
		break;
	case FZ_FORMAT_HTML:
		fz_print_stext_page_as_html(ctx, wri->out, wri->page);
		break;
	case FZ_FORMAT_XHTML:
		fz_print_stext_page_as_xhtml(ctx, wri->out, wri->page);
		break;
	case FZ_FORMAT_STEXT:
		fz_print_stext_page_as_xml(ctx, wri->out, wri->page);
		break;
	}

	fz_drop_stext_page(ctx, wri->page);
	wri->page = NULL;
}

static void
text_close_writer(fz_context *ctx, fz_document_writer *wri_)
{
	fz_text_writer *wri = (fz_text_writer*)wri_;
	switch (wri->format)
	{
	case FZ_FORMAT_HTML:
		fz_print_stext_trailer_as_html(ctx, wri->out);
		break;
	case FZ_FORMAT_XHTML:
		fz_print_stext_trailer_as_xhtml(ctx, wri->out);
		break;
	case FZ_FORMAT_STEXT:
		fz_write_string(ctx, wri->out, "</document>\n");
		break;
	}
}

static void
text_drop_writer(fz_context *ctx, fz_document_writer *wri_)
{
	fz_text_writer *wri = (fz_text_writer*)wri_;
	fz_drop_stext_page(ctx, wri->page);
	fz_drop_stext_sheet(ctx, wri->sheet);
	fz_drop_output(ctx, wri->out);
}

fz_document_writer *
fz_new_text_writer(fz_context *ctx, const char *format, const char *path, const char *args)
{
	fz_text_writer *wri;

	wri = fz_new_derived_document_writer(ctx, fz_text_writer, text_begin_page, text_end_page, text_close_writer, text_drop_writer);
	fz_try(ctx)
	{
		fz_parse_stext_options(ctx, &wri->opts, args);

		wri->format = FZ_FORMAT_TEXT;
		if (!strcmp(format, "text"))
			wri->format = FZ_FORMAT_TEXT;
		else if (!strcmp(format, "html"))
			wri->format = FZ_FORMAT_HTML;
		else if (!strcmp(format, "xhtml"))
			wri->format = FZ_FORMAT_XHTML;
		else if (!strcmp(format, "stext"))
			wri->format = FZ_FORMAT_STEXT;

		wri->sheet = fz_new_stext_sheet(ctx);
		wri->out = fz_new_output_with_path(ctx, path ? path : "out.txt", 0);

		switch (wri->format)
		{
		case FZ_FORMAT_HTML:
			fz_print_stext_header_as_html(ctx, wri->out);
			break;
		case FZ_FORMAT_XHTML:
			fz_print_stext_header_as_xhtml(ctx, wri->out);
			break;
		case FZ_FORMAT_STEXT:
			fz_write_string(ctx, wri->out, "<?xml version=\"1.0\"?>\n");
			fz_write_string(ctx, wri->out, "<document>\n");
			break;
		}
	}
	fz_catch(ctx)
	{
		fz_drop_output(ctx, wri->out);
		fz_drop_stext_sheet(ctx, wri->sheet);
		fz_free(ctx, wri);
		fz_rethrow(ctx);
	}

	return (fz_document_writer*)wri;
}
