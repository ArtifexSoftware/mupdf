/*
 * mudraw -- command line tool for drawing and converting documents
 */

#include "mupdf/fitz.h"
#include "mupdf/pdf.h" /* for pdf output */

#ifdef _MSC_VER
#include <winsock2.h>
#define main main_utf8
#else
#include <sys/time.h>
#endif

enum {
	OUT_NONE,
	OUT_PNG, OUT_TGA, OUT_PNM, OUT_PGM, OUT_PPM, OUT_PAM,
	OUT_PBM, OUT_PWG, OUT_PCL,
	OUT_TEXT, OUT_HTML, OUT_STEXT,
	OUT_TRACE, OUT_SVG, OUT_PDF,
};

enum { CS_INVALID, CS_UNSET, CS_MONO, CS_GRAY, CS_GRAY_ALPHA, CS_RGB, CS_RGB_ALPHA, CS_CMYK, CS_CMYK_ALPHA };

typedef struct
{
	char *suffix;
	int format;
} suffix_t;

static const suffix_t suffix_table[] =
{
	{ ".png", OUT_PNG },
	{ ".pgm", OUT_PGM },
	{ ".ppm", OUT_PPM },
	{ ".pnm", OUT_PNM },
	{ ".pam", OUT_PAM },
	{ ".pbm", OUT_PBM },
	{ ".svg", OUT_SVG },
	{ ".pwg", OUT_PWG },
	{ ".pcl", OUT_PCL },
	{ ".pdf", OUT_PDF },
	{ ".tga", OUT_TGA },

	{ ".txt", OUT_TEXT },
	{ ".text", OUT_TEXT },
	{ ".html", OUT_HTML },
	{ ".stext", OUT_STEXT },

	{ ".trace", OUT_TRACE },
};

typedef struct
{
	char *name;
	int colorspace;
} cs_name_t;

static const cs_name_t cs_name_table[] =
{
	{ "m", CS_MONO },
	{ "mono", CS_MONO },
	{ "g", CS_GRAY },
	{ "gray", CS_GRAY },
	{ "grey", CS_GRAY },
	{ "ga", CS_GRAY_ALPHA },
	{ "grayalpha", CS_GRAY_ALPHA },
	{ "greyalpha", CS_GRAY_ALPHA },
	{ "rgb", CS_RGB },
	{ "rgba", CS_RGB_ALPHA },
	{ "rgbalpha", CS_RGB_ALPHA },
	{ "cmyk", CS_CMYK },
	{ "cmyka", CS_CMYK_ALPHA },
	{ "cmykalpha", CS_CMYK_ALPHA },
};

typedef struct
{
	int format;
	int default_cs;
	int permitted_cs[6];
} format_cs_table_t;

static const format_cs_table_t format_cs_table[] =
{
	{ OUT_PNG, CS_RGB, { CS_GRAY, CS_GRAY_ALPHA, CS_RGB, CS_RGB_ALPHA } },
	{ OUT_PPM, CS_RGB, { CS_GRAY, CS_RGB } },
	{ OUT_PNM, CS_GRAY, { CS_GRAY, CS_RGB } },
	{ OUT_PAM, CS_RGB_ALPHA, { CS_GRAY, CS_GRAY_ALPHA, CS_RGB, CS_RGB_ALPHA, CS_CMYK, CS_CMYK_ALPHA } },
	{ OUT_PGM, CS_GRAY, { CS_GRAY, CS_RGB } },
	{ OUT_PBM, CS_MONO, { CS_MONO } },
	{ OUT_PWG, CS_RGB, { CS_MONO, CS_GRAY, CS_RGB, CS_CMYK } },
	{ OUT_PCL, CS_MONO, { CS_MONO } },
	{ OUT_TGA, CS_RGB, { CS_GRAY, CS_GRAY_ALPHA, CS_RGB, CS_RGB_ALPHA } },

	{ OUT_TRACE, CS_RGB, { CS_RGB } },
	{ OUT_SVG, CS_RGB, { CS_RGB } },
	{ OUT_PDF, CS_RGB, { CS_RGB } },

	{ OUT_TEXT, CS_RGB, { CS_RGB } },
	{ OUT_HTML, CS_RGB, { CS_RGB } },
	{ OUT_STEXT, CS_RGB, { CS_RGB } },
};

static char *output = NULL;
static char *format = NULL;
static int output_format = OUT_NONE;

static float rotation = 0;
static float resolution = 72;
static int res_specified = 0;
static int width = 0;
static int height = 0;
static int fit = 0;

static float layout_w = 450;
static float layout_h = 600;
static float layout_em = 12;

static int showfeatures = 0;
static int showtime = 0;
static size_t memtrace_current = 0;
static size_t memtrace_peak = 0;
static size_t memtrace_total = 0;
static int showmemory = 0;
static int showmd5 = 0;

static pdf_document *pdfout = NULL;

static int ignore_errors = 0;
static int uselist = 1;
static int alphabits = 8;

static int out_cs = CS_UNSET;
static float gamma_value = 1;
static int invert = 0;
static int bandheight = 0;

static int errored = 0;
static int append = 0;
static fz_text_sheet *sheet = NULL;
static fz_colorspace *colorspace;
static char *filename;
static int files = 0;
fz_output *out = NULL;

static struct {
	int count, total;
	int min, max;
	int minpage, maxpage;
	char *minfilename;
	char *maxfilename;
} timing;

static void usage(void)
{
	fprintf(stderr,
		"mudraw version " FZ_VERSION "\n"
		"Usage: mudraw [options] file [pages]\n"
		"\t-p -\tpassword\n"
		"\n"
		"\t-o -\toutput file name (%%d for page number)\n"
		"\t-F -\toutput format (default inferred from output file name)\n"
		"\t\traster: png, tga, pnm, pam, pbm, pwg, pcl\n"
		"\t\tvector: svg, pdf, trace\n"
		"\t\ttext: txt, html, stext\n"
		"\n"
		"\t-s -\tshow extra information:\n"
		"\t\tm - show memory use\n"
		"\t\tt - show timings\n"
		"\t\tf - show page features\n"
		"\t\t5 - show md5 checksum of rendered image\n"
		"\n"
		"\t-R -\trotate clockwise (default: 0 degrees)\n"
		"\t-r -\tresolution in dpi (default: 72)\n"
		"\t-w -\twidth (in pixels) (maximum width if -r is specified)\n"
		"\t-h -\theight (in pixels) (maximum height if -r is specified)\n"
		"\t-f -\tfit width and/or height exactly; ignore original aspect ratio\n"
		"\t-B -\tmaximum bandheight (pgm, ppm, pam, png output only)\n"
		"\n"
		"\t-W -\tpage width for EPUB layout\n"
		"\t-H -\tpage height for EPUB layout\n"
		"\t-S -\tfont size for EPUB layout\n"
		"\n"
		"\t-c -\tcolorspace (mono, gray, grayalpha, rgb, rgba, cmyk, cmykalpha)\n"
		"\t-G -\tapply gamma correction\n"
		"\t-I\tinvert colors\n"
		"\n"
		"\t-A -\tnumber of bits of antialiasing (0 to 8)\n"
		"\t-D\tdisable use of display list\n"
		"\t-i\tignore errors\n"
		"\n"
		"\tpages\tcomma separated list of page numbers and ranges\n"
		);
	exit(1);
}

static int gettime(void)
{
	static struct timeval first;
	static int once = 1;
	struct timeval now;
	if (once)
	{
		gettimeofday(&first, NULL);
		once = 0;
	}
	gettimeofday(&now, NULL);
	return (now.tv_sec - first.tv_sec) * 1000 + (now.tv_usec - first.tv_usec) / 1000;
}

static int isrange(char *s)
{
	while (*s)
	{
		if ((*s < '0' || *s > '9') && *s != '-' && *s != ',')
			return 0;
		s++;
	}
	return 1;
}

static int has_percent_d(char *s)
{
	/* find '%[0-9]*d' */
	while (*s)
	{
		if (*s++ == '%')
		{
			while (*s >= '0' && *s <= '9')
				++s;
			if (*s == 'd')
				return 1;
		}
	}
	return 0;
}

static void drawpage(fz_context *ctx, fz_document *doc, int pagenum)
{
	fz_page *page;
	fz_display_list *list = NULL;
	fz_device *dev = NULL;
	int start;
	fz_cookie cookie = { 0 };

	fz_var(list);
	fz_var(dev);

	if (showtime)
		start = gettime();

	fz_try(ctx)
		page = fz_load_page(ctx, doc, pagenum - 1);
	fz_catch(ctx)
		fz_rethrow_message(ctx, "cannot load page %d in file '%s'", pagenum, filename);

	if (showmd5 || showtime || showfeatures)
		printf("page %s %d", filename, pagenum);

	if (uselist)
	{
		fz_try(ctx)
		{
			list = fz_new_display_list(ctx);
			dev = fz_new_list_device(ctx, list);
			fz_run_page(ctx, page, dev, &fz_identity, &cookie);
		}
		fz_always(ctx)
		{
			fz_drop_device(ctx, dev);
			dev = NULL;
		}
		fz_catch(ctx)
		{
			fz_drop_display_list(ctx, list);
			fz_drop_page(ctx, page);
			fz_rethrow_message(ctx, "cannot draw page %d in file '%s'", pagenum, filename);
		}
	}

	if (showfeatures)
	{
		int iscolor;
		dev = fz_new_test_device(ctx, &iscolor, 0.02f);
		fz_try(ctx)
		{
			if (list)
				fz_run_display_list(ctx, list, dev, &fz_identity, &fz_infinite_rect, NULL);
			else
				fz_run_page(ctx, page, dev, &fz_identity, &cookie);
		}
		fz_always(ctx)
		{
			fz_drop_device(ctx, dev);
			dev = NULL;
		}
		fz_catch(ctx)
		{
			fz_rethrow(ctx);
		}
		printf(" %s", iscolor ? "color" : "grayscale");
	}

	if (output_format == OUT_TRACE)
	{
		fz_try(ctx)
		{
			dev = fz_new_trace_device(ctx);
			if (list)
				fz_run_display_list(ctx, list, dev, &fz_identity, &fz_infinite_rect, &cookie);
			else
				fz_run_page(ctx, page, dev, &fz_identity, &cookie);
		}
		fz_always(ctx)
		{
			fz_drop_device(ctx, dev);
			dev = NULL;
		}
		fz_catch(ctx)
		{
			fz_drop_display_list(ctx, list);
			fz_drop_page(ctx, page);
			fz_rethrow(ctx);
		}
	}

	else if (output_format == OUT_TEXT || output_format == OUT_HTML || output_format == OUT_STEXT)
	{
		fz_text_page *text = NULL;

		fz_var(text);

		fz_try(ctx)
		{
			text = fz_new_text_page(ctx);
			dev = fz_new_text_device(ctx, sheet, text);
			if (output_format == OUT_HTML)
				fz_disable_device_hints(ctx, dev, FZ_IGNORE_IMAGE);
			if (list)
				fz_run_display_list(ctx, list, dev, &fz_identity, &fz_infinite_rect, &cookie);
			else
				fz_run_page(ctx, page, dev, &fz_identity, &cookie);
			fz_drop_device(ctx, dev);
			dev = NULL;
			if (output_format == OUT_STEXT)
			{
				fz_print_text_page_xml(ctx, out, text);
			}
			else if (output_format == OUT_HTML)
			{
				fz_analyze_text(ctx, sheet, text);
				fz_print_text_page_html(ctx, out, text);
			}
			else if (output_format == OUT_TEXT)
			{
				fz_print_text_page(ctx, out, text);
				fz_printf(ctx, out, "\f\n");
			}
		}
		fz_always(ctx)
		{
			fz_drop_device(ctx, dev);
			dev = NULL;
			fz_drop_text_page(ctx, text);
		}
		fz_catch(ctx)
		{
			fz_drop_display_list(ctx, list);
			fz_drop_page(ctx, page);
			fz_rethrow(ctx);
		}
	}

	else if (output_format == OUT_PDF)
	{
		fz_matrix ctm;
		fz_rect bounds, tbounds;
		pdf_page *newpage;

		fz_bound_page(ctx, page, &bounds);
		fz_rotate(&ctm, rotation);
		tbounds = bounds;
		fz_transform_rect(&tbounds, &ctm);

		newpage = pdf_create_page(ctx, pdfout, bounds, 72, 0);

		fz_try(ctx)
		{
			dev = pdf_page_write(ctx, pdfout, newpage);
			if (list)
				fz_run_display_list(ctx, list, dev, &ctm, &tbounds, &cookie);
			else
				fz_run_page(ctx, page, dev, &ctm, &cookie);
			fz_drop_device(ctx, dev);
			dev = NULL;
		}
		fz_always(ctx)
		{
			fz_drop_device(ctx, dev);
			dev = NULL;
		}
		fz_catch(ctx)
		{
			fz_drop_display_list(ctx, list);
			fz_drop_page(ctx, page);
			fz_rethrow(ctx);
		}
		pdf_insert_page(ctx, pdfout, newpage, INT_MAX);
		fz_drop_page(ctx, &newpage->super);
	}

	else if (output_format == OUT_SVG)
	{
		float zoom;
		fz_matrix ctm;
		fz_rect bounds, tbounds;
		char buf[512];
		FILE *file;
		fz_output *out;

		if (!strcmp(output, "-"))
			file = stdout;
		else
		{
			sprintf(buf, output, pagenum);
			file = fopen(buf, "wb");
			if (file == NULL)
				fz_throw(ctx, FZ_ERROR_GENERIC, "cannot open file '%s': %s", buf, strerror(errno));
		}

		out = fz_new_output_with_file(ctx, file, 0);

		fz_bound_page(ctx, page, &bounds);
		zoom = resolution / 72;
		fz_pre_rotate(fz_scale(&ctm, zoom, zoom), rotation);
		tbounds = bounds;
		fz_transform_rect(&tbounds, &ctm);

		fz_try(ctx)
		{
			dev = fz_new_svg_device(ctx, out, tbounds.x1-tbounds.x0, tbounds.y1-tbounds.y0);
			if (list)
				fz_run_display_list(ctx, list, dev, &ctm, &tbounds, &cookie);
			else
				fz_run_page(ctx, page, dev, &ctm, &cookie);
			fz_drop_device(ctx, dev);
			dev = NULL;
		}
		fz_always(ctx)
		{
			fz_drop_device(ctx, dev);
			dev = NULL;
			fz_drop_output(ctx, out);
			if (file != stdout)
				fclose(file);
		}
		fz_catch(ctx)
		{
			fz_drop_display_list(ctx, list);
			fz_drop_page(ctx, page);
			fz_rethrow(ctx);
		}
	}

	else
	{
		float zoom;
		fz_matrix ctm;
		fz_rect bounds, tbounds;
		fz_irect ibounds;
		fz_pixmap *pix = NULL;
		int w, h;
		fz_output *output_file = NULL;
		fz_png_output_context *poc = NULL;

		fz_var(pix);
		fz_var(poc);

		fz_bound_page(ctx, page, &bounds);
		zoom = resolution / 72;
		fz_pre_scale(fz_rotate(&ctm, rotation), zoom, zoom);
		tbounds = bounds;
		fz_round_rect(&ibounds, fz_transform_rect(&tbounds, &ctm));

		/* Make local copies of our width/height */
		w = width;
		h = height;

		/* If a resolution is specified, check to see whether w/h are
		 * exceeded; if not, unset them. */
		if (res_specified)
		{
			int t;
			t = ibounds.x1 - ibounds.x0;
			if (w && t <= w)
				w = 0;
			t = ibounds.y1 - ibounds.y0;
			if (h && t <= h)
				h = 0;
		}

		/* Now w or h will be 0 unless they need to be enforced. */
		if (w || h)
		{
			float scalex = w / (tbounds.x1 - tbounds.x0);
			float scaley = h / (tbounds.y1 - tbounds.y0);
			fz_matrix scale_mat;

			if (fit)
			{
				if (w == 0)
					scalex = 1.0f;
				if (h == 0)
					scaley = 1.0f;
			}
			else
			{
				if (w == 0)
					scalex = scaley;
				if (h == 0)
					scaley = scalex;
			}
			if (!fit)
			{
				if (scalex > scaley)
					scalex = scaley;
				else
					scaley = scalex;
			}
			fz_scale(&scale_mat, scalex, scaley);
			fz_concat(&ctm, &ctm, &scale_mat);
			tbounds = bounds;
			fz_transform_rect(&tbounds, &ctm);
		}
		fz_round_rect(&ibounds, &tbounds);
		fz_rect_from_irect(&tbounds, &ibounds);

		/* TODO: banded rendering and multi-page ppm */
		fz_try(ctx)
		{
			int savealpha = (out_cs == CS_GRAY_ALPHA || out_cs == CS_RGB_ALPHA || out_cs == CS_CMYK_ALPHA);
			fz_irect band_ibounds = ibounds;
			int band, bands = 1;
			char filename_buf[512];
			int totalheight = ibounds.y1 - ibounds.y0;
			int drawheight = totalheight;

			if (bandheight != 0)
			{
				/* Banded rendering; we'll only render to a
				 * given height at a time. */
				drawheight = bandheight;
				if (totalheight > bandheight)
					band_ibounds.y1 = band_ibounds.y0 + bandheight;
				bands = (totalheight + bandheight-1)/bandheight;
				tbounds.y1 = tbounds.y0 + bandheight + 2;
			}

			pix = fz_new_pixmap_with_bbox(ctx, colorspace, &band_ibounds);
			fz_pixmap_set_resolution(pix, resolution);

			if (output)
			{
				if (!strcmp(output, "-"))
					output_file = fz_new_output_with_file(ctx, stdout, 0);
				else
				{
					sprintf(filename_buf, output, pagenum);
					output_file = fz_new_output_to_filename(ctx, filename_buf);
				}

				if (output_format == OUT_PGM || output_format == OUT_PPM || output_format == OUT_PNM)
					fz_output_pnm_header(ctx, output_file, pix->w, totalheight, pix->n);
				else if (output_format == OUT_PAM)
					fz_output_pam_header(ctx, output_file, pix->w, totalheight, pix->n, savealpha);
				else if (output_format == OUT_PNG)
					poc = fz_output_png_header(ctx, output_file, pix->w, totalheight, pix->n, savealpha);
			}

			for (band = 0; band < bands; band++)
			{
				if (savealpha)
					fz_clear_pixmap(ctx, pix);
				else
					fz_clear_pixmap_with_value(ctx, pix, 255);

				dev = fz_new_draw_device(ctx, pix);
				if (alphabits == 0)
					fz_enable_device_hints(ctx, dev, FZ_DONT_INTERPOLATE_IMAGES);
				if (list)
					fz_run_display_list(ctx, list, dev, &ctm, &tbounds, &cookie);
				else
					fz_run_page(ctx, page, dev, &ctm, &cookie);
				fz_drop_device(ctx, dev);
				dev = NULL;

				if (invert)
					fz_invert_pixmap(ctx, pix);
				if (gamma_value != 1)
					fz_gamma_pixmap(ctx, pix, gamma_value);

				if (savealpha)
					fz_unmultiply_pixmap(ctx, pix);

				if (output)
				{
					if (output_format == OUT_PGM || output_format == OUT_PPM || output_format == OUT_PNM)
						fz_output_pnm_band(ctx, output_file, pix->w, totalheight, pix->n, band, drawheight, pix->samples);
					else if (output_format == OUT_PAM)
						fz_output_pam_band(ctx, output_file, pix->w, totalheight, pix->n, band, drawheight, pix->samples, savealpha);
					else if (output_format == OUT_PNG)
						fz_output_png_band(ctx, output_file, pix->w, totalheight, pix->n, band, drawheight, pix->samples, savealpha, poc);
					else if (output_format == OUT_PWG)
					{
						if (has_percent_d(output))
							append = 0;
						if (out_cs == CS_MONO)
						{
							fz_bitmap *bit = fz_halftone_pixmap(ctx, pix, NULL);
							fz_write_pwg_bitmap(ctx, bit, filename_buf, append, NULL);
							fz_drop_bitmap(ctx, bit);
						}
						else
							fz_write_pwg(ctx, pix, filename_buf, append, NULL);
						append = 1;
					}
					else if (output_format == OUT_PCL)
					{
						fz_pcl_options options;

						fz_pcl_preset(ctx, &options, "ljet4");

						if (has_percent_d(output))
							append = 0;
						if (out_cs == CS_MONO)
						{
							fz_bitmap *bit = fz_halftone_pixmap(ctx, pix, NULL);
							fz_write_pcl_bitmap(ctx, bit, filename_buf, append, &options);
							fz_drop_bitmap(ctx, bit);
						}
						else
							fz_write_pcl(ctx, pix, filename_buf, append, &options);
						append = 1;
					}
					else if (output_format == OUT_PBM) {
						fz_bitmap *bit = fz_halftone_pixmap(ctx, pix, NULL);
						fz_write_pbm(ctx, bit, filename_buf);
						fz_drop_bitmap(ctx, bit);
					}
					else if (output_format == OUT_TGA)
					{
						fz_write_tga(ctx, pix, filename_buf, savealpha);
					}
				}
				ctm.f -= drawheight;
			}

			if (showmd5)
			{
				unsigned char digest[16];
				int i;

				fz_md5_pixmap(ctx, pix, digest);
				printf(" ");
				for (i = 0; i < 16; i++)
					printf("%02x", digest[i]);
			}
		}
		fz_always(ctx)
		{
			if (output)
			{
				if (output_format == OUT_PNG)
					fz_output_png_trailer(ctx, output_file, poc);
			}

			fz_drop_device(ctx, dev);
			dev = NULL;
			fz_drop_pixmap(ctx, pix);
			if (output_file)
				fz_drop_output(ctx, output_file);
		}
		fz_catch(ctx)
		{
			fz_drop_display_list(ctx, list);
			fz_drop_page(ctx, page);
			fz_rethrow(ctx);
		}
	}

	if (list)
		fz_drop_display_list(ctx, list);

	fz_drop_page(ctx, page);

	if (showtime)
	{
		int end = gettime();
		int diff = end - start;

		if (diff < timing.min)
		{
			timing.min = diff;
			timing.minpage = pagenum;
			timing.minfilename = filename;
		}
		if (diff > timing.max)
		{
			timing.max = diff;
			timing.maxpage = pagenum;
			timing.maxfilename = filename;
		}
		timing.total += diff;
		timing.count ++;

		printf(" %dms", diff);
	}

	if (showmd5 || showtime || showfeatures)
		printf("\n");

	if (showmemory)
	{
		fz_dump_glyph_cache_stats(ctx);
	}

	fz_flush_warnings(ctx);

	if (cookie.errors)
		errored = 1;
}

static void drawrange(fz_context *ctx, fz_document *doc, char *range)
{
	int page, spage, epage, pagecount;
	char *spec, *dash;

	pagecount = fz_count_pages(ctx, doc);
	spec = fz_strsep(&range, ",");
	while (spec)
	{
		dash = strchr(spec, '-');

		if (dash == spec)
			spage = epage = pagecount;
		else
			spage = epage = atoi(spec);

		if (dash)
		{
			if (strlen(dash) > 1)
				epage = atoi(dash + 1);
			else
				epage = pagecount;
		}

		spage = fz_clampi(spage, 1, pagecount);
		epage = fz_clampi(epage, 1, pagecount);

		if (spage < epage)
			for (page = spage; page <= epage; page++)
				drawpage(ctx, doc, page);
		else
			for (page = spage; page >= epage; page--)
				drawpage(ctx, doc, page);

		spec = fz_strsep(&range, ",");
	}
}

static int
parse_colorspace(const char *name)
{
	int i;

	for (i = 0; i < nelem(cs_name_table); i++)
	{
		if (!strcmp(name, cs_name_table[i].name))
			return cs_name_table[i].colorspace;
	}
	fprintf(stderr, "Unknown colorspace \"%s\"\n", name);
	exit(1);
}

typedef struct
{
	size_t size;
#if defined(_M_IA64) || defined(_M_AMD64)
	size_t align;
#endif
} trace_header;

static void *
trace_malloc(void *arg, unsigned int size)
{
	trace_header *p;
	if (size == 0)
		return NULL;
	p = malloc(size + sizeof(trace_header));
	if (p == NULL)
		return NULL;
	p[0].size = size;
	memtrace_current += size;
	memtrace_total += size;
	if (memtrace_current > memtrace_peak)
		memtrace_peak = memtrace_current;
	return (void *)&p[1];
}

static void
trace_free(void *arg, void *p_)
{
	trace_header *p = (trace_header *)p_;

	if (p == NULL)
		return;
	memtrace_current -= p[-1].size;
	free(&p[-1]);
}

static void *
trace_realloc(void *arg, void *p_, unsigned int size)
{
	trace_header *p = (trace_header *)p_;
	size_t oldsize;

	if (size == 0)
	{
		trace_free(arg, p_);
		return NULL;
	}
	if (p == NULL)
		return trace_malloc(arg, size);
	oldsize = p[-1].size;
	p = realloc(&p[-1], size + sizeof(trace_header));
	if (p == NULL)
		return NULL;
	memtrace_current += size - oldsize;
	if (size > oldsize)
		memtrace_total += size - oldsize;
	if (memtrace_current > memtrace_peak)
		memtrace_peak = memtrace_current;
	p[0].size = size;
	return &p[1];
}

int main(int argc, char **argv)
{
	char *password = "";
	fz_document *doc = NULL;
	int c;
	fz_context *ctx;
	fz_alloc_context alloc_ctx = { NULL, trace_malloc, trace_realloc, trace_free };

	fz_var(doc);

	while ((c = fz_getopt(argc, argv, "po:F:R:r:w:h:fB:c:G:I:s:A:DiW:H:S:v")) != -1)
	{
		switch (c)
		{
		default: usage(); break;

		case 'p': password = fz_optarg; break;

		case 'o': output = fz_optarg; break;
		case 'F': format = fz_optarg; break;

		case 'R': rotation = atof(fz_optarg); break;
		case 'r': resolution = atof(fz_optarg); res_specified = 1; break;
		case 'w': width = atof(fz_optarg); break;
		case 'h': height = atof(fz_optarg); break;
		case 'f': fit = 1; break;
		case 'B': bandheight = atoi(fz_optarg); break;

		case 'c': out_cs = parse_colorspace(fz_optarg); break;
		case 'G': gamma_value = atof(fz_optarg); break;
		case 'I': invert++; break;

		case 'W': layout_w = atof(fz_optarg); break;
		case 'H': layout_h = atof(fz_optarg); break;
		case 'S': layout_em = atof(fz_optarg); break;

		case 's':
			if (strchr(fz_optarg, 't')) ++showtime;
			if (strchr(fz_optarg, 'm')) ++showmemory;
			if (strchr(fz_optarg, 'f')) ++showfeatures;
			if (strchr(fz_optarg, '5')) ++showmd5;
			break;

		case 'A': alphabits = atoi(fz_optarg); break;
		case 'D': uselist = 0; break;
		case 'i': ignore_errors = 1; break;

		case 'v': fprintf(stderr, "mudraw version %s\n", FZ_VERSION); return 1;
		}
	}

	if (fz_optind == argc)
		usage();

	ctx = fz_new_context((showmemory == 0 ? NULL : &alloc_ctx), NULL, FZ_STORE_DEFAULT);
	if (!ctx)
	{
		fprintf(stderr, "cannot initialise context\n");
		exit(1);
	}

	fz_set_aa_level(ctx, alphabits);

	/* Determine output type */
	if (bandheight < 0)
	{
		fprintf(stderr, "Bandheight must be > 0\n");
		exit(1);
	}

	output_format = OUT_PNG;
	if (format)
	{
		int i;

		for (i = 0; i < nelem(suffix_table); i++)
		{
			if (!strcmp(format, suffix_table[i].suffix+1))
			{
				output_format = suffix_table[i].format;
				break;
			}
		}
		if (i == nelem(suffix_table))
		{
			fprintf(stderr, "Unknown output format '%s'\n", format);
			exit(1);
		}
	}
	else if (output)
	{
		char *suffix = output;
		int i;

		for (i = 0; i < nelem(suffix_table); i++)
		{
			char *s = strstr(suffix, suffix_table[i].suffix);

			if (s != NULL)
			{
				suffix = s+1;
				output_format = suffix_table[i].format;
				i = 0;
			}
		}
	}

	if (bandheight)
	{
		if (output_format != OUT_PAM && output_format != OUT_PGM && output_format != OUT_PPM && output_format != OUT_PNM && output_format != OUT_PNG)
		{
			fprintf(stderr, "Banded operation only possible with PAM, PGM, PPM, PNM and PNG outputs\n");
			exit(1);
		}
		if (showmd5)
		{
			fprintf(stderr, "Banded operation not compatible with MD5\n");
			exit(1);
		}
	}

	{
		int i, j;

		for (i = 0; i < nelem(format_cs_table); i++)
		{
			if (format_cs_table[i].format == output_format)
			{
				if (out_cs == CS_UNSET)
					out_cs = format_cs_table[i].default_cs;
				for (j = 0; j < nelem(format_cs_table[i].permitted_cs); j++)
				{
					if (format_cs_table[i].permitted_cs[j] == out_cs)
						break;
				}
				if (j == nelem(format_cs_table[i].permitted_cs))
				{
					fprintf(stderr, "Unsupported colorspace for this format\n");
					exit(1);
				}
			}
		}
	}

	switch (out_cs)
	{
	case CS_MONO:
	case CS_GRAY:
	case CS_GRAY_ALPHA:
		colorspace = fz_device_gray(ctx);
		break;
	case CS_RGB:
	case CS_RGB_ALPHA:
		colorspace = fz_device_rgb(ctx);
		break;
	case CS_CMYK:
	case CS_CMYK_ALPHA:
		colorspace = fz_device_cmyk(ctx);
		break;
	default:
		fprintf(stderr, "Unknown colorspace!\n");
		exit(1);
		break;
	}

	if (output_format == OUT_PDF)
	{
		pdfout = pdf_create_document(ctx);
	}

	timing.count = 0;
	timing.total = 0;
	timing.min = 1 << 30;
	timing.max = 0;
	timing.minpage = 0;
	timing.maxpage = 0;
	timing.minfilename = "";
	timing.maxfilename = "";

	if (output_format == OUT_TEXT || output_format == OUT_HTML || output_format == OUT_STEXT || output_format == OUT_TRACE)
		out = fz_new_output_with_file(ctx, stdout, 0);

	if (output_format == OUT_STEXT || output_format == OUT_TRACE)
		fz_printf(ctx, out, "<?xml version=\"1.0\"?>\n");

	if (output_format == OUT_TEXT || output_format == OUT_HTML || output_format == OUT_STEXT)
		sheet = fz_new_text_sheet(ctx);

	if (output_format == OUT_HTML)
	{
		fz_printf(ctx, out, "<style>\n");
		fz_printf(ctx, out, "body{background-color:gray;margin:12pt;}\n");
		fz_printf(ctx, out, "div.page{background-color:white;margin:6pt;padding:6pt;}\n");
		fz_printf(ctx, out, "div.block{border:1px solid gray;margin:6pt;padding:6pt;}\n");
		fz_printf(ctx, out, "div.metaline{display:table;width:100%%}\n");
		fz_printf(ctx, out, "div.line{display:table-row;padding:6pt}\n");
		fz_printf(ctx, out, "div.cell{display:table-cell;padding-left:6pt;padding-right:6pt}\n");
		fz_printf(ctx, out, "p{margin:0pt;padding:0pt;}\n");
		fz_printf(ctx, out, "</style>\n");
		fz_printf(ctx, out, "<body>\n");
	}

	fz_try(ctx)
	{
		fz_register_document_handlers(ctx);

		while (fz_optind < argc)
		{
			fz_try(ctx)
			{
				filename = argv[fz_optind++];
				files++;

				fz_try(ctx)
				{
					doc = fz_open_document(ctx, filename);
				}
				fz_catch(ctx)
				{
					fz_rethrow_message(ctx, "cannot open document: %s", filename);
				}

				if (fz_needs_password(ctx, doc))
				{
					if (!fz_authenticate_password(ctx, doc, password))
						fz_throw(ctx, FZ_ERROR_GENERIC, "cannot authenticate password: %s", filename);
				}

				fz_layout_document(ctx, doc, layout_w, layout_h, layout_em);

				if (output_format == OUT_STEXT || output_format == OUT_TRACE)
					fz_printf(ctx, out, "<document name=\"%s\">\n", filename);

				if (fz_optind == argc || !isrange(argv[fz_optind]))
					drawrange(ctx, doc, "1-");
				if (fz_optind < argc && isrange(argv[fz_optind]))
					drawrange(ctx, doc, argv[fz_optind++]);

				if (output_format == OUT_STEXT || output_format == OUT_TRACE)
					fz_printf(ctx, out, "</document>\n");

				fz_drop_document(ctx, doc);
				doc = NULL;
			}
			fz_catch(ctx)
			{
				if (!ignore_errors)
					fz_rethrow(ctx);

				fz_drop_document(ctx, doc);
				doc = NULL;
				fz_warn(ctx, "ignoring error in '%s'", filename);
			}
		}
	}
	fz_catch(ctx)
	{
		fz_drop_document(ctx, doc);
		fprintf(stderr, "error: cannot draw '%s'\n", filename);
		errored = 1;
	}

	if (pdfout)
	{
		fz_write_options opts = { 0 };

		pdf_write_document(ctx, pdfout, output, &opts);
		pdf_close_document(ctx, pdfout);
	}

	if (output_format == OUT_HTML)
	{
		fz_printf(ctx, out, "</body>\n");
		fz_printf(ctx, out, "<style>\n");
		fz_print_text_sheet(ctx, out, sheet);
		fz_printf(ctx, out, "</style>\n");
	}

	fz_drop_text_sheet(ctx, sheet);
	fz_drop_output(ctx, out);
	out = NULL;

	if (showtime && timing.count > 0)
	{
		if (files == 1)
		{
			printf("total %dms / %d pages for an average of %dms\n",
				timing.total, timing.count, timing.total / timing.count);
			printf("fastest page %d: %dms\n", timing.minpage, timing.min);
			printf("slowest page %d: %dms\n", timing.maxpage, timing.max);
		}
		else
		{
			printf("total %dms / %d pages for an average of %dms in %d files\n",
				timing.total, timing.count, timing.total / timing.count, files);
			printf("fastest page %d: %dms (%s)\n", timing.minpage, timing.min, timing.minfilename);
			printf("slowest page %d: %dms (%s)\n", timing.maxpage, timing.max, timing.maxfilename);
		}
	}

	fz_drop_context(ctx);

	if (showmemory)
	{
#if defined(_WIN64)
#define FMT "%Iu"
#elif defined(_WIN32)
#define FMT "%u"
#else
#define FMT "%zu"
#endif
		printf("Total memory use = " FMT " bytes\n", memtrace_total);
		printf("Peak memory use = " FMT " bytes\n", memtrace_peak);
		printf("Current memory use = " FMT " bytes\n", memtrace_current);
	}

	return (errored != 0);
}

#ifdef _MSC_VER
int wmain(int argc, wchar_t *wargv[])
{
	char **argv = fz_argv_from_wargv(argc, wargv);
	int ret = main(argc, argv);
	fz_free_argv(argc, argv);
	return ret;
}
#endif
