/*
 * mudraw -- command line tool for drawing and converting documents
 */

#include "mupdf/fitz.h"
#include "mupdf/pdf.h" /* for pdf output */

#ifdef _MSC_VER
#include <winsock2.h>
#include <windows.h>
#define MUDRAW_THREADS 1
#else
#include <sys/time.h>
#ifdef HAVE_PTHREADS
#define MUDRAW_THREADS 2
#include <pthread.h>
#include <semaphore.h>
#endif
#endif

/* Enable for helpful threading debug */
/* #define DEBUG_THREADS(A) do { printf A; fflush(stdout); } while (0) */
#define DEBUG_THREADS(A) do { } while (0)

enum {
	OUT_NONE,
	OUT_PNG, OUT_TGA, OUT_PNM, OUT_PGM, OUT_PPM, OUT_PAM,
	OUT_PBM, OUT_PKM, OUT_PWG, OUT_PCL, OUT_PS,
	OUT_TEXT, OUT_HTML, OUT_STEXT,
	OUT_TRACE, OUT_SVG, OUT_PDF,
	OUT_GPROOF
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
	{ ".pkm", OUT_PKM },
	{ ".svg", OUT_SVG },
	{ ".pwg", OUT_PWG },
	{ ".pcl", OUT_PCL },
	{ ".ps", OUT_PS },
	{ ".pdf", OUT_PDF },
	{ ".tga", OUT_TGA },

	{ ".txt", OUT_TEXT },
	{ ".text", OUT_TEXT },
	{ ".html", OUT_HTML },
	{ ".stext", OUT_STEXT },

	{ ".trace", OUT_TRACE },
	{ ".gproof", OUT_GPROOF },
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
	{ OUT_PKM, CS_CMYK, { CS_CMYK } },
	{ OUT_PWG, CS_RGB, { CS_MONO, CS_GRAY, CS_RGB, CS_CMYK } },
	{ OUT_PCL, CS_MONO, { CS_MONO, CS_RGB } },
	{ OUT_PS, CS_RGB, { CS_GRAY, CS_RGB, CS_CMYK } },
	{ OUT_TGA, CS_RGB, { CS_GRAY, CS_GRAY_ALPHA, CS_RGB, CS_RGB_ALPHA } },

	{ OUT_TRACE, CS_RGB, { CS_RGB } },
	{ OUT_SVG, CS_RGB, { CS_RGB } },
	{ OUT_PDF, CS_RGB, { CS_RGB } },
	{ OUT_GPROOF, CS_RGB, { CS_RGB } },

	{ OUT_TEXT, CS_RGB, { CS_RGB } },
	{ OUT_HTML, CS_RGB, { CS_RGB } },
	{ OUT_STEXT, CS_RGB, { CS_RGB } },
};

/*
	In the presence of pthreads or Windows threads, we can offer
	a multi-threaded option. In the absence, of such, we degrade
	nicely.
*/
#ifdef MUDRAW_THREADS
#if MUDRAW_THREADS == 1

/* Windows threads */
#define SEMAPHORE HANDLE
#define SEMAPHORE_INIT(A) do { A = CreateSemaphore(NULL, 0, 1, NULL); } while (0)
#define SEMAPHORE_FIN(A) do { CloseHandle(A); } while (0)
#define SEMAPHORE_TRIGGER(A) do { (void)ReleaseSemaphore(A, 1, NULL); } while (0) 
#define SEMAPHORE_WAIT(A) do { (void)WaitForSingleObject(A, INFINITE); } while (0)
#define THREAD HANDLE
#define THREAD_INIT(A,B,C) do { A = CreateThread(NULL, 0, B, C, 0, NULL); } while (0)
#define THREAD_FIN(A) do { CloseHandle(A); } while (0)
#define THREAD_RETURN_TYPE DWORD WINAPI
#define THREAD_RETURN() return 0
#define MUTEX CRITICAL_SECTION
#define MUTEX_INIT(A) do { InitializeCriticalSection(&A); } while (0)
#define MUTEX_FIN(A) do { DeleteCriticalSection(&A); } while (0)
#define MUTEX_LOCK(A) do { EnterCriticalSection(&A); } while (0)
#define MUTEX_UNLOCK(A) do { LeaveCriticalSection(&A); } while (0)

#elif MUDRAW_THREADS == 2

/* PThreads */
#define SEMAPHORE sem_t
#define SEMAPHORE_INIT(A) do { (void)sem_init(&A, 0, 0); } while (0)
#define SEMAPHORE_FIN(A) do { (void)sem_destroy(&A); } while (0)
#define SEMAPHORE_TRIGGER(A) do { (void)sem_post(&A); } while (0)
#define SEMAPHORE_WAIT(A) do { (void)sem_wait(&A); } while (0)
#define THREAD pthread_t
#define THREAD_INIT(A,B,C) do { (void)pthread_create(&A, NULL, B, C); } while (0)
#define THREAD_FIN(A) do { void *res; (void)pthread_join(A, &res); } while (0)
#define THREAD_RETURN_TYPE void *
#define THREAD_RETURN() return NULL
#define MUTEX pthread_mutex_t
#define MUTEX_INIT(A) do { (void)pthread_mutex_init(&A, NULL); } while (0)
#define MUTEX_FIN(A) do { (void)pthread_mutex_destroy(&A); } while (0)
#define MUTEX_LOCK(A) do { (void)pthread_mutex_lock(&A); } while (0)
#define MUTEX_UNLOCK(A) do { (void)pthread_mutex_unlock(&A); } while (0)

#else
#error Unknown MUDRAW_THREADS setting
#endif

#define LOCKS_INIT() init_mudraw_locks()
#define LOCKS_FIN() fin_mudraw_locks()

static MUTEX mutexes[FZ_LOCK_MAX];

static void mudraw_lock(void *user, int lock)
{
	MUTEX_LOCK(mutexes[lock]);
}

static void mudraw_unlock(void *user, int lock)
{
	MUTEX_UNLOCK(mutexes[lock]);
}

static fz_locks_context mudraw_locks =
{
	NULL, mudraw_lock, mudraw_unlock
};

static fz_locks_context *init_mudraw_locks(void)
{
	int i;

	for (i = 0; i < FZ_LOCK_MAX; i++)
		MUTEX_INIT(mutexes[i]);

	return &mudraw_locks;
}

static void fin_mudraw_locks(void)
{
	int i;

	for (i = 0; i < FZ_LOCK_MAX; i++)
		MUTEX_FIN(mutexes[i]);
}

#else

/* Null Threads implementation */
#define SEMAPHORE int
#define THREAD int
#define SEMAPHORE_INIT(A) do { A = 0; } while (0)
#define SEMAPHORE_FIN(A) do { A = 0; } while (0)
#define SEMAPHORE_TRIGGER(A) do { A = 0; } while (0)
#define SEMAPHORE_WAIT(A) do { A = 0; } while (0)
#define THREAD_INIT(A,B,C) do { A = 0; (void)C; } while (0)
#define THREAD_FIN(A) do { A = 0; } while (0)
#define LOCKS_INIT() NULL
#define LOCKS_FIN() do { } while (0)

#endif

typedef struct worker_t {
	fz_context *ctx;
	int num;
	int band; /* -1 to shutdown, or band to render */
	int savealpha;
	fz_display_list *list;
	fz_matrix ctm;
	fz_rect tbounds;
	fz_pixmap *pix;
	fz_cookie cookie;
	SEMAPHORE start;
	SEMAPHORE stop;
	THREAD thread;
} worker_t;

static char *output = NULL;
fz_output *out = NULL;
static int output_pagenum = 0;
static int output_append = 0;
static int output_file_per_page = 0;

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
static char *layout_css = NULL;

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
static int lowmemory = 0;

static int errored = 0;
static fz_stext_sheet *sheet = NULL;
static fz_colorspace *colorspace;
static char *filename;
static int files = 0;
static int num_workers = 0;
static worker_t *workers;

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
		"\t\traster: png, tga, pnm, pam, pbm, pkm, pwg, pcl, ps\n"
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
#ifdef MUDRAW_THREADS
		"\t-T -\tnumber of threads to use for rendering (banded mode only)\n"
#endif
		"\n"
		"\t-W -\tpage width for EPUB layout\n"
		"\t-H -\tpage height for EPUB layout\n"
		"\t-S -\tfont size for EPUB layout\n"
		"\t-U -\tfile name of user stylesheet for EPUB layout\n"
		"\n"
		"\t-c -\tcolorspace (mono, gray, grayalpha, rgb, rgba, cmyk, cmykalpha)\n"
		"\t-G -\tapply gamma correction\n"
		"\t-I\tinvert colors\n"
		"\n"
		"\t-A -\tnumber of bits of antialiasing (0 to 8)\n"
		"\t-D\tdisable use of display list\n"
		"\t-i\tignore errors\n"
		"\t-L\tlow memory mode (avoid caching, clear objects after each page)\n"
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

/* Output file level (as opposed to page level) headers */
static void
file_level_headers(fz_context *ctx)
{
	if (output_format == OUT_STEXT || output_format == OUT_TRACE)
		fz_printf(ctx, out, "<?xml version=\"1.0\"?>\n");

	if (output_format == OUT_TEXT || output_format == OUT_HTML || output_format == OUT_STEXT)
		sheet = fz_new_stext_sheet(ctx);

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

	if (output_format == OUT_STEXT || output_format == OUT_TRACE)
		fz_printf(ctx, out, "<document name=\"%s\">\n", filename);

	if (output_format == OUT_PS)
		fz_write_ps_file_header(ctx, out);
}

static void
file_level_trailers(fz_context *ctx)
{
	if (output_format == OUT_STEXT || output_format == OUT_TRACE)
		fz_printf(ctx, out, "</document>\n");

	if (output_format == OUT_HTML)
	{
		fz_printf(ctx, out, "</body>\n");
		fz_printf(ctx, out, "<style>\n");
		fz_print_stext_sheet(ctx, out, sheet);
		fz_printf(ctx, out, "</style>\n");
	}

	if (output_format == OUT_PS)
		fz_write_ps_file_trailer(ctx, out, output_pagenum);

	fz_drop_stext_sheet(ctx, sheet);
}

static void drawband(fz_context *ctx, int savealpha, fz_page *page, fz_display_list *list, const fz_matrix *ctm, const fz_rect *tbounds, fz_cookie *cookie, int band, fz_pixmap *pix)
{
	fz_device *dev = NULL;

	fz_try(ctx)
	{
		if (savealpha)
			fz_clear_pixmap(ctx, pix);
		else
			fz_clear_pixmap_with_value(ctx, pix, 255);

		dev = fz_new_draw_device(ctx, pix);
		if (lowmemory)
			fz_enable_device_hints(ctx, dev, FZ_NO_CACHE);
		if (alphabits == 0)
			fz_enable_device_hints(ctx, dev, FZ_DONT_INTERPOLATE_IMAGES);
		if (list)
			fz_run_display_list(ctx, list, dev, ctm, tbounds, cookie);
		else
			fz_run_page(ctx, page, dev, ctm, cookie);
		fz_drop_device(ctx, dev);
		dev = NULL;

		if (invert)
			fz_invert_pixmap(ctx, pix);
		if (gamma_value != 1)
			fz_gamma_pixmap(ctx, pix, gamma_value);

		if (savealpha)
			fz_unmultiply_pixmap(ctx, pix);
	}
	fz_catch(ctx)
	{
		fz_drop_device(ctx, dev);
		fz_rethrow(ctx);
	}
}

static void drawpage(fz_context *ctx, fz_document *doc, int pagenum)
{
	fz_page *page;
	fz_display_list *list = NULL;
	fz_device *dev = NULL;
	int start;
	fz_cookie cookie = { 0 };
	fz_rect mediabox;
	int first_page = !output_append;

	fz_var(list);
	fz_var(dev);

	if (showtime)
		start = gettime();

	fz_try(ctx)
		page = fz_load_page(ctx, doc, pagenum - 1);
	fz_catch(ctx)
		fz_rethrow_message(ctx, "cannot load page %d in file '%s'", pagenum, filename);

	if (showmd5 || showtime || showfeatures)
		fprintf(stderr, "page %s %d", filename, pagenum);

	fz_bound_page(ctx, page, &mediabox);

	if (output_file_per_page)
	{
		char text_buffer[512];

		fz_drop_output(ctx, out);
		fz_snprintf(text_buffer, sizeof(text_buffer), output, pagenum);
		out = fz_new_output_with_path(ctx, text_buffer, output_append);
		output_append = 1;
	}

	/* Output any file level (as opposed to page level) headers. */
	if (first_page)
		file_level_headers(ctx);

	if (uselist)
	{
		fz_try(ctx)
		{
			list = fz_new_display_list(ctx);
			dev = fz_new_list_device(ctx, list);
			if (lowmemory)
				fz_enable_device_hints(ctx, dev, FZ_NO_CACHE);
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
		if (lowmemory)
			fz_enable_device_hints(ctx, dev, FZ_NO_CACHE);
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
		fprintf(stderr, " %s", iscolor ? "color" : "grayscale");
	}

	if (output_format == OUT_TRACE)
	{
		fz_try(ctx)
		{
			fz_printf(ctx, out, "<page mediabox=\"%g %g %g %g\">\n",
					mediabox.x0, mediabox.y0, mediabox.x1, mediabox.y1);
			dev = fz_new_trace_device(ctx, out);
			if (lowmemory)
				fz_enable_device_hints(ctx, dev, FZ_NO_CACHE);
			if (list)
				fz_run_display_list(ctx, list, dev, &fz_identity, &fz_infinite_rect, &cookie);
			else
				fz_run_page(ctx, page, dev, &fz_identity, &cookie);
			fz_printf(ctx, out, "</page>\n");
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
		fz_stext_page *text = NULL;

		fz_var(text);

		fz_try(ctx)
		{
			text = fz_new_stext_page(ctx);
			dev = fz_new_stext_device(ctx, sheet, text);
			if (lowmemory)
				fz_enable_device_hints(ctx, dev, FZ_NO_CACHE);
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
				fz_print_stext_page_xml(ctx, out, text);
			}
			else if (output_format == OUT_HTML)
			{
				fz_analyze_text(ctx, sheet, text);
				fz_print_stext_page_html(ctx, out, text);
			}
			else if (output_format == OUT_TEXT)
			{
				fz_print_stext_page(ctx, out, text);
				fz_printf(ctx, out, "\f\n");
			}
		}
		fz_always(ctx)
		{
			fz_drop_device(ctx, dev);
			dev = NULL;
			fz_drop_stext_page(ctx, text);
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
		fz_buffer *contents;
		pdf_obj *resources;

		dev = pdf_page_write(ctx, pdfout, &mediabox, &contents, &resources);
		fz_try(ctx)
		{
			pdf_obj *page_obj;

			if (list)
				fz_run_display_list(ctx, list, dev, &fz_identity, NULL, &cookie);
			else
				fz_run_page(ctx, page, dev, &fz_identity, &cookie);

			page_obj = pdf_add_page(ctx, pdfout, &mediabox, rotation, contents, resources);
			pdf_insert_page(ctx, pdfout, -1, page_obj);
			pdf_drop_obj(ctx, page_obj);
		}
		fz_always(ctx)
		{
			pdf_drop_obj(ctx, resources);
			fz_drop_buffer(ctx, contents);
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

	else if (output_format == OUT_SVG)
	{
		float zoom;
		fz_matrix ctm;
		fz_rect bounds, tbounds;
		char buf[512];
		fz_output *out;

		if (!strcmp(output, "-"))
			out = fz_new_output_with_file_ptr(ctx, stdout, 0);
		else
		{
			sprintf(buf, output, pagenum);
			out = fz_new_output_with_path(ctx, buf, 0);
		}

		fz_bound_page(ctx, page, &bounds);
		zoom = resolution / 72;
		fz_pre_rotate(fz_scale(&ctm, zoom, zoom), rotation);
		tbounds = bounds;
		fz_transform_rect(&tbounds, &ctm);

		fz_try(ctx)
		{
			dev = fz_new_svg_device(ctx, out, tbounds.x1-tbounds.x0, tbounds.y1-tbounds.y0);
			if (lowmemory)
				fz_enable_device_hints(ctx, dev, FZ_NO_CACHE);
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
		fz_png_output_context *poc = NULL;
		fz_ps_output_context *psoc = NULL;
		fz_mono_pcl_output_context *pmcoc = NULL;
		fz_color_pcl_output_context *pccoc = NULL;

		fz_var(pix);
		fz_var(poc);
		fz_var(psoc);
		fz_var(pmcoc);
		fz_var(pccoc);

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

		fz_try(ctx)
		{
			int savealpha = (out_cs == CS_GRAY_ALPHA || out_cs == CS_RGB_ALPHA || out_cs == CS_CMYK_ALPHA);
			fz_irect band_ibounds = ibounds;
			int band, bands = 1;
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
				DEBUG_THREADS(("Using %d Bands\n", bands));
			}

			if (num_workers > 0)
			{
				for (band = 0; band < fz_mini(num_workers, bands); band++)
				{
					workers[band].band = band;
					workers[band].savealpha = savealpha; /* Constant on a page */
					workers[band].ctm = ctm;
					workers[band].tbounds = tbounds;
					memset(&workers[band].cookie, 0, sizeof(fz_cookie));
					workers[band].list = list;
					workers[band].pix = fz_new_pixmap_with_bbox(ctx, colorspace, &band_ibounds);
					fz_pixmap_set_resolution(workers[band].pix, resolution);
					DEBUG_THREADS(("Worker %d, Pre-triggering band %d\n", band, band));
					SEMAPHORE_TRIGGER(workers[band].start);
					ctm.f -= drawheight;
				}
				pix = workers[0].pix;
			}
			else
			{
				pix = fz_new_pixmap_with_bbox(ctx, colorspace, &band_ibounds);
				fz_pixmap_set_resolution(pix, resolution);
			}

			/* Output any page level headers (for banded formats) */
			if (output)
			{
				if (output_format == OUT_PGM || output_format == OUT_PPM || output_format == OUT_PNM)
					fz_write_pnm_header(ctx, out, pix->w, totalheight, pix->n);
				else if (output_format == OUT_PAM)
					fz_write_pam_header(ctx, out, pix->w, totalheight, pix->n, savealpha);
				else if (output_format == OUT_PNG)
					poc = fz_write_png_header(ctx, out, pix->w, totalheight, pix->n, savealpha);
				else if (output_format == OUT_PBM)
					fz_write_pbm_header(ctx, out, pix->w, totalheight);
				else if (output_format == OUT_PKM)
					fz_write_pkm_header(ctx, out, pix->w, totalheight);
				else if (output_format == OUT_PS)
					psoc = fz_write_ps_header(ctx, out, pix->w, totalheight, pix->n, pix->xres, pix->yres, ++output_pagenum);
				else if (output_format == OUT_PCL)
				{
					if (out_cs == CS_MONO)
						pmcoc = fz_write_mono_pcl_header(ctx, out, pix->w, totalheight, pix->xres, pix->yres, ++output_pagenum, NULL);
					else
						pccoc = fz_write_color_pcl_header(ctx, out, pix->w, totalheight, pix->n, pix->xres, pix->yres, ++output_pagenum, NULL);
				}
			}

			for (band = 0; band < bands; band++)
			{
				if (num_workers > 0)
				{
					worker_t *w = &workers[band % num_workers];
					DEBUG_THREADS(("Waiting for worker %d to complete band %d\n", w->num, band));
					SEMAPHORE_WAIT(w->stop);
					pix = w->pix;
					cookie.errors += w->cookie.errors;
				}
				else
					drawband(ctx, savealpha, page, list, &ctm, &tbounds, &cookie, band, pix);

				if (output)
				{
					if (output_format == OUT_PGM || output_format == OUT_PPM || output_format == OUT_PNM)
						fz_write_pnm_band(ctx, out, pix->w, totalheight, pix->n, band, drawheight, pix->samples);
					else if (output_format == OUT_PAM)
						fz_write_pam_band(ctx, out, pix->w, totalheight, pix->n, band, drawheight, pix->samples, savealpha);
					else if (output_format == OUT_PNG)
						fz_write_png_band(ctx, out, poc, pix->w, totalheight, pix->n, band, drawheight, pix->samples, savealpha);
					else if (output_format == OUT_PWG)
						fz_write_pixmap_as_pwg(ctx, out, pix, NULL);
					else if (output_format == OUT_PCL)
					{
						if (out_cs == CS_MONO)
						{
							fz_bitmap *bit = fz_new_bitmap_from_pixmap_band(ctx, pix, NULL, band, bandheight);
							fz_write_mono_pcl_band(ctx, out, pmcoc, bit);
							fz_drop_bitmap(ctx, bit);
						}
						else
							fz_write_color_pcl_band(ctx, out, pccoc, pix->w, totalheight, pix->n, band, drawheight, pix->samples);
					}
					else if (output_format == OUT_PS)
						fz_write_ps_band(ctx, out, psoc, pix->w, totalheight, pix->n, band, drawheight, pix->samples);
					else if (output_format == OUT_PBM) {
						fz_bitmap *bit = fz_new_bitmap_from_pixmap_band(ctx, pix, NULL, band, bandheight);
						fz_write_pbm_band(ctx, out, bit);
						fz_drop_bitmap(ctx, bit);
					}
					else if (output_format == OUT_PKM) {
						fz_bitmap *bit = fz_new_bitmap_from_pixmap_band(ctx, pix, NULL, band, bandheight);
						fz_write_pkm_band(ctx, out, bit);
						fz_drop_bitmap(ctx, bit);
					}
					else if (output_format == OUT_TGA)
					{
						fz_write_pixmap_as_tga(ctx, out, pix, savealpha);
					}
				}

				if (num_workers > 0 && band + num_workers < bands)
				{
					worker_t *w = &workers[band % num_workers];
					w->band = band + num_workers;
					w->ctm = ctm;
					w->tbounds = tbounds;
					memset(&w->cookie, 0, sizeof(fz_cookie));
					DEBUG_THREADS(("Triggering worker %d for band %d\n", w->num, w->band));
					SEMAPHORE_TRIGGER(w->start);
				}
				ctm.f -= drawheight;
			}

			/* FIXME */
			if (showmd5)
			{
				unsigned char digest[16];
				int i;

				fz_md5_pixmap(ctx, pix, digest);
				fprintf(stderr, " ");
				for (i = 0; i < 16; i++)
					fprintf(stderr, "%02x", digest[i]);
			}

			/* Any page level trailers go here */
			if (output)
			{
				if (output_format == OUT_PNG)
					fz_write_png_trailer(ctx, out, poc);
				if (output_format == OUT_PS)
					fz_write_ps_trailer(ctx, out, psoc);
				if (output_format == OUT_PCL)
				{
					if (out_cs == CS_MONO)
						fz_write_mono_pcl_trailer(ctx, out, pmcoc);
					else
						fz_write_color_pcl_trailer(ctx, out, pccoc);
				}
			}
		}
		fz_always(ctx)
		{
			fz_drop_device(ctx, dev);
			dev = NULL;
			if (num_workers > 0)
			{
				int band;
				for (band = 0; band < num_workers; band++)
					fz_drop_pixmap(ctx, workers[band].pix);
			}
			else
				fz_drop_pixmap(ctx, pix);
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

	if (!output_append)
		file_level_trailers(ctx);

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

		fprintf(stderr, " %dms", diff);
	}

	if (showmd5 || showtime || showfeatures)
		fprintf(stderr, "\n");

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

#ifdef MUDRAW_THREADS
static THREAD_RETURN_TYPE worker_thread(void *arg)
{
	worker_t *me = (worker_t *)arg;

	do
	{
		DEBUG_THREADS(("Worker %d waiting\n", me->num));
		SEMAPHORE_WAIT(me->start);
		DEBUG_THREADS(("Worker %d woken for band %d\n", me->num, me->band));
		if (me->band >= 0)
			drawband(me->ctx, me->savealpha, NULL, me->list, &me->ctm, &me->tbounds, &me->cookie, me->band, me->pix);
		DEBUG_THREADS(("Worker %d completed band %d\n", me->num, me->band));
		SEMAPHORE_TRIGGER(me->stop);
	}
	while (me->band >= 0);
	THREAD_RETURN();
}
#endif

#ifdef MUDRAW_STANDALONE
int main(int argc, char **argv)
#else
int mudraw_main(int argc, char **argv)
#endif
{
	char *password = "";
	fz_document *doc = NULL;
	int c, i;
	fz_context *ctx;
	fz_alloc_context alloc_ctx = { NULL, trace_malloc, trace_realloc, trace_free };

	fz_var(doc);

	while ((c = fz_getopt(argc, argv, "p:o:F:R:r:w:h:fB:c:G:I:s:A:DiW:H:S:T:U:Lv")) != -1)
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
		case 'U': layout_css = fz_optarg; break;

		case 's':
			if (strchr(fz_optarg, 't')) ++showtime;
			if (strchr(fz_optarg, 'm')) ++showmemory;
			if (strchr(fz_optarg, 'f')) ++showfeatures;
			if (strchr(fz_optarg, '5')) ++showmd5;
			break;

		case 'A': alphabits = atoi(fz_optarg); break;
		case 'D': uselist = 0; break;
		case 'i': ignore_errors = 1; break;

		case 'T':
#ifdef MUDRAW_THREADS
			num_workers = atoi(fz_optarg); break;
#else
			fprintf(stderr, "Threads not enabled in this build\n");
			break;
#endif
		case 'L': lowmemory = 1; break;

		case 'v': fprintf(stderr, "mudraw version %s\n", FZ_VERSION); return 1;
		}
	}

	if (fz_optind == argc)
		usage();

	if (num_workers > 0)
	{
		if (uselist == 0)
		{
			fprintf(stderr, "cannot use multiple threads without using display list\n");
			exit(1);
		}

		if (bandheight == 0)
		{
			fprintf(stderr, "Using multiple threads without banding is pointless\n");
		}
	}

	ctx = fz_new_context((showmemory == 0 ? NULL : &alloc_ctx), LOCKS_INIT(), (lowmemory ? 1 : FZ_STORE_DEFAULT));
	if (!ctx)
	{
		fprintf(stderr, "cannot initialise context\n");
		exit(1);
	}

	if (num_workers > 0)
	{
		workers = fz_calloc(ctx, num_workers, sizeof(*workers));
		for (i = 0; i < num_workers; i++)
		{
			workers[i].ctx = fz_clone_context(ctx);
			workers[i].num = i;
			SEMAPHORE_INIT(workers[i].start);
			SEMAPHORE_INIT(workers[i].stop);
			THREAD_INIT(workers[i].thread, worker_thread, &workers[i]);
		}
	}

	fz_set_aa_level(ctx, alphabits);

	if (layout_css)
	{
		fz_buffer *buf = fz_read_file(ctx, layout_css);
		fz_write_buffer_byte(ctx, buf, 0);
		fz_set_user_css(ctx, (char*)buf->data);
		fz_drop_buffer(ctx, buf);
	}

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
		if (output_format != OUT_PAM && output_format != OUT_PGM && output_format != OUT_PPM && output_format != OUT_PNM && output_format != OUT_PNG && output_format != OUT_PBM && output_format != OUT_PKM && output_format != OUT_PCL && output_format != OUT_PS)
		{
			fprintf(stderr, "Banded operation only possible with PAM, PBM, PGM, PKM, PPM, PNM, PCL, PS and PNG outputs\n");
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
	else if (output_format == OUT_GPROOF)
	{
		/* GPROOF files are saved direct. Do not open "output". */
	}
	else if (output && (output[0] != '-' || output[1] != 0) && *output != 0)
	{
		if (has_percent_d(output))
			output_file_per_page = 1;
		else
			out = fz_new_output_with_path(ctx, output, 0);
	}
	else
		out = fz_new_output_with_file_ptr(ctx, stdout, 0);

	timing.count = 0;
	timing.total = 0;
	timing.min = 1 << 30;
	timing.max = 0;
	timing.minpage = 0;
	timing.maxpage = 0;
	timing.minfilename = "";
	timing.maxfilename = "";

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

				if (output_format == OUT_GPROOF)
				{
					fz_save_gproof(ctx, filename, doc, output, resolution, "", "");
				}
				else
				{
					if (fz_optind == argc || !isrange(argv[fz_optind]))
						drawrange(ctx, doc, "1-");
					if (fz_optind < argc && isrange(argv[fz_optind]))
						drawrange(ctx, doc, argv[fz_optind++]);
				}

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

	if (output_append)
		file_level_trailers(ctx);

	if (output_format == OUT_PDF)
	{
		if (!output)
			output = "out.pdf";
		pdf_save_document(ctx, pdfout, output, NULL);
		pdf_drop_document(ctx, pdfout);
	}
	else if (output_format == OUT_GPROOF)
	{
		/* No output file to close */
	}
	else
	{
		fz_drop_output(ctx, out);
		out = NULL;
	}

	if (showtime && timing.count > 0)
	{
		if (files == 1)
		{
			fprintf(stderr, "total %dms / %d pages for an average of %dms\n",
				timing.total, timing.count, timing.total / timing.count);
			fprintf(stderr, "fastest page %d: %dms\n", timing.minpage, timing.min);
			fprintf(stderr, "slowest page %d: %dms\n", timing.maxpage, timing.max);
		}
		else
		{
			fprintf(stderr, "total %dms / %d pages for an average of %dms in %d files\n",
				timing.total, timing.count, timing.total / timing.count, files);
			fprintf(stderr, "fastest page %d: %dms (%s)\n", timing.minpage, timing.min, timing.minfilename);
			fprintf(stderr, "slowest page %d: %dms (%s)\n", timing.maxpage, timing.max, timing.maxfilename);
		}
	}

	if (num_workers > 0)
	{
		for (i = 0; i < num_workers; i++)
		{
			workers[i].band = -1;
			SEMAPHORE_TRIGGER(workers[i].start);
			SEMAPHORE_WAIT(workers[i].stop);
			SEMAPHORE_FIN(workers[i].start);
			SEMAPHORE_FIN(workers[i].stop);
			fz_drop_context(workers[i].ctx);
			THREAD_FIN(workers[i].thread);
		}
		fz_free(ctx, workers);
	}

	fz_drop_context(ctx);
	LOCKS_FIN();

	if (showmemory)
	{
#if defined(_WIN64)
#define FMT "%Iu"
#elif defined(_WIN32)
#define FMT "%u"
#else
#define FMT "%zu"
#endif
		fprintf(stderr, "Total memory use = " FMT " bytes\n", memtrace_total);
		fprintf(stderr, "Peak memory use = " FMT " bytes\n", memtrace_peak);
		fprintf(stderr, "Current memory use = " FMT " bytes\n", memtrace_current);
	}

	return (errored != 0);
}
