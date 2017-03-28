#include "mupdf/fitz.h"

#if FZ_ENABLE_GPRF
/* Choose whether to call gs via an exe or via an API */
#if defined(__ANDROID__) || defined(GSVIEW_WIN)
#define USE_GS_API
#endif
/* GSVIEW on Windows does not support stdout stderr */
#ifdef GSVIEW_WIN
#define GS_API_NULL_STDIO
#endif

#include "mupdf/fitz.h"

#if defined(USE_GS_API)

/* We are assumed to be using the DLL here */
#define GSDLLEXPORT
#ifdef _MSC_VER
#define GSDLLAPI __stdcall
#else
#define GSDLLAPI
#endif

#ifndef GSDLLCALL
#define GSDLLCALL
#endif

/*
	We can either rely on the official iapi.h from ghostscript
	(which is not supplied in the MuPDF source), or we can use
	a potted version of it inline here (which suffices for
	android, but has not been verified on all platforms).
*/
#if HAVE_IAPI_H
#include "iapi.h"
#else
/* Avoid having to #include the gs api */
extern GSDLLEXPORT int GSDLLAPI gsapi_new_instance(void **, void *);
extern GSDLLEXPORT int GSDLLAPI gsapi_init_with_args(void *, int, char *argv[]);
extern GSDLLEXPORT void GSDLLAPI gsapi_delete_instance(void *);
extern GSDLLEXPORT int GSDLLAPI gsapi_set_stdio(void *, int (GSDLLCALL *)(void *, char *, int), int (GSDLLCALL *)(void *, const char *, int), int (GSDLLCALL *)(void *, const char *, int));
#endif /* HAVE_IAPI_H */
#endif /* USE_GS_API */

typedef struct gprf_document_s gprf_document;
typedef struct gprf_chapter_s gprf_chapter;
typedef struct gprf_page_s gprf_page;

/* Quality trumps speed for this file */
#ifndef SLOWCMYK
#define SLOWCMYK
#endif

enum
{
	GPRF_TILESIZE = 256
};

struct gprf_document_s
{
	fz_document super;
	char *gprf_filename;
	char *pdf_filename;
	char *print_profile;
	char *display_profile;
	int res;
	int num_pages;
	struct {
		int w;
		int h;
	} *page_dims;
};

typedef struct gprf_file_s
{
	int refs;
	char *filename;
} gprf_file;

static gprf_file *
fz_new_gprf_file(fz_context *ctx, char *filename)
{
	gprf_file *file = fz_malloc_struct(ctx, gprf_file);
	file->refs = 1;
	file->filename = filename;

	return file;
}

static gprf_file *
fz_keep_gprf_file(fz_context *ctx, gprf_file *file)
{
	return fz_keep_imp(ctx, file, &file->refs);
}

static void
fz_drop_gprf_file(fz_context *ctx, gprf_file *file)
{
	if (fz_drop_imp(ctx, file, &file->refs))
	{
		unlink(file->filename);
		fz_free(ctx, file->filename);
		fz_free(ctx, file);
	}
}

struct gprf_page_s
{
	fz_page super;
	gprf_document *doc;
	gprf_file *file;
	int number;
	fz_separations *separations;
	int width;
	int height;
	int tile_width;
	int tile_height;
	int num_tiles;
	fz_image **tiles;
};

typedef struct fz_image_gprf_s
{
	fz_image super;
	fz_off_t offset[FZ_MAX_SEPARATIONS+3+1]; /* + RGB + END */
	gprf_file *file;
	fz_separations *separations;
} fz_image_gprf;

static int
gprf_count_pages(fz_context *ctx, fz_document *doc_)
{
	gprf_document *doc = (gprf_document*)doc_;
	return doc->num_pages;
}

static void
gprf_drop_page_imp(fz_context *ctx, fz_page *page_)
{
	gprf_page *page = (gprf_page*)page_;
	gprf_document *doc = page->doc;
	int i;

	fz_drop_document(ctx, &doc->super);
	if (page->tiles)
	{
		for (i = 0; i < page->num_tiles; i++)
			fz_drop_image(ctx, page->tiles[i]);
		fz_free(ctx, page->tiles);
	}
	fz_drop_separations(ctx, page->separations);
	fz_drop_gprf_file(ctx, page->file);
}

static fz_rect *
gprf_bound_page(fz_context *ctx, fz_page *page_, fz_rect *bbox)
{
	gprf_page *page = (gprf_page*)page_;
	gprf_document *doc = page->doc;

	/* BBox is in points, not pixels */
	bbox->x0 = 0;
	bbox->y0 = 0;
	bbox->x1 = 72.0 * page->width / doc->res;
	bbox->y1 = 72.0 * page->height / doc->res;

	return bbox;
}

static void
fz_drop_image_gprf_imp(fz_context *ctx, fz_storable *image_)
{
	fz_image_gprf *image = (fz_image_gprf *)image_;

	fz_drop_gprf_file(ctx, image->file);
	fz_drop_separations(ctx, image->separations);
}

static inline unsigned char *cmyk_to_rgba(unsigned char *out, uint32_t c, uint32_t m, uint32_t y, uint32_t k)
{
	/* c m y k in 0 to 65535 range on entry */
	uint32_t r, g, b;
#ifdef SLOWCMYK /* FP version originally from poppler */
	uint32_t x;
	uint32_t cm, c1m, cm1, c1m1;
	uint32_t c1m1y, c1m1y1, c1my, c1my1, cm1y, cm1y1, cmy, cmy1;

	/* We use some tricks here:
	 *	x + (x >> 15)
	 * converts x from 0..65535 to 0..65536
	 *	(A * B) >> 16
	 * multiplies A (0..65535) and B (0..65536) to give a 0...65535 result.
	 * (This relies on A and B being unsigned).
	 *
	 * We also rely on the fact that if:
	 *	C = (A * B) >> 16
	 * for A (0..65535) and B (0..65536) then A - C is also in (0..65535)
	 * as C cannot possibly be any larger than A.
	 */
	cm = (c * (m + (m>>15)))>>16;
	c1m = m - cm;
	cm1 = c - cm;
	c1m1 = 65535 - m - cm1; /* Need to clamp for underflow here */
	if ((int)c1m1 < 0)
		c1m1 = 0;
	y += (y>>15);
	c1m1y = (c1m1 * y)>>16;
	c1m1y1 = c1m1 - c1m1y;
	c1my = (c1m * y)>>16;
	c1my1 = c1m - c1my;
	cm1y = (cm1 * y)>>16;
	cm1y1 = cm1 - cm1y;
	cmy = (cm * y)>>16;
	cmy1 = cm - cmy;

#define CONST16(x) ((int)(x * 65536.0 + 0.5))

	k += (k>>15); /* Move k to be 0..65536 */

	/* this is a matrix multiplication, unrolled for performance */
	x = (c1m1y1 * k)>>16;	/* 0 0 0 1 */
	r = g = b = c1m1y1 - x;	/* 0 0 0 0 */
	r += (CONST16(0.1373) * x)>>16;
	g += (CONST16(0.1216) * x)>>16;
	b += (CONST16(0.1255) * x)>>16;

	x = (c1m1y * k)>>16;	/* 0 0 1 1 */
	r += (CONST16(0.1098) * x)>>16;
	g += (CONST16(0.1020) * x)>>16;
	x = c1m1y - x;		/* 0 0 1 0 */
	r += x;
	g += (CONST16(0.9490) * x)>>16;

	x = (c1my1 * k)>>16;	/* 0 1 0 1 */
	r += (CONST16(0.1412) * x)>>16;
	x = c1my1 - x;		/* 0 1 0 0 */
	r += (CONST16(0.9255) * x)>>16;
	b += (CONST16(0.5490) * x)>>16;

	x = (c1my * k)>>16;	/* 0 1 1 1 */
	r += (CONST16(0.1333) * x)>>16;
	x = c1my - x;		/* 0 1 1 0 */
	r += (CONST16(0.9294) * x)>>16;
	g += (CONST16(0.1098) * x)>>16;
	b += (CONST16(0.1412) * x)>>16;

	x = (cm1y1 * k)>>16;	/* 1 0 0 1 */
	g += (CONST16(0.0588) * x)>>16;
	b += (CONST16(0.1412) * x)>>16;
	x = cm1y1 - x;		/* 1 0 0 0 */
	g += (CONST16(0.6784) * x)>>16;
	b += (CONST16(0.9373) * x)>>16;

	x = (cm1y * k)>>16;	/* 1 0 1 1 */
	g += (CONST16(0.0745) * x)>>16;
	x = cm1y - x;		/* 1 0 1 0 */
	g += (CONST16(0.6510) * x)>>16;
	b += (CONST16(0.3137) * x)>>16;

	x = (cmy1 * k)>>16;	/* 1 1 0 1 */
	b += (CONST16(0.0078) * x)>>16;
	x = cmy1 - x;		/* 1 1 0 0 */
	r += (CONST16(0.1804) * x)>>16;
	g += (CONST16(0.1922) * x)>>16;
	b += (CONST16(0.5725) * x)>>16;

	x = (cmy * (65536-k))>>16;	/* 1 1 1 0 */
	r += (CONST16(0.2118) * x)>>16;
	g += (CONST16(0.2119) * x)>>16;
	b += (CONST16(0.2235) * x)>>16;
	/* I have convinced myself that r, g, b cannot have underflowed at
	 * thus point. I have not convinced myself that they won't have
	 * overflowed though. */
	r >>= 8;
	if (r > 255)
		r = 255;
	g >>= 8;
	if (g > 255)
		g = 255;
	b >>= 8;
	if (b > 255)
		b = 255;
#else
	k = 65536 - k;
	r = k - c;
	g = k - m;
	b = k - y;

	r >>= 8;
	if ((int)r < 0)
		r = 0;
	else if (r > 255)
		r = 255;
	g >>= 8;
	if ((int)g < 0)
		g = 0;
	else if (g > 255)
		g = 255;
	b >>= 8;
	if ((int)b < 0)
		b = 0;
	else if (b > 255)
		b = 255;
#endif

	*out++ = r;
	*out++ = g;
	*out++ = b;
	*out++ = 0xFF;
	return out;
}

unsigned char undelta(unsigned char delta, unsigned char *ptr, int len)
{
	do
	{
		delta = (*ptr++ += delta);
	}
	while (--len);

	return delta;
}

static fz_pixmap *
gprf_get_pixmap(fz_context *ctx, fz_image *image_, fz_irect *area, int w, int h, int *l2factor)
{
	/* The file contains RGB + up to FZ_MAX_SEPARATIONS. Hence the
	 * "3 + FZ_MAX_SEPARATIONS" usage in all the arrays below. */
	fz_image_gprf *image = (fz_image_gprf *)image_;
	fz_pixmap *pix = fz_new_pixmap(ctx, image->super.colorspace, image->super.w, image->super.h, 1);
	fz_stream *file[3 + FZ_MAX_SEPARATIONS] = { NULL };
	int read_sep[3 + FZ_MAX_SEPARATIONS] = { 0 };
	int num_seps, i, j, n;
	enum { decode_chunk_size = 64 };
	unsigned char data[(3 + FZ_MAX_SEPARATIONS) * decode_chunk_size];
	unsigned char delta[3 + FZ_MAX_SEPARATIONS] = { 0 };
	unsigned char equiv[3 + FZ_MAX_SEPARATIONS][4];
	int bytes_per_channel = image->super.w * image->super.h;
	unsigned char *out = fz_pixmap_samples(ctx, pix);

	fz_var(file);

	if (area)
	{
		area->x0 = 0;
		area->y0 = 0;
		area->x1 = image->super.w;
		area->y1 = image->super.h;
	}

	fz_try(ctx)
	{
		/* First off, figure out if we are doing RGB or separations
		 * decoding. */
		num_seps = 3 + fz_count_separations(ctx, image->separations);
		if (fz_separations_all_enabled(ctx, image->separations))
		{
			num_seps = 3;
			for (i = 0; i < 3; i++)
				read_sep[i] = 1;
		}
		else
		{
			for (i = 3; i < num_seps; i++)
			{
				read_sep[i] = !fz_separation_disabled(ctx, image->separations, i-3);
				if (read_sep[i])
				{
					uint32_t rgb, cmyk;

					(void)fz_get_separation(ctx, image->separations, i - 3, &rgb, &cmyk);
					equiv[i][0] = (cmyk>> 0) & 0xFF;
					equiv[i][1] = (cmyk>> 8) & 0xFF;
					equiv[i][2] = (cmyk>>16) & 0xFF;
					equiv[i][3] = (cmyk>>24) & 0xFF;
				}
			}
		}

		/* Open 1 file handle per channel */
		for (i = 0; i < num_seps; i++)
		{
			if (!read_sep[i])
				continue;

			if (image->offset[i] == image->offset[i+1])
			{
				read_sep[i] = 2;
				memset(&data[i * decode_chunk_size], 0, decode_chunk_size);
			}
			file[i] = fz_open_file(ctx, image->file->filename);
			fz_seek(ctx, file[i], image->offset[i], SEEK_SET);
			file[i] = fz_open_flated(ctx, file[i], 15);
		}

		/* Now actually do the decode */
		for (j = 0; j < bytes_per_channel; j += decode_chunk_size)
		{
			int len = bytes_per_channel - j;
			if (len > decode_chunk_size)
				len = decode_chunk_size;

			/* Load data with the unpacked channel bytes */
			for (i = 0; i < num_seps; i++)
			{
				if (read_sep[i] == 1)
				{
					fz_read(ctx, file[i], &data[i * decode_chunk_size], len);
					delta[i] = undelta(delta[i], &data[i * decode_chunk_size], len);
				}
			}

			/* And unpack */
			if (num_seps == 3)
			{
				for (n = 0; n < len; n++)
				{
					*out++ = data[0 * decode_chunk_size + n];
					*out++ = data[1 * decode_chunk_size + n];
					*out++ = data[2 * decode_chunk_size + n];
					*out++ = 0xFF; /* Alpha */
				}
			}
			else
			{
				for (n = 0; n < len; n++)
				{
					int c, m, y, k;

					c = m = y = k = 0;
					for (i = 3; i < num_seps; i++)
					{
						int v;
						if (read_sep[i] != 1)
							continue;
						v = data[i * decode_chunk_size + n];
						v += (v>>7);
						c += v * equiv[i][0];
						m += v * equiv[i][1];
						y += v * equiv[i][2];
						k += v * equiv[i][3];
					}
					out = cmyk_to_rgba(out, c, m, y, k);
				}
			}
		}
	}
	fz_always(ctx)
	{
		for (i = 0; i < 3+num_seps; i++)
			fz_drop_stream(ctx, file[i]);
	}
	fz_catch(ctx)
	{
		fz_drop_pixmap(ctx, pix);
		fz_rethrow(ctx);
	}

	return pix;
}

static fz_image *
fz_new_gprf_image(fz_context *ctx, gprf_page *page, int imagenum, fz_off_t offsets[], fz_off_t end)
{
	fz_image_gprf *image = fz_malloc_struct(ctx, fz_image_gprf);
	int tile_x = imagenum % page->tile_width;
	int tile_y = imagenum / page->tile_width;
	int w = GPRF_TILESIZE;
	int h = GPRF_TILESIZE;
	int seps = fz_count_separations(ctx, page->separations);

	if (tile_x == page->tile_width-1)
	{
		w = page->width % GPRF_TILESIZE;
		if (w == 0)
			w = GPRF_TILESIZE;
	}
	if (tile_y == page->tile_height-1)
	{
		h = page->height % GPRF_TILESIZE;
		if (h == 0)
			h = GPRF_TILESIZE;
	}

	FZ_INIT_KEY_STORABLE(&image->super, 1, fz_drop_image_gprf_imp);
	image->super.w = w;
	image->super.h = h;
	image->super.n = 4; /* Always RGB + Alpha */
	image->super.colorspace = fz_keep_colorspace(ctx, fz_device_rgb(ctx));
	image->super.bpc = 8;
	image->super.get_pixmap = gprf_get_pixmap;
	image->super.xres = page->doc->res;
	image->super.yres = page->doc->res;
	image->super.mask = NULL;
	image->file = fz_keep_gprf_file(ctx, page->file);
	memcpy(image->offset, offsets, sizeof(fz_off_t) * (3+seps));
	image->offset[seps+3] = end;
	image->separations = fz_keep_separations(ctx, page->separations);

	return &image->super;
}

#ifndef USE_GS_API
static void
fz_system(fz_context *ctx, const char *cmd)
{
	int ret = system(cmd);

	if (ret != 0)
		fz_throw(ctx, FZ_ERROR_GENERIC, "child process reported error %d", ret);
}
#endif

static int GSDLLCALL
gsdll_stdout(void *instance, const char *str, int len)
{
#ifndef GS_API_NULL_STDIO
	int remain = len;
	char text[32];

	while (remain)
	{
		int l = remain;
		if (l > sizeof(text)-1)
			l = sizeof(text)-1;
		memcpy(text, str, l);
		text[l] = 0;
		fprintf(stdout, "%s", text);
		remain -= l;
		str += l;
	}
#endif
	return len;
}

static int GSDLLCALL
gsdll_stderr(void *instance, const char *str, int len)
{
#ifndef GS_API_NULL_STDIO
	int remain = len;
	char text[32];

	while (remain)
	{
		int l = remain;
		if (l > sizeof(text)-1)
			l = sizeof(text)-1;
		memcpy(text, str, l);
		text[l] = 0;
		fprintf(stderr, "%s", text);
		remain -= l;
		str += l;
	}
#endif
	return len;
}

static void
generate_page(fz_context *ctx, gprf_page *page)
{
	gprf_document *doc = page->doc;
	char nameroot[32];
	char *filename;
	char *disp_profile = NULL;
	char *print_profile = NULL;
	int len;

	/* put the page file in the same directory as the gproof file */
	sprintf(nameroot, "gprf_%d_", page->number);
	filename = fz_tempfilename(ctx, nameroot, doc->gprf_filename);

/*
	When invoking gs via the GS API, we need to give the profile
	names unquoted. When invoking via system, we need to quote them.
	Use a #define to keep the code simple.
*/
#ifdef USE_GS_API
#define QUOTE
#else
#define QUOTE "\""
#endif

	/* Set up the icc profiles */
	if (strlen(doc->display_profile) == 0)
	{
		len = sizeof("-sPostRenderProfile=srgb.icc");
		disp_profile = (char*)fz_malloc(ctx, len + 1);
		sprintf(disp_profile, "-sPostRenderProfile=srgb.icc");
	}
	else
	{
		len = sizeof("-sPostRenderProfile=" QUOTE QUOTE); /* with quotes */
		disp_profile = (char*)fz_malloc(ctx, len + strlen(doc->display_profile) + 1);
		sprintf(disp_profile, "-sPostRenderProfile=" QUOTE "%s" QUOTE, doc->display_profile);
	}

	if (strlen(doc->print_profile) == 0)
	{
		len = sizeof("-sOutputICCProfile=default_cmyk.icc");
		print_profile = (char*)fz_malloc(ctx, len + 1);
		sprintf(print_profile, "-sOutputICCProfile=default_cmyk.icc");
	}
	else if (strcmp(doc->print_profile, "<EMBEDDED>") != 0)
	{
		len = sizeof("-sOutputICCProfile=" QUOTE QUOTE); /* with quotes */
		print_profile = (char*)fz_malloc(ctx, len + strlen(doc->print_profile) + 1);
		sprintf(print_profile, "-sOutputICCProfile=" QUOTE "%s" QUOTE, doc->print_profile);
	}

	fz_try(ctx)
	{
#ifdef USE_GS_API
		void *instance;
		int code;
		char *argv[20];
		char arg_fp[32];
		char arg_lp[32];
		char arg_g[32];
		int argc = 0;

		argv[argc++] = "gs";
		argv[argc++] = "-sDEVICE=gprf";
		if (print_profile == NULL)
			argv[argc++] = "-dUsePDFX3Profile";
		else
			argv[argc++] = print_profile;
		argv[argc++] = disp_profile;
		argv[argc++] = "-dFitPage";
		argv[argc++] = "-o";
		argv[argc++] = filename;
		sprintf(arg_fp, "-dFirstPage=%d", page->number+1);
		argv[argc++] = arg_fp;
		sprintf(arg_lp, "-dLastPage=%d", page->number+1);
		argv[argc++] = arg_lp;
		argv[argc++] = "-I%rom%Resource/Init/";
		sprintf(arg_g, "-g%dx%d", page->width, page->height);
		argv[argc++] = arg_g;
		argv[argc++] = doc->pdf_filename;
		assert(argc <= sizeof(argv)/sizeof(*argv));

		code = gsapi_new_instance(&instance, ctx);
		if (code < 0)
			fz_throw(ctx, FZ_ERROR_GENERIC, "GS startup failed: %d", code);
		gsapi_set_stdio(instance, NULL, gsdll_stdout, gsdll_stderr);
#ifndef NDEBUG
		{
			int i;
			fprintf(stderr, "Invoking GS\n");
			for (i = 0; i < argc; i++)
			{
				fprintf(stderr, "%s\n", argv[i]);
			}
		}
#endif
		code = gsapi_init_with_args(instance, argc, argv);

		gsapi_delete_instance(instance);
		if (code < 0)
			fz_throw(ctx, FZ_ERROR_GENERIC, "GS run failed: %d", code);
#else
		char gs_command[1024];
		/* Invoke gs to convert to a temp file. */
		sprintf(gs_command, "gswin32c.exe -sDEVICE=gprf %s %s -dFitPage -o \"%s\" -dFirstPage=%d -dLastPage=%d -I%%rom%%Resource/Init/ -g%dx%d \"%s\"",
			print_profile == NULL ? "-dUsePDFX3Profile" : print_profile, disp_profile,
			filename, page->number+1, page->number+1, page->width, page->height, doc->pdf_filename);
		fz_system(ctx, gs_command);
#endif

		page->file = fz_new_gprf_file(ctx, filename);
	}
	fz_always(ctx)
	{
		fz_free(ctx, print_profile);
		fz_free(ctx, disp_profile);
	}
	fz_catch(ctx)
	{
		unlink(filename);
		fz_free(ctx, filename);
		fz_rethrow(ctx);
	}
}

static void
read_tiles(fz_context *ctx, gprf_page *page)
{
	fz_stream *file;
	int32_t val;
	uint64_t offset;
	int num_tiles;
	int num_seps;
	int i, x, y;
	int64_t off;

	/* Clear up any aborted attempts before (unlikely) */
	fz_drop_separations(ctx, page->separations);
	page->separations = NULL;

	file = fz_open_file(ctx, page->file->filename);

	fz_try(ctx)
	{
		val = fz_read_int32_le(ctx, file);
		if (val != 0x46505347)
			fz_throw(ctx, FZ_ERROR_GENERIC, "Unexpected signature in GSPF file");

		val = fz_read_int16_le(ctx, file);
		if (val != 1)
			fz_throw(ctx, FZ_ERROR_GENERIC, "Unexpected version in GSPF file");

		val = fz_read_int16_le(ctx, file);
		if (val != 0)
			fz_throw(ctx, FZ_ERROR_GENERIC, "Unexpected compression in GSPF file");

		val = fz_read_int32_le(ctx, file);
		if (val != page->width)
			fz_throw(ctx, FZ_ERROR_GENERIC, "Unexpected width in GSPF file");

		val = fz_read_int32_le(ctx, file);
		if (val != page->height)
			fz_throw(ctx, FZ_ERROR_GENERIC, "Unexpected height in GSPF file");

		val = fz_read_int16_le(ctx, file);
		if (val != 8)
			fz_throw(ctx, FZ_ERROR_GENERIC, "Unexpected bpc in GSPF file");

		num_seps = fz_read_int16_le(ctx, file);
		if (num_seps < 0 || num_seps > FZ_MAX_SEPARATIONS)
			fz_throw(ctx, FZ_ERROR_GENERIC, "Unexpected number of separations in GSPF file");

		offset = fz_read_int64_le(ctx, file); /* Ignore the ICC for now */

		/* Read the table offset */
		offset = fz_read_int64_le(ctx, file);

		/* Skip to the separations */
		fz_seek(ctx, file, 64, SEEK_SET);
		page->separations = fz_new_separations(ctx);
		for (i = 0; i < num_seps; i++)
		{
			char blatter[4096];
			int32_t rgba = fz_read_int32_le(ctx, file);
			int32_t cmyk = fz_read_int32_le(ctx, file);
			fz_read_string(ctx, file, blatter, sizeof(blatter));
			fz_add_separation(ctx, page->separations, rgba, cmyk, blatter);
		}

		/* Seek to the image data */
		fz_seek(ctx, file, (fz_off_t)offset, SEEK_SET);

		num_tiles = page->tile_width * page->tile_height;
		page->tiles = fz_calloc(ctx, num_tiles, sizeof(fz_image *));

		i = 0;
		off = fz_read_int64_le(ctx, file);
		for (y = 0; y < page->tile_height; y++)
		{
			for (x = 0; x < page->tile_width; x++)
			{
				fz_off_t offsets[FZ_MAX_SEPARATIONS + 3]; /* SEPARATIONS + RGB */
				int j;

				for (j = 0; j < num_seps+3; j++)
				{
					offsets[j] = (fz_off_t)off;
					off = fz_read_int64_le(ctx, file);
				}

				page->tiles[i] = fz_new_gprf_image(ctx, page, i, offsets, (fz_off_t)off);
				i++;
			}
		}
	}
	fz_always(ctx)
	{
		fz_drop_stream(ctx, file);
	}
	fz_catch(ctx)
	{
		/* Free any tiles made so far */
		for (i = num_tiles - 1; i >= 0; i--)
		{
			fz_drop_image(ctx, page->tiles[i]);
		}
		fz_free(ctx, page->tiles);

		fz_rethrow(ctx);
	}
	page->num_tiles = num_tiles;
}

static void
gprf_run_page(fz_context *ctx, fz_page *page_, fz_device *dev, const fz_matrix *ctm, fz_cookie *cookie)
{
	gprf_page *page = (gprf_page*)page_;
	gprf_document *doc = page->doc;
	int i, y, x;

	/* If we have no page, generate it. */
	if (page->file == NULL)
	{
		generate_page(ctx, page);
	}
	/* If we have no tiles, generate them. */
	if (page->num_tiles == 0)
	{
		read_tiles(ctx, page);
	}

	/* Send the images to the page */
	fz_render_flags(ctx, dev, FZ_DEVFLAG_GRIDFIT_AS_TILED, 0);
	i = 0;
	for (y = 0; y < page->tile_height; y++)
	{
		double scale = GPRF_TILESIZE * 72.0 / doc->res;
		for (x = 0; x < page->tile_width; x++)
		{
			fz_matrix local;
			double scale_x = page->tiles[i]->w * 72.0 / doc->res;
			double scale_y = page->tiles[i]->h * 72.0 / doc->res;
			local.a = scale_x;
			local.b = 0;
			local.c = 0;
			local.d = scale_y;
			local.e = x * scale;
			local.f = y * scale;
			fz_concat(&local, &local, ctm);
			fz_fill_image(ctx, dev, page->tiles[i++], &local, 1.0);
		}
	}
	fz_render_flags(ctx, dev, 0, FZ_DEVFLAG_GRIDFIT_AS_TILED);
}

static int gprf_count_separations(fz_context *ctx, fz_page *page_)
{
	gprf_page *page = (gprf_page *)page_;

	return fz_count_separations(ctx, page->separations);
}

static void gprf_control_separation(fz_context *ctx, fz_page *page_, int sep, int disable)
{
	gprf_page *page = (gprf_page *)page_;

	fz_control_separation(ctx, page->separations, sep, disable);
}

static int gprf_separation_disabled(fz_context *ctx, fz_page *page_, int sep)
{
	gprf_page *page = (gprf_page *)page_;

	return fz_separation_disabled(ctx, page->separations, sep);
}

static const char *gprf_get_separation(fz_context *ctx, fz_page *page_, int sep, uint32_t *rgba, uint32_t*cmyk)
{
	gprf_page *page = (gprf_page *)page_;

	return fz_get_separation(ctx, page->separations, sep, rgba, cmyk);
}

static fz_page *
gprf_load_page(fz_context *ctx, fz_document *doc_, int number)
{
	gprf_document *doc = (gprf_document*)doc_;
	gprf_page *page = fz_new_page(ctx, gprf_page);

	fz_try(ctx)
	{
		page->super.bound_page = gprf_bound_page;
		page->super.run_page_contents = gprf_run_page;
		page->super.drop_page = gprf_drop_page_imp;
		page->super.count_separations = gprf_count_separations;
		page->super.control_separation = gprf_control_separation;
		page->super.separation_disabled = gprf_separation_disabled;
		page->super.get_separation = gprf_get_separation;
		page->doc = (gprf_document *)fz_keep_document(ctx, &doc->super);
		page->number = number;
		page->separations = fz_new_separations(ctx);
		page->width = doc->page_dims[number].w;
		page->height = doc->page_dims[number].h;
		page->tile_width = (page->width + GPRF_TILESIZE-1)/GPRF_TILESIZE;
		page->tile_height = (page->height + GPRF_TILESIZE-1)/GPRF_TILESIZE;
	}
	fz_catch(ctx)
	{
		fz_drop_page(ctx, &page->super);
		fz_rethrow(ctx);
	}

	return (fz_page*)page;
}

static void
gprf_close_document(fz_context *ctx, fz_document *doc_)
{
	gprf_document *doc = (gprf_document*)doc_;

	fz_free(ctx, doc->page_dims);
	fz_free(ctx, doc->pdf_filename);
	fz_free(ctx, doc->gprf_filename);
	fz_free(ctx, doc->print_profile);
	fz_free(ctx, doc->display_profile);
}

static int
gprf_lookup_metadata(fz_context *ctx, fz_document *doc, const char *key, char *buf, int size)
{
	if (!strcmp(key, "format"))
		return (int)fz_snprintf(buf, size, "GPROOF");

	return -1;
}

static fz_document *
gprf_open_document_with_stream(fz_context *ctx, fz_stream *file)
{
	gprf_document *doc;

	doc = fz_new_document(ctx, gprf_document);
	doc->super.drop_document = gprf_close_document;
	doc->super.count_pages = gprf_count_pages;
	doc->super.load_page = gprf_load_page;
	doc->super.lookup_metadata = gprf_lookup_metadata;

	fz_try(ctx)
	{
		int32_t val;
		int i;
		char buf[4096];

		val = fz_read_int32_le(ctx, file);
		if (val != 0x4f525047)
			fz_throw(ctx, FZ_ERROR_GENERIC, "Invalid file signature in gproof file");
		val = fz_read_byte(ctx, file);
		val |= fz_read_byte(ctx, file)<<8;
		if (val != 1)
			fz_throw(ctx, FZ_ERROR_GENERIC, "Invalid version in gproof file");
		doc->res = fz_read_int32_le(ctx, file);
		if (doc->res < 0)
			fz_throw(ctx, FZ_ERROR_GENERIC, "Invalid resolution in gproof file");
		doc->num_pages = fz_read_int32_le(ctx, file);
		if (doc->num_pages < 0)
			fz_throw(ctx, FZ_ERROR_GENERIC, "Invalid resolution in gproof file");
		doc->page_dims = fz_calloc(ctx, doc->num_pages, sizeof(*doc->page_dims));

		for (i = 0; i < doc->num_pages; i++)
		{
			doc->page_dims[i].w = fz_read_int32_le(ctx, file);
			doc->page_dims[i].h = fz_read_int32_le(ctx, file);
		}
		fz_read_string(ctx, file, buf, sizeof(buf));
		doc->pdf_filename = fz_strdup(ctx, buf);
		fz_read_string(ctx, file, buf, sizeof(buf));
		doc->print_profile = fz_strdup(ctx, buf);
		fz_read_string(ctx, file, buf, sizeof(buf));
		doc->display_profile = fz_strdup(ctx, buf);
	}
	fz_catch(ctx)
	{
		fz_drop_document(ctx, &doc->super);
		fz_rethrow(ctx);
	}

	return (fz_document*)doc;
}

static fz_document *
gprf_open_document(fz_context *ctx, const char *filename)
{
	fz_stream *file = fz_open_file(ctx, filename);
	fz_document *doc;
	gprf_document *gdoc;

	fz_try(ctx)
	{
		doc = gprf_open_document_with_stream(ctx, file);
		gdoc = (gprf_document *)doc;
		gdoc->gprf_filename = fz_strdup(ctx,filename);
	}
	fz_always(ctx)
	{
		fz_drop_stream(ctx, file);
	}
	fz_catch(ctx)
	{
		fz_rethrow(ctx);
	}
	return doc;
}

static const char *gprf_extensions[] =
{
	"gproof",
	NULL
};

static const char *gprf_mimetypes[] =
{
	"application/x-ghostproof",
	NULL
};

fz_document_handler gprf_document_handler =
{
	NULL,
	gprf_open_document,
	gprf_open_document_with_stream,
	gprf_extensions,
	gprf_mimetypes
};
#endif
