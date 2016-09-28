#include "mupdf/fitz.h"

struct info
{
	fz_colorspace *cs;
	int width, height;
	int maxval, bitdepth;
	int depth, alpha;
	char *tupletype;
};

static inline int iswhiteeol(int a)
{
	switch (a) {
	case ' ': case '\t': case '\r': case '\n':
		return 1;
	}
	return 0;
}

static inline int iswhite(int a)
{
	switch (a) {
	case ' ': case '\t':
		return 1;
	}
	return 0;
}

static inline int iseol(int a)
{
	switch (a) {
	case '\r': case '\n':
		return 1;
	}
	return 0;
}

static inline int bitdepth_from_maxval(int maxval)
{
	int depth = 0;
	while (maxval)
	{
		maxval >>= 1;
		depth++;
	}
	return depth;
}

static unsigned char *
pnm_read_white(fz_context *ctx, unsigned char *p, unsigned char *e, int single_line)
{
	if (e - p < 1)
		fz_throw(ctx, FZ_ERROR_GENERIC, "cannot parse whitespace in pnm image");

	if (single_line)
	{
		if (!iswhiteeol(*p) && *p != '#')
			fz_throw(ctx, FZ_ERROR_GENERIC, "expected whitespace/comment in pnm image");
		while (p < e && iswhite(*p))
			p++;

		if (p < e && *p == '#')
			while (p < e && !iseol(*p))
				p++;
		if (p < e && iseol(*p))
			p++;
	}
	else
	{
		if (!iswhiteeol(*p) && *p != '#')
			fz_throw(ctx, FZ_ERROR_GENERIC, "expected whitespace in pnm image");
		while (p < e && iswhiteeol(*p))
			p++;

		while (p < e && *p == '#')
		{
			while (p < e && !iseol(*p))
				p++;

			if (p < e && iseol(*p))
				p++;

			while (p < e && iswhiteeol(*p))
				p++;

			if (p < e && iseol(*p))
				p++;
		}

	}

	return p;
}

static unsigned char *
pnm_read_signature(fz_context *ctx, unsigned char *p, unsigned char *e, char *signature)
{
	if (e - p < 2)
		fz_throw(ctx, FZ_ERROR_GENERIC, "cannot parse magic number in pnm image");
	if (p[0] != 'P' || p[1] < '1' || p[1] > '7')
		fz_throw(ctx, FZ_ERROR_GENERIC, "expected signature in pnm image");

	signature[0] = *p++;
	signature[1] = *p++;
	return p;
}

static unsigned char *
pnm_read_number(fz_context *ctx, unsigned char *p, unsigned char *e, int *number)
{
	if (e - p < 1)
		fz_throw(ctx, FZ_ERROR_GENERIC, "cannot parse number in pnm image");
	if (*p < '0' && *p > '9')
		fz_throw(ctx, FZ_ERROR_GENERIC, "expected numeric field in pnm image");

	while (p < e && *p >= '0' && *p <= '9')
	{
		*number = *number * 10 + *p - '0';
		p++;
	}

	return p;
}

static unsigned char *
pnm_read_string(fz_context *ctx, unsigned char *p, unsigned char *e, char **out)
{
	unsigned char *s;

	if (e - p < 1)
		fz_throw(ctx, FZ_ERROR_GENERIC, "cannot parse string in pnm image");

	s = p;
	while (!iswhiteeol(*p))
		p++;

	*out = fz_malloc(ctx, p - s + 1);
	memcpy(*out, s, p - s);
	(*out)[p - s] = '\0';

	return p;
}

static int
map_color(fz_context *ctx, int color, int inmax, int outmax)
{
	float f = (float) color / inmax;
	return f * outmax;
}

static fz_pixmap *
pnm_ascii_read_image(fz_context *ctx, struct info *pnm, unsigned char *p, unsigned char *e, int onlymeta, int bitmap)
{
	fz_pixmap *img = NULL;

	p = pnm_read_number(ctx, p, e, &pnm->width);
	p = pnm_read_white(ctx, p, e, 0);

	if (bitmap)
	{
		p = pnm_read_number(ctx, p, e, &pnm->height);
		p = pnm_read_white(ctx, p, e, 1);
		pnm->maxval = 1;
	}
	else
	{
		p = pnm_read_number(ctx, p, e, &pnm->height);
		p = pnm_read_white(ctx, p, e, 0);
		p = pnm_read_number(ctx, p, e, &pnm->maxval);
		p = pnm_read_white(ctx, p, e, 0);
	}

	if (pnm->maxval <= 0 || pnm->maxval >= 65536)
		fz_throw(ctx, FZ_ERROR_GENERIC, "maximum sample value of out range in pnm image: %d", pnm->maxval);

	pnm->bitdepth = bitdepth_from_maxval(pnm->maxval);

	if (pnm->height <= 0)
		fz_throw(ctx, FZ_ERROR_GENERIC, "image height must be > 0");
	if (pnm->width <= 0)
		fz_throw(ctx, FZ_ERROR_GENERIC, "image width must be > 0");
	if (pnm->height > UINT_MAX / pnm->width / fz_colorspace_n(ctx, pnm->cs) / (pnm->bitdepth / 8 + 1))
		fz_throw(ctx, FZ_ERROR_GENERIC, "image too large");

	if (!onlymeta)
	{
		unsigned char *dp;
		int x, y, k;
		int w, h, n;

		img = fz_new_pixmap(ctx, pnm->cs, pnm->width, pnm->height, 0);
		dp = img->samples;

		w = img->w;
		h = img->h;
		n = img->n;

		if (bitmap)
		{
			for (y = 0; y < h; y++)
			{
				for (x = 0; x < w; x++)
				{
					int v = 0;
					p = pnm_read_number(ctx, p, e, &v);
					p = pnm_read_white(ctx, p, e, 0);
					*dp++ = v ? 0x00 : 0xff;
				}
			}
		}
		else
		{
			for (y = 0; y < h; y++)
				for (x = 0; x < w; x++)
					for (k = 0; k < n; k++)
					{
						int v = 0;
						p = pnm_read_number(ctx, p, e, &v);
						p = pnm_read_white(ctx, p, e, 0);
						v = fz_clampi(v, 0, pnm->maxval);
						*dp++ = map_color(ctx, v, pnm->maxval, 255);
					}
		}

	}

	return img;
}

static fz_pixmap *
pnm_binary_read_image(fz_context *ctx, struct info *pnm, unsigned char *p, unsigned char *e, int onlymeta, int bitmap)
{
	fz_pixmap *img = NULL;

	p = pnm_read_number(ctx, p, e, &pnm->width);
	p = pnm_read_white(ctx, p, e, 0);

	if (bitmap)
	{
		p = pnm_read_number(ctx, p, e, &pnm->height);
		p = pnm_read_white(ctx, p, e, 1);
		pnm->maxval = 1;
	}
	else
	{
		p = pnm_read_number(ctx, p, e, &pnm->height);
		p = pnm_read_white(ctx, p, e, 0);
		p = pnm_read_number(ctx, p, e, &pnm->maxval);
		p = pnm_read_white(ctx, p, e, 1);
	}

	if (pnm->maxval <= 0 || pnm->maxval >= 65536)
		fz_throw(ctx, FZ_ERROR_GENERIC, "maximum sample value of out range in pnm image: %d", pnm->maxval);

	pnm->bitdepth = bitdepth_from_maxval(pnm->maxval);

	if (pnm->height <= 0)
		fz_throw(ctx, FZ_ERROR_GENERIC, "image height must be > 0");
	if (pnm->width <= 0)
		fz_throw(ctx, FZ_ERROR_GENERIC, "image width must be > 0");
	if (pnm->height > UINT_MAX / pnm->width / fz_colorspace_n(ctx, pnm->cs) / (pnm->bitdepth / 8 + 1))
		fz_throw(ctx, FZ_ERROR_GENERIC, "image too large");

	if (!onlymeta)
	{
		unsigned char *dp;
		int x, y, k;
		int w, h, n;

		img = fz_new_pixmap(ctx, pnm->cs, pnm->width, pnm->height, 0);
		dp = img->samples;

		w = img->w;
		h = img->h;
		n = img->n;

		if (pnm->maxval == 255)
			memcpy(dp, p, w * h * n);
		else if (bitmap)
		{
			for (y = 0; y < h; y++)
			{
				for (x = 0; x < w; x++)
				{
					*dp++ = (*p & (1 << (7 - (x & 0x7)))) ? 0xff : 0x00;
					if ((x & 0x7) == 7)
						p++;
				}
				if (w & 0x7)
					p++;
			}
		}
		else if (pnm->maxval < 255)
		{
			for (y = 0; y < h; y++)
				for (x = 0; x < w; x++)
					for (k = 0; k < n; k++)
						*dp++ = map_color(ctx, *p++, pnm->maxval, 255);
		}
		else
		{
			for (y = 0; y < h; y++)
				for (x = 0; x < w; x++)
					for (k = 0; k < n; k++)
					{
						*dp++ = map_color(ctx, (p[0] << 8) | p[1], pnm->maxval, 255);
						p += 2;
					}
		}
	}

	return img;
}

static unsigned char *
pam_binary_read_header(fz_context *ctx, struct info *pnm, unsigned char *p, unsigned char *e)
{
	char *token = fz_strdup(ctx, "");

	fz_try(ctx)
	{
		while (p < e && strcmp(token, "ENDHDR"))
		{
			fz_free(ctx, token);
			p = pnm_read_string(ctx, p, e, &token);
			p = pnm_read_white(ctx, p, e, 0);
			if (!strcmp(token, "WIDTH"))
				p = pnm_read_number(ctx, p, e, &pnm->width);
			else if (!strcmp(token, "HEIGHT"))
				p = pnm_read_number(ctx, p, e, &pnm->height);
			else if (!strcmp(token, "DEPTH"))
				p = pnm_read_number(ctx, p, e, &pnm->depth);
			else if (!strcmp(token, "MAXVAL"))
				p = pnm_read_number(ctx, p, e, &pnm->maxval);
			else if (!strcmp(token, "TUPLTYPE"))
				p = pnm_read_string(ctx, p, e, &pnm->tupletype);
			else if (strcmp(token, "ENDHDR"))
				fz_throw(ctx, FZ_ERROR_GENERIC, "unknown header token in pnm image");

			if (strcmp(token, "ENDHDR"))
				p = pnm_read_white(ctx, p, e, 0);
		}
	}
	fz_always(ctx)
	{
		fz_free(ctx, token);
	}
	fz_catch(ctx)
	{
		fz_rethrow(ctx);
	}

	return p;
}

static fz_pixmap *
pam_binary_read_image(fz_context *ctx, struct info *pnm, unsigned char *p, unsigned char *e, int onlymeta)
{
	fz_pixmap *img = NULL;
	int bitmap = 0;
	int minval = 1;
	int maxval = 65535;

	p = pam_binary_read_header(ctx, pnm, p, e);

	if (pnm->tupletype == NULL)
		switch (pnm->depth)
		{
		case 1: pnm->tupletype = fz_strdup(ctx, "BLACKANDWHITE"); break;
		case 2: pnm->tupletype = fz_strdup(ctx, "GRAYSCALE_ALPHA"); break;
		case 3: pnm->tupletype = fz_strdup(ctx, "RGB"); break;
		case 4: pnm->tupletype = fz_strdup(ctx, "CMYK"); break;
		case 5: pnm->tupletype = fz_strdup(ctx, "CMYK_ALPHA"); break;
		default:
			fz_throw(ctx, FZ_ERROR_GENERIC, "cannot guess tupletype based on depth in pnm image");
		}

	if (!strcmp(pnm->tupletype, "BLACKANDWHITE"))
	{
		pnm->cs = fz_device_gray(ctx);
		maxval = 1;
		if (pnm->maxval == 1)
			bitmap = 1;
	}
	else if (!strcmp(pnm->tupletype, "GRAYSCALE"))
	{
		pnm->cs = fz_device_gray(ctx);
		minval = 2;
	}
	else if (!strcmp(pnm->tupletype, "GRAYSCALE_ALPHA"))
	{
		pnm->cs = fz_device_gray(ctx);
		pnm->alpha = 1;
		minval = 2;
	}
	else if (!strcmp(pnm->tupletype, "RGB"))
	{
		pnm->cs = fz_device_rgb(ctx);
	}
	else if (!strcmp(pnm->tupletype, "RGB_ALPHA"))
	{
		pnm->cs = fz_device_rgb(ctx);
		pnm->alpha = 1;
	}
	else if (!strcmp(pnm->tupletype, "CMYK"))
	{
		pnm->cs = fz_device_cmyk(ctx);
	}
	else if (!strcmp(pnm->tupletype, "CMYK_ALPHA"))
	{
		pnm->cs = fz_device_cmyk(ctx);
		pnm->alpha = 1;
	}
	else
	{
		fz_free(ctx, pnm->tupletype);
		fz_throw(ctx, FZ_ERROR_GENERIC, "unsupported tupletype");
	}

	fz_free(ctx, pnm->tupletype);

	if (pnm->depth != fz_colorspace_n(ctx, pnm->cs) + pnm->alpha)
		fz_throw(ctx, FZ_ERROR_GENERIC, "depth out of tuple type range");
	if (pnm->maxval < minval || pnm->maxval > maxval)
		fz_throw(ctx, FZ_ERROR_GENERIC, "maxval out of range");

	pnm->bitdepth = bitdepth_from_maxval(pnm->maxval);

	if (pnm->height <= 0)
		fz_throw(ctx, FZ_ERROR_GENERIC, "image height must be > 0");
	if (pnm->width <= 0)
		fz_throw(ctx, FZ_ERROR_GENERIC, "image width must be > 0");
	if (pnm->height > UINT_MAX / pnm->width / fz_colorspace_n(ctx, pnm->cs) / (pnm->bitdepth / 8 + 1))
		fz_throw(ctx, FZ_ERROR_GENERIC, "image too large");

	if (!onlymeta)
	{
		unsigned char *dp;
		int x, y, k;
		int w, h, n;

		img = fz_new_pixmap(ctx, pnm->cs, pnm->width, pnm->height, pnm->alpha);
		dp = img->samples;

		w = img->w;
		h = img->h;
		n = img->n;

		if (e - p < w * h * n * (pnm->maxval < 256 ? 1 : 2))
			fz_throw(ctx, FZ_ERROR_GENERIC, "truncated image");

		if (pnm->maxval == 255)
			memcpy(dp, p, w * h * n);
		else if (bitmap)
		{
			for (y = 0; y < h; y++)
				for (x = 0; x < w; x++)
					for (k = 0; k < n; k++)
						*dp++ = *p++ ? 0x00 : 0xff;
		}
		else if (pnm->maxval < 255)
		{
			for (y = 0; y < h; y++)
				for (x = 0; x < w; x++)
					for (k = 0; k < n; k++)
						*dp++ = map_color(ctx, *p++, pnm->maxval, 255);
		}
		else
		{
			for (y = 0; y < h; y++)
				for (x = 0; x < w; x++)
					for (k = 0; k < n; k++)
					{
						*dp++ = map_color(ctx, (p[0] << 8) | p[1], pnm->maxval, 255);
						p += 2;
					}
		}
	}

	return img;
}

static fz_pixmap *
pnm_read_image(fz_context *ctx, struct info *pnm, unsigned char *p, size_t total, int onlymeta)
{
	unsigned char *e = p + total;
	char signature[3] = { 0 };

	p = pnm_read_signature(ctx, p, e, signature);
	p = pnm_read_white(ctx, p, e, 0);

	if (!strcmp(signature, "P1"))
	{
		pnm->cs = fz_device_gray(ctx);
		return pnm_ascii_read_image(ctx, pnm, p, e, onlymeta, 1);
	}
	else if (!strcmp(signature, "P2"))
	{
		pnm->cs = fz_device_gray(ctx);
		return pnm_ascii_read_image(ctx, pnm, p, e, onlymeta, 0);
	}
	else if (!strcmp(signature, "P3"))
	{
		pnm->cs = fz_device_rgb(ctx);
		return pnm_ascii_read_image(ctx, pnm, p, e, onlymeta, 0);
	}
	else if (!strcmp(signature, "P4"))
	{
		pnm->cs = fz_device_gray(ctx);
		return pnm_binary_read_image(ctx, pnm, p, e, onlymeta, 1);
	}
	else if (!strcmp(signature, "P5"))
	{
		pnm->cs = fz_device_gray(ctx);
		return pnm_binary_read_image(ctx, pnm, p, e, onlymeta, 0);
	}
	else if (!strcmp(signature, "P6"))
	{
		pnm->cs = fz_device_rgb(ctx);
		return pnm_binary_read_image(ctx, pnm, p, e, onlymeta, 0);
	}
	else if (!strcmp(signature, "P7"))
		return pam_binary_read_image(ctx, pnm, p, e, onlymeta);
	else
		fz_throw(ctx, FZ_ERROR_GENERIC, "unsupported portable anymap signature (0x%02x, 0x%02x)", signature[0], signature[1]);
}

fz_pixmap *
fz_load_pnm(fz_context *ctx, unsigned char *p, size_t total)
{
	fz_pixmap *img;
	struct info pnm = { 0 };

	fz_try(ctx)
		img = pnm_read_image(ctx, &pnm, p, total, 0);
	fz_always(ctx)
		fz_drop_colorspace(ctx, pnm.cs);
	fz_catch(ctx)
		fz_rethrow(ctx);

	return img;
}

void
fz_load_pnm_info(fz_context *ctx, unsigned char *p, size_t total, int *wp, int *hp, int *xresp, int *yresp, fz_colorspace **cspacep)
{
	struct info pnm = { 0 };

	fz_try(ctx)
	{
		pnm_read_image(ctx, &pnm, p, total, 1);
		*cspacep = pnm.cs;
		*wp = pnm.width;
		*hp = pnm.height;
		*xresp = 72;
		*yresp = 72;
	}
	fz_always(ctx)
		fz_drop_colorspace(ctx, pnm.cs);
	fz_catch(ctx)
		fz_rethrow(ctx);
}
