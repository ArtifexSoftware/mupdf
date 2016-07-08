#include "mupdf/fitz.h"

struct info
{
	fz_colorspace *cs;
	int width, height;
	int maxval, depth;
	int alpha;
	char *tupletype;
};

/* TODO: parse PAM */

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
		if (pnm->maxval < 0 || pnm->maxval >= 65536)
			fz_throw(ctx, FZ_ERROR_GENERIC, "maximum sample value of out range in pnm image: %d", pnm->maxval);
	}

	if (!onlymeta)
	{
		unsigned char *dp;
		int x, y, k;

		img = fz_new_pixmap(ctx, pnm->cs, pnm->width, pnm->height, 0);
		dp = img->samples;

		if (bitmap)
		{
			for (y = 0; y < pnm->height; y++)
			{
				for (x = 0; x < pnm->width; x++)
				{
					int v = 0;
					p = pnm_read_number(ctx, p, e, &v);
					p = pnm_read_white(ctx, p, e, 0);
					if (v == 0)
						*dp = 0x00;
					else
						*dp = 0xff;

					dp++;
				}
			}
		}
		else
		{
			for (y = 0; y < pnm->height; y++)
				for (x = 0; x < pnm->width; x++)
					for (k = 0; k < img->colorspace->n; k++)
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
		if (pnm->maxval < 0 || pnm->maxval >= 65536)
			fz_throw(ctx, FZ_ERROR_GENERIC, "maximum sample value of out range in pnm image: %d", pnm->maxval);
	}

	if (!onlymeta)
	{
		unsigned char *dp;
		int x, y, k;

		img = fz_new_pixmap(ctx, pnm->cs, pnm->width, pnm->height, 0);
		dp = img->samples;

		if (bitmap)
		{
			for (y = 0; y < pnm->height; y++)
			{
				for (x = 0; x < pnm->width; x++)
				{
					if (*p & (1 << (7 - (x & 0x7))))
						*dp = 0x00;
					else
						*dp = 0xff;

					dp++;
					if ((x & 0x7) == 7)
						p++;
				}
				if (pnm->width & 0x7)
					p++;
			}
		}
		else
		{
			if (pnm->maxval == 255)
			{
				for (y = 0; y < pnm->height; y++)
					for (x = 0; x < pnm->width; x++)
						for (k = 0; k < img->colorspace->n; k++)
							*dp++ = *p++;
			}
			else if (pnm->maxval < 256)
			{
				for (y = 0; y < pnm->height; y++)
					for (x = 0; x < pnm->width; x++)
						for (k = 0; k < img->colorspace->n; k++)
							*dp++ = map_color(ctx, *p++, pnm->maxval, 255);
			}
			else
			{
				for (y = 0; y < pnm->height; y++)
					for (x = 0; x < pnm->width; x++)
						for (k = 0; k < img->colorspace->n; k++)
						{
							*dp++ = map_color(ctx, (p[0] << 8) | p[1], pnm->maxval, 255);
							p += 2;
						}
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
		if (pnm->depth != 1)
			fz_throw(ctx, FZ_ERROR_GENERIC, "depth out of range for b/w pnm image");
		if (pnm->maxval == 1)
			bitmap = 1;
		else if (pnm->maxval < 2 || pnm->maxval > 65535)
			fz_throw(ctx, FZ_ERROR_GENERIC, "maxval out of range for grayscale pnm image");

		pnm->cs = fz_device_gray(ctx);
	}
	else if (!strcmp(pnm->tupletype, "GRAYSCALE"))
	{
		if (pnm->maxval < 2 || pnm->maxval > 65535)
			fz_throw(ctx, FZ_ERROR_GENERIC, "maxval out of range for grayscale pnm image");
		if (pnm->depth != 1)
			fz_throw(ctx, FZ_ERROR_GENERIC, "depth out of range for grayscale pnm image");
		pnm->cs = fz_device_gray(ctx);
	}
	else if (!strcmp(pnm->tupletype, "GRAYSCALE_ALPHA"))
	{
		if (pnm->maxval < 2 || pnm->maxval > 65535)
			fz_throw(ctx, FZ_ERROR_GENERIC, "maxval out of range for grayscale pnm image with alpha");
		if (pnm->depth != 2)
			fz_throw(ctx, FZ_ERROR_GENERIC, "depth out of range for grayscale pnm image with alpha");
		pnm->cs = fz_device_gray(ctx);
		pnm->alpha = 1;
	}
	else if (!strcmp(pnm->tupletype, "RGB"))
	{
		if (pnm->maxval < 1 || pnm->maxval > 65535)
			fz_throw(ctx, FZ_ERROR_GENERIC, "maxval out of range for rgb pnm image");
		if (pnm->depth != 3)
			fz_throw(ctx, FZ_ERROR_GENERIC, "depth out of range for rgb pnm image");
		pnm->cs = fz_device_rgb(ctx);
	}
	else if (!strcmp(pnm->tupletype, "RGB_ALPHA"))
	{
		if (pnm->maxval < 1 || pnm->maxval > 65535)
			fz_throw(ctx, FZ_ERROR_GENERIC, "maxval out of range for rgb pnm image with alpha");
		if (pnm->depth != 4)
			fz_throw(ctx, FZ_ERROR_GENERIC, "depth out of range for rgb pnm image with alpha");
		pnm->cs = fz_device_rgb(ctx);
		pnm->alpha = 1;
	}
	else if (!strcmp(pnm->tupletype, "CMYK"))
	{
		if (pnm->maxval < 1 || pnm->maxval > 65535)
			fz_throw(ctx, FZ_ERROR_GENERIC, "maxval out of range for cmyk pnm image");
		if (pnm->depth != 4)
			fz_throw(ctx, FZ_ERROR_GENERIC, "depth out of range for cmyk pnm image");
		pnm->cs = fz_device_cmyk(ctx);
	}
	else if (!strcmp(pnm->tupletype, "CMYK_ALPHA"))
	{
		if (pnm->maxval < 1 || pnm->maxval > 65535)
			fz_throw(ctx, FZ_ERROR_GENERIC, "maxval out of range for cmyk pnm image with alpha");
		if (pnm->depth != 5)
			fz_throw(ctx, FZ_ERROR_GENERIC, "depth out of range for cmyk pnm image with alpha");
		pnm->cs = fz_device_cmyk(ctx);
		pnm->alpha = 1;
	}
	else
	{
		fz_free(ctx, pnm->tupletype);
		fz_throw(ctx, FZ_ERROR_GENERIC, "unsupported tupletype");
	}

	fz_free(ctx, pnm->tupletype);

	if (!onlymeta)
	{
		unsigned char *dp;
		int x, y, k;

		img = fz_new_pixmap(ctx, pnm->cs, pnm->width, pnm->height, pnm->alpha);
		dp = img->samples;

		if (bitmap)
		{
			if (e - p < pnm->height * pnm->width * img->n)
				fz_throw(ctx, FZ_ERROR_GENERIC, "truncated image");

			for (y = 0; y < pnm->height; y++)
				for (x = 0; x < pnm->width; x++)
					for (k = 0; k < img->colorspace->n; k++)
					{
						if (*p)
							*dp = 0x00;
						else
							*dp = 0xff;
						dp++;
						p++;
					}
		}
		else
		{
			if (pnm->maxval == 255)
			{
				if (e - p < pnm->height * pnm->width * img->n)
					fz_throw(ctx, FZ_ERROR_GENERIC, "truncated image");

				for (y = 0; y < pnm->height; y++)
					for (x = 0; x < pnm->width; x++)
						for (k = 0; k < img->n; k++)
							*dp++ = *p++;
			}
			else if (pnm->maxval < 256)
			{
				if (e - p < pnm->height * pnm->width * img->n)
					fz_throw(ctx, FZ_ERROR_GENERIC, "truncated image");

				for (y = 0; y < pnm->height; y++)
					for (x = 0; x < pnm->width; x++)
						for (k = 0; k < img->n; k++)
							*dp++ = map_color(ctx, *p++, pnm->maxval, 255);
			}
			else
			{
				if (e - p < pnm->height * pnm->width * img->n * 2)
					fz_throw(ctx, FZ_ERROR_GENERIC, "truncated image");

				for (y = 0; y < pnm->height; y++)
					for (x = 0; x < pnm->width; x++)
						for (k = 0; k < img->n; k++)
						{
							*dp++ = map_color(ctx, (p[0] << 8) | p[1], pnm->maxval, 255);
							p += 2;
						}
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
		if (!onlymeta)
			pnm->cs = fz_device_gray(ctx);
		return pnm_ascii_read_image(ctx, pnm, p, e, onlymeta, 1);
	}
	else if (!strcmp(signature, "P2"))
	{
		if (!onlymeta)
			pnm->cs = fz_device_gray(ctx);
		return pnm_ascii_read_image(ctx, pnm, p, e, onlymeta, 0);
	}
	else if (!strcmp(signature, "P3"))
	{
		if (!onlymeta)
			pnm->cs = fz_device_rgb(ctx);
		return pnm_ascii_read_image(ctx, pnm, p, e, onlymeta, 0);
	}
	else if (!strcmp(signature, "P4"))
	{
		if (!onlymeta)
			pnm->cs = fz_device_gray(ctx);
		return pnm_binary_read_image(ctx, pnm, p, e, onlymeta, 1);
	}
	else if (!strcmp(signature, "P5"))
	{
		if (!onlymeta)
			pnm->cs = fz_device_gray(ctx);
		return pnm_binary_read_image(ctx, pnm, p, e, onlymeta, 0);
	}
	else if (!strcmp(signature, "P6"))
	{
		if (!onlymeta)
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

	img = pnm_read_image(ctx, &pnm, p, total, 0);

	return img;
}

void
fz_load_pnm_info(fz_context *ctx, unsigned char *p, size_t total, int *wp, int *hp, int *xresp, int *yresp, fz_colorspace **cspacep)
{
	struct info pnm = { 0 };

	pnm_read_image(ctx, &pnm, p, total, 1);

	*cspacep = pnm.cs;
	*wp = pnm.width;
	*hp = pnm.height;
	*xresp = 72;
	*yresp = 72;
}
