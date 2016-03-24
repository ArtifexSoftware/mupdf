#include "mupdf/fitz.h"

static const unsigned char web_palette[] = {
	0x00, 0x00, 0x00, 0x33, 0x00, 0x00, 0x66, 0x00, 0x00, 0x99, 0x00, 0x00, 0xCC, 0x00, 0x00, 0xFF, 0x00, 0x00,
	0x00, 0x00, 0x33, 0x33, 0x00, 0x33, 0x66, 0x00, 0x33, 0x99, 0x00, 0x33, 0xCC, 0x00, 0x33, 0xFF, 0x00, 0x33,
	0x00, 0x00, 0x66, 0x33, 0x00, 0x66, 0x66, 0x00, 0x66, 0x99, 0x00, 0x66, 0xCC, 0x00, 0x66, 0xFF, 0x00, 0x66,
	0x00, 0x00, 0x99, 0x33, 0x00, 0x99, 0x66, 0x00, 0x99, 0x99, 0x00, 0x99, 0xCC, 0x00, 0x99, 0xFF, 0x00, 0x99,
	0x00, 0x00, 0xCC, 0x33, 0x00, 0xCC, 0x66, 0x00, 0xCC, 0x99, 0x00, 0xCC, 0xCC, 0x00, 0xCC, 0xFF, 0x00, 0xCC,
	0x00, 0x00, 0xFF, 0x33, 0x00, 0xFF, 0x66, 0x00, 0xFF, 0x99, 0x00, 0xFF, 0xCC, 0x00, 0xFF, 0xFF, 0x00, 0xFF,
	0x00, 0x33, 0x00, 0x33, 0x33, 0x00, 0x66, 0x33, 0x00, 0x99, 0x33, 0x00, 0xCC, 0x33, 0x00, 0xFF, 0x33, 0x00,
	0x00, 0x33, 0x33, 0x33, 0x33, 0x33, 0x66, 0x33, 0x33, 0x99, 0x33, 0x33, 0xCC, 0x33, 0x33, 0xFF, 0x33, 0x33,
	0x00, 0x33, 0x66, 0x33, 0x33, 0x66, 0x66, 0x33, 0x66, 0x99, 0x33, 0x66, 0xCC, 0x33, 0x66, 0xFF, 0x33, 0x66,
	0x00, 0x33, 0x99, 0x33, 0x33, 0x99, 0x66, 0x33, 0x99, 0x99, 0x33, 0x99, 0xCC, 0x33, 0x99, 0xFF, 0x33, 0x99,
	0x00, 0x33, 0xCC, 0x33, 0x33, 0xCC, 0x66, 0x33, 0xCC, 0x99, 0x33, 0xCC, 0xCC, 0x33, 0xCC, 0xFF, 0x33, 0xCC,
	0x00, 0x33, 0xFF, 0x33, 0x33, 0xFF, 0x66, 0x33, 0xFF, 0x99, 0x33, 0xFF, 0xCC, 0x33, 0xFF, 0xFF, 0x33, 0xFF,
	0x00, 0x66, 0x00, 0x33, 0x66, 0x00, 0x66, 0x66, 0x00, 0x99, 0x66, 0x00, 0xCC, 0x66, 0x00, 0xFF, 0x66, 0x00,
	0x00, 0x66, 0x33, 0x33, 0x66, 0x33, 0x66, 0x66, 0x33, 0x99, 0x66, 0x33, 0xCC, 0x66, 0x33, 0xFF, 0x66, 0x33,
	0x00, 0x66, 0x66, 0x33, 0x66, 0x66, 0x66, 0x66, 0x66, 0x99, 0x66, 0x66, 0xCC, 0x66, 0x66, 0xFF, 0x66, 0x66,
	0x00, 0x66, 0x99, 0x33, 0x66, 0x99, 0x66, 0x66, 0x99, 0x99, 0x66, 0x99, 0xCC, 0x66, 0x99, 0xFF, 0x66, 0x99,
	0x00, 0x66, 0xCC, 0x33, 0x66, 0xCC, 0x66, 0x66, 0xCC, 0x99, 0x66, 0xCC, 0xCC, 0x66, 0xCC, 0xFF, 0x66, 0xCC,
	0x00, 0x66, 0xFF, 0x33, 0x66, 0xFF, 0x66, 0x66, 0xFF, 0x99, 0x66, 0xFF, 0xCC, 0x66, 0xFF, 0xFF, 0x66, 0xFF,
	0x00, 0x99, 0x00, 0x33, 0x99, 0x00, 0x66, 0x99, 0x00, 0x99, 0x99, 0x00, 0xCC, 0x99, 0x00, 0xFF, 0x99, 0x00,
	0x00, 0x99, 0x33, 0x33, 0x99, 0x33, 0x66, 0x99, 0x33, 0x99, 0x99, 0x33, 0xCC, 0x99, 0x33, 0xFF, 0x99, 0x33,
	0x00, 0x99, 0x66, 0x33, 0x99, 0x66, 0x66, 0x99, 0x66, 0x99, 0x99, 0x66, 0xCC, 0x99, 0x66, 0xFF, 0x99, 0x66,
	0x00, 0x99, 0x99, 0x33, 0x99, 0x99, 0x66, 0x99, 0x99, 0x99, 0x99, 0x99, 0xCC, 0x99, 0x99, 0xFF, 0x99, 0x99,
	0x00, 0x99, 0xCC, 0x33, 0x99, 0xCC, 0x66, 0x99, 0xCC, 0x99, 0x99, 0xCC, 0xCC, 0x99, 0xCC, 0xFF, 0x99, 0xCC,
	0x00, 0x99, 0xFF, 0x33, 0x99, 0xFF, 0x66, 0x99, 0xFF, 0x99, 0x99, 0xFF, 0xCC, 0x99, 0xFF, 0xFF, 0x99, 0xFF,
	0x00, 0xCC, 0x00, 0x33, 0xCC, 0x00, 0x66, 0xCC, 0x00, 0x99, 0xCC, 0x00, 0xCC, 0xCC, 0x00, 0xFF, 0xCC, 0x00,
	0x00, 0xCC, 0x33, 0x33, 0xCC, 0x33, 0x66, 0xCC, 0x33, 0x99, 0xCC, 0x33, 0xCC, 0xCC, 0x33, 0xFF, 0xCC, 0x33,
	0x00, 0xCC, 0x66, 0x33, 0xCC, 0x66, 0x66, 0xCC, 0x66, 0x99, 0xCC, 0x66, 0xCC, 0xCC, 0x66, 0xFF, 0xCC, 0x66,
	0x00, 0xCC, 0x99, 0x33, 0xCC, 0x99, 0x66, 0xCC, 0x99, 0x99, 0xCC, 0x99, 0xCC, 0xCC, 0x99, 0xFF, 0xCC, 0x99,
	0x00, 0xCC, 0xCC, 0x33, 0xCC, 0xCC, 0x66, 0xCC, 0xCC, 0x99, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xFF, 0xCC, 0xCC,
	0x00, 0xCC, 0xFF, 0x33, 0xCC, 0xFF, 0x66, 0xCC, 0xFF, 0x99, 0xCC, 0xFF, 0xCC, 0xCC, 0xFF, 0xFF, 0xCC, 0xFF,
	0x00, 0xFF, 0x00, 0x33, 0xFF, 0x00, 0x66, 0xFF, 0x00, 0x99, 0xFF, 0x00, 0xCC, 0xFF, 0x00, 0xFF, 0xFF, 0x00,
	0x00, 0xFF, 0x33, 0x33, 0xFF, 0x33, 0x66, 0xFF, 0x33, 0x99, 0xFF, 0x33, 0xCC, 0xFF, 0x33, 0xFF, 0xFF, 0x33,
	0x00, 0xFF, 0x66, 0x33, 0xFF, 0x66, 0x66, 0xFF, 0x66, 0x99, 0xFF, 0x66, 0xCC, 0xFF, 0x66, 0xFF, 0xFF, 0x66,
	0x00, 0xFF, 0x99, 0x33, 0xFF, 0x99, 0x66, 0xFF, 0x99, 0x99, 0xFF, 0x99, 0xCC, 0xFF, 0x99, 0xFF, 0xFF, 0x99,
	0x00, 0xFF, 0xCC, 0x33, 0xFF, 0xCC, 0x66, 0xFF, 0xCC, 0x99, 0xFF, 0xCC, 0xCC, 0xFF, 0xCC, 0xFF, 0xFF, 0xCC,
	0x00, 0xFF, 0xFF, 0x33, 0xFF, 0xFF, 0x66, 0xFF, 0xFF, 0x99, 0xFF, 0xFF, 0xCC, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
};

static const unsigned char vga_palette[] = {
	0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0xFF, 0x00,
	0x00, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0xFF, 0x00, 0xFF,
	0xFF, 0xFF, 0x00, 0xFF, 0xFF, 0xFF, 0x00, 0x80, 0x00,
	0x00, 0x80, 0x80, 0x80, 0x00, 0x00, 0x80, 0x00, 0x80,
	0x80, 0x80, 0x00, 0xC0, 0xC0, 0xC0, 0x80, 0x80, 0x80,
	0x00, 0x00, 0xFF,
};

static const unsigned char gray_palette[] = {
	0x00, 0x00, 0x00, 0x54, 0x54, 0x54,
	0xA8, 0xA8, 0xA8, 0xFF, 0xFF, 0xFF,
};

static const unsigned char bw_palette[] = {
	0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF,
};

struct info
{
	int filesize;
	int offset;
	int topdown;
	int width, height;
	int xres, yres;
	int bitcount;
	int compression;
	int colors;
	int rmask, gmask, bmask;
	unsigned char palette[256 * 3];

	int palettetype;
	unsigned char *samples;

	int rshift, gshift, bshift;
	int rbits, gbits, bbits;
};

#define read8(p) ((p)[0])
#define read16(p) (((p)[1] << 8) | (p)[0])
#define read32(p) (((p)[3] << 24) | ((p)[2] << 16) | ((p)[1] << 8) | (p)[0])

static unsigned char *
bmp_read_file_header(fz_context *ctx, struct info *info, unsigned char *p, unsigned char *end)
{
	if (end - p < 14)
		fz_throw(ctx, FZ_ERROR_GENERIC, "premature end in file header in bmp image");

	if (memcmp(&p[0], "BM", 2))
		fz_throw(ctx, FZ_ERROR_GENERIC, "invalid signature in bmp image");

	info->filesize = read32(p + 2);
	info->offset = read32(p + 10);

	return p + 14;
}

static unsigned char *
bmp_read_bitmap_core_header(fz_context *ctx, struct info *info, unsigned char *p, unsigned char *end)
{
	int size;

	size = read32(p + 0);
	if (size != 12)
		fz_throw(ctx, FZ_ERROR_GENERIC, "unsupported core header size in bmp image");

	if (size >= 12)
	{
		if (end - p < 12)
			fz_throw(ctx, FZ_ERROR_GENERIC, "premature end in bitmap core header in bmp image");

		info->width = read16(p + 4);
		info->height = read16(p + 6);
		info->bitcount = read16(p + 10);
	}

	info->xres = 2835;
	info->yres = 2835;
	info->compression = 0;
	info->palettetype = 0;

	return p + size;
}

static unsigned char *
bmp_read_bitmap_os2_header(fz_context *ctx, struct info *info, unsigned char *p, unsigned char *end)
{
	int size;

	size = read32(p + 0);
	if (size != 16 && size != 64)
		fz_throw(ctx, FZ_ERROR_GENERIC, "unsupported os2 header size in bmp image");

	if (size >= 16)
	{
		if (end - p < 16)
			fz_throw(ctx, FZ_ERROR_GENERIC, "premature end in bitmap os2 header in bmp image");

		info->width = read32(p + 4);
		info->height = read32(p + 8);
		info->bitcount = read16(p + 14);
		info->compression = read32(p + 16);
	}
	if (size >= 64)
	{
		if (end - p < 64)
			fz_throw(ctx, FZ_ERROR_GENERIC, "premature end in bitmap os2 header in bmp image");

		info->xres = read32(p + 24);
		info->yres = read32(p + 28);
		info->colors = read32(p + 32);
	}

	info->palettetype = 1;

	return p + size;
}

static unsigned char *
bmp_read_bitmap_info_header(fz_context *ctx, struct info *info, unsigned char *p, unsigned char *end)
{
	int size;

	size = read32(p + 0);
	if (size != 40 && size != 52 && size != 56 && size != 64 &&
			size != 108 && size != 124)
		fz_throw(ctx, FZ_ERROR_GENERIC, "unsupported info header size in bmp image");

	if (size >= 40)
	{
		if (end - p < 40)
			fz_throw(ctx, FZ_ERROR_GENERIC, "premature end in bitmap info header in bmp image");

		info->width = read32(p + 4);
		info->topdown = (p[8 + 3] & 0x80) != 0;
		if (info->topdown)
			info->height = -read32(p + 8);
		else
			info->height = read32(p + 8);
		info->bitcount = read16(p + 14);
		info->compression = read32(p + 16);
		info->xres = read32(p + 24);
		info->yres = read32(p + 28);
		info->colors = read32(p + 32);

		if (info->bitcount == 16) {
			info->rmask = 0x00007c00;
			info->gmask = 0x000003e0;
			info->bmask = 0x0000001f;
		} else if (info->bitcount == 32) {
			info->rmask = 0x00ff0000;
			info->gmask = 0x0000ff00;
			info->bmask = 0x000000ff;
		}
	}
	if (size >= 52)
	{
		if (end - p < 52)
			fz_throw(ctx, FZ_ERROR_GENERIC, "premature end in bitmap info header in bmp image");

		info->rmask = read32(p + 40);
		info->gmask = read32(p + 44);
		info->bmask = read32(p + 48);
	}

	info->palettetype = 1;

	return p + size;
}

static void maskinfo(unsigned int mask, int *shift, int *bits)
{
	*bits = 0;
	*shift = 0;
	if (mask) {
		while ((mask & 1) == 0) {
			*shift = *shift + 1;
			mask >>= 1;
		}
		while ((mask & 1) == 1) {
			*bits = *bits + 1;
			mask >>= 1;
		}
		if (*bits > 8) {
			*shift += *bits - 8;
			*bits = 8;
		}
	}
}

static unsigned char *
bmp_read_masks(fz_context *ctx, struct info *info, unsigned char *p, unsigned char *end)
{
	if (info->compression == 3)
	{
		if (end - p < 12)
			fz_throw(ctx, FZ_ERROR_GENERIC, "premature end in mask header in bmp image");
		info->rmask = read32(p + 0);
		info->gmask = read32(p + 4);
		info->bmask = read32(p + 8);
		p += 12;
	}
	else if (info->compression == 6)
	{
		if (end - p < 16)
			fz_throw(ctx, FZ_ERROR_GENERIC, "premature end in mask header in bmp image");
		info->rmask = read32(p + 0);
		info->gmask = read32(p + 4);
		info->bmask = read32(p + 8);
		p += 16;
	}

	maskinfo(info->rmask, &info->rshift, &info->rbits);
	maskinfo(info->gmask, &info->gshift, &info->gbits);
	maskinfo(info->bmask, &info->bshift, &info->bbits);

	return p;
}

static void
bmp_load_default_palette(fz_context *ctx, struct info *info)
{
	if (info->bitcount == 8)
		memcpy(info->palette, web_palette, sizeof(web_palette));
	else if (info->bitcount == 4)
		memcpy(info->palette, vga_palette, sizeof(vga_palette));
	else if (info->bitcount == 2)
		memcpy(info->palette, gray_palette, sizeof(gray_palette));
	else if (info->bitcount == 1)
		memcpy(info->palette, bw_palette, sizeof(bw_palette));
}

static unsigned char *
bmp_read_color_table(fz_context *ctx, struct info *info, unsigned char *p, unsigned char *end)
{
	int i, colors;

	if (info->bitcount > 8)
		return p;

	if (info->colors == 0)
		colors = 1 << info->bitcount;
	else
		colors = info->colors;

	colors = fz_mini(colors, 1 << info->bitcount);

	if (info->palettetype == 0)
	{
		if (end - p < colors * 3) {
			fz_warn(ctx, "color table too short; loading default palette");
			bmp_load_default_palette(ctx, info);
			colors = (end - p) / 3;
		}
		for (i = 0; i < colors; i++)
		{
			info->palette[3 * i + 0] = read8(p + i * 3 + 2);
			info->palette[3 * i + 1] = read8(p + i * 3 + 1);
			info->palette[3 * i + 2] = read8(p + i * 3 + 0);
		}
		return p + colors * 3;
	}
	else
	{
		if (end - p < colors * 4) {
			fz_warn(ctx, "color table too short; loading default palette");
			bmp_load_default_palette(ctx, info);
			colors = (end - p) / 4;
		}
		for (i = 0; i < colors; i++)
		{
			info->palette[3 * i + 0] = read8(p + i * 4 + 2);
			info->palette[3 * i + 1] = read8(p + i * 4 + 1);
			info->palette[3 * i + 2] = read8(p + i * 4 + 0);
			/* ignore alpha channel */
		}
		return p + colors * 4;
	}

	return p;
}

static unsigned char *
bmp_decompress_rle8(fz_context *ctx, struct info *info, unsigned char *p, unsigned char **end)
{
	unsigned char *sp, *dp, *ep, *decompressed;
	int width = info->width;
	int height = info->height;
	int stride;
	int x, i;

	stride = (width + 3) / 4 * 4;

	sp = p;
	dp = decompressed = fz_calloc(ctx, height, stride);
	ep = dp + height * stride;
	x = 0;

	while (sp + 2 <= *end)
	{
		if (sp[0] == 0 && sp[1] == 0)
		{ /* end of line */
			if (x < stride)
				dp += stride - x;
			sp += 2;
			x = 0;
		}
		else if (sp[0] == 0 && sp[1] == 1)
		{ /* end of bitmap */
			dp = ep;
			break;
		}
		else if (sp[0] == 0 && sp[1] == 2)
		{ /* delta */
			int deltax, deltay;
			if (sp + 4 > *end)
				break;
			deltax = sp[2];
			deltay = sp[3];
			dp += deltax + deltay * stride;
			sp += 4;
			x += deltax;
		}
		else if (sp[0] == 0 && sp[1] >= 3)
		{ /* absolute */
			int n = sp[1];
			int nn = (n + 1) / 2 * 2;
			if (sp + 2 + nn > *end)
				break;
			if (dp + n > ep) {
				fz_warn(ctx, "buffer overflow in bitmap data in bmp image");
				break;
			}
			sp += 2;
			for (i = 0; i < n; i++)
				dp[i] = sp[i];
			dp += n;
			sp += (n + 1) / 2 * 2;
			x += n;
		}
		else
		{ /* encoded */
			int n = sp[0];
			if (dp + n > ep) {
				fz_warn(ctx, "buffer overflow in bitmap data in bmp image");
				break;
			}
			for (i = 0; i < n; i++)
				dp[i] = sp[1];
			dp += n;
			sp += 2;
			x += n;
		}
	}

	if (dp < ep)
		fz_warn(ctx, "premature end of bitmap data in bmp image");

	info->compression = 0;
	info->bitcount = 8;
	*end = ep;
	return decompressed;
}

static unsigned char *
bmp_decompress_rle4(fz_context *ctx, struct info *info, unsigned char *p, unsigned char **end)
{
	unsigned char *sp, *dp, *ep, *decompressed;
	int width = info->width;
	int height = info->height;
	int stride;
	int i, x;

	stride = ((width + 1) / 2 + 3) / 4 * 4;

	sp = p;
	dp = decompressed = fz_calloc(ctx, height, stride);
	ep = dp + height * stride;
	x = 0;

	while (sp + 2 < *end)
	{
		if (sp[0] == 0 && sp[1] == 0)
		{ /* end of line */
			int xx = x / 2;
			if (xx < stride)
				dp += stride - xx;
			sp += 2;
			x = 0;
		}
		else if (sp[0] == 0 && sp[1] == 1)
		{ /* end of bitmap */
			dp = ep;
			break;
		}
		else if (sp[0] == 0 && sp[1] == 2)
		{ /* delta */
			int deltax, deltay, startlow;
			if (sp + 4 > *end)
				break;
			deltax = sp[2];
			deltay = sp[3];
			startlow = x & 1;
			dp += (deltax + startlow) / 2 + deltay * stride;
			sp += 4;
			x += deltax;
		}
		else if (sp[0] == 0 && sp[1] >= 3)
		{ /* absolute */
			int n = sp[1];
			int nn = ((n + 1) / 2 + 1) / 2 * 2;
			if (sp + 2 + nn > *end)
				break;
			if (dp + n / 2 > ep) {
				fz_warn(ctx, "buffer overflow in bitmap data in bmp image");
				break;
			}
			sp += 2;
			for (i = 0; i < n; i++, x++)
			{
				int val = i & 1 ? (sp[i/2]) & 0xF : (sp[i/2] >> 4) & 0xF;
				if (x & 1)
					*dp++ |= val;
				else
					*dp |= val << 4;
			}
			sp += nn;
		}
		else
		{ /* encoded */
			int n = sp[0];
			int hi = (sp[1] >> 4) & 0xF;
			int lo = sp[1] & 0xF;
			if (dp + n / 2 > ep) {
				fz_warn(ctx, "buffer overflow in bitmap data in bmp image");
				break;
			}
			for (i = 0; i < n; i++, x++)
			{
				int val = i & 1 ? lo : hi;
				if (x & 1)
					*dp++ |= val;
				else
					*dp |= val << 4;
			}
			sp += 2;
		}
	}

	info->compression = 0;
	info->bitcount = 4;
	*end = ep;
	return decompressed;
}

static fz_pixmap *
bmp_read_bitmap(fz_context *ctx, struct info *info, unsigned char *p, unsigned char *end)
{
	fz_pixmap *pix;
	unsigned char *decompressed = NULL;
	unsigned char *ssp, *ddp;
	int bitcount, width, height;
	int sstride, dstride;
	int rmult, gmult, bmult;
	int x, y;

	if (info->compression == 1)
		ssp = decompressed = bmp_decompress_rle8(ctx, info, p, &end);
	else if (info->compression == 2)
		ssp = decompressed = bmp_decompress_rle4(ctx, info, p, &end);
	else
		ssp = p;

	bitcount = info->bitcount;
	width = info->width;
	height = info->height;

	sstride = ((width * bitcount + 31) / 32) * 4;

	if (ssp + sstride * height > end)
	{
		fz_free(ctx, decompressed);
		fz_throw(ctx, FZ_ERROR_GENERIC, "premature end in bitmap data in bmp image");
	}

	fz_try(ctx)
		pix = fz_new_pixmap(ctx, fz_device_rgb(ctx), width, height);
	fz_catch(ctx)
	{
		fz_free(ctx, decompressed);
		fz_rethrow(ctx);
	}

	ddp = pix->samples;
	dstride = width * 4;
	if (!info->topdown)
	{
		ddp = pix->samples + (height - 1) * dstride;
		dstride = -dstride;
	}

	/* These only apply for components in 16-bit mode
	   5-bit (31 * 264) / 32
	   6-bit (63 * 130 ) / 32 */
	rmult = info->rbits == 5 ? 264 : 130;
	gmult = info->gbits == 5 ? 264 : 130;
	bmult = info->bbits == 5 ? 264 : 130;

	for (y = 0; y < height; y++)
	{
		unsigned char *sp = ssp + y * sstride;
		unsigned char *dp = ddp + y * dstride;

		for (x = 0; x < width; x++)
		{
			if (bitcount == 32)
			{
				int sample = (sp[3] << 24) | (sp[2] << 16) | (sp[1] << 8) | sp[0];
				*dp++ = (sample & info->rmask) >> info->rshift;
				*dp++ = (sample & info->gmask) >> info->gshift;
				*dp++ = (sample & info->bmask) >> info->bshift;
				*dp++ = 255;
				sp += 4;
			}
			else if (bitcount == 24)
			{
				*dp++ = sp[2];
				*dp++ = sp[1];
				*dp++ = sp[0];
				*dp++ = 255;
				sp += 3;
			}
			else if (bitcount == 16)
			{
				int sample = (sp[1] << 8) | sp[0];
				int r = (sample & info->rmask) >> info->rshift;
				int g = (sample & info->gmask) >> info->gshift;
				int b = (sample & info->bmask) >> info->bshift;
				*dp++ = (r * rmult) >> 5;
				*dp++ = (g * gmult) >> 5;
				*dp++ = (b * bmult) >> 5;
				*dp++ = 255;
				sp += 2;
			}
			else if (bitcount == 8)
			{
				*dp++ = info->palette[3 * sp[0] + 0];
				*dp++ = info->palette[3 * sp[0] + 1];
				*dp++ = info->palette[3 * sp[0] + 2];
				*dp++ = 255;
				sp++;
			}
			else if (bitcount == 4)
			{
				int idx;
				switch (x & 1)
				{
				case 0: idx = (sp[0] >> 4) & 0x0f; break;
				case 1: idx = (sp[0] >> 0) & 0x0f; sp++; break;
				}
				*dp++ = info->palette[3 * idx + 0];
				*dp++ = info->palette[3 * idx + 1];
				*dp++ = info->palette[3 * idx + 2];
				*dp++ = 255;
			}
			else if (bitcount == 2)
			{
				int idx;
				switch (x & 3)
				{
				case 0: idx = (sp[0] >> 6) & 0x03; break;
				case 1: idx = (sp[0] >> 4) & 0x03; break;
				case 2: idx = (sp[0] >> 2) & 0x03; break;
				case 3: idx = (sp[0] >> 0) & 0x03; sp++; break;
				}
				*dp++ = info->palette[3 * idx + 0];
				*dp++ = info->palette[3 * idx + 1];
				*dp++ = info->palette[3 * idx + 2];
				*dp++ = 255;
			}
			else if (bitcount == 1)
			{
				int idx;
				switch (x & 7)
				{
				case 0: idx = (sp[0] >> 7) & 0x01; break;
				case 1: idx = (sp[0] >> 6) & 0x01; break;
				case 2: idx = (sp[0] >> 5) & 0x01; break;
				case 3: idx = (sp[0] >> 4) & 0x01; break;
				case 4: idx = (sp[0] >> 3) & 0x01; break;
				case 5: idx = (sp[0] >> 2) & 0x01; break;
				case 6: idx = (sp[0] >> 1) & 0x01; break;
				case 7: idx = (sp[0] >> 0) & 0x01; sp++; break;
				}
				*dp++ = info->palette[3 * idx + 0];
				*dp++ = info->palette[3 * idx + 1];
				*dp++ = info->palette[3 * idx + 2];
				*dp++ = 255;
			}
		}
	}

	fz_free(ctx, decompressed);
	return pix;
}

static fz_pixmap *
bmp_read_image(fz_context *ctx, struct info *info, unsigned char *p, int total, int only_metadata)
{
	unsigned char *begin = p;
	unsigned char *end = p + total;
	int size;

	memset(info, 0x00, sizeof (*info));

	p = bmp_read_file_header(ctx, info, p, end);

	info->filesize = fz_mini(info->filesize, total);

	if (end - p < 4)
		fz_throw(ctx, FZ_ERROR_GENERIC, "premature end in bitmap core header in bmp image");
	size = read32(p + 0);

	if (size == 12)
		p = bmp_read_bitmap_core_header(ctx, info, p, end);
	else if (size == 40 || size == 52 || size == 56 || size == 108 || size == 124)
	{
		p = bmp_read_bitmap_info_header(ctx, info, p, end);
		p = bmp_read_masks(ctx, info, p, end);
	}
	else if (size == 16 || size == 64)
		p = bmp_read_bitmap_os2_header(ctx, info, p, end);
	else
		fz_throw(ctx, FZ_ERROR_GENERIC, "invalid header size (%d) in bmp image", size);

	if (info->width <= 0 || info->width > SHRT_MAX || info->height <= 0 || info->height > SHRT_MAX)
		fz_throw(ctx, FZ_ERROR_GENERIC, "dimensions (%d x %d) out of range in bmp image",
				info->width, info->height);
	if (info->bitcount != 1 && info->bitcount != 2 &&
			info->bitcount != 4 && info->bitcount != 8 &&
			info->bitcount != 16 && info->bitcount != 24 &&
			info->bitcount != 32)
		fz_throw(ctx, FZ_ERROR_GENERIC, "unsupported bits per pixel (%d) in bmp image", info->bitcount);
	if (info->compression != 0 && info->compression != 1 &&
			info->compression != 2 && info->compression != 3)
		fz_throw(ctx, FZ_ERROR_GENERIC, "unsupported compression method (%d) in bmp image", info->compression);
	if ((info->compression == 1 && info->bitcount != 8) ||
			(info->compression == 2 && info->bitcount != 4) ||
			(info->compression == 3 && info->bitcount != 16 && info->bitcount != 32))
		fz_throw(ctx, FZ_ERROR_GENERIC, "invalid bits per pixel (%d) for compression (%d) in bmp image",
				info->bitcount, info->compression);
	if (info->rbits > 0 && info->rbits != 5 && info->rbits != 8)
		fz_throw(ctx, FZ_ERROR_GENERIC, "unsupported %d bit red mask in bmp image", info->rbits);
	if (info->gbits > 0 && info->gbits != 5 && info->gbits != 6 && info->rbits != 8)
		fz_throw(ctx, FZ_ERROR_GENERIC, "unsupported %d bit green mask in bmp image", info->gbits);
	if (info->bbits > 0 && info->bbits != 5 && info->rbits != 8)
		fz_throw(ctx, FZ_ERROR_GENERIC, "unsupported %d bit blue mask in bmp image", info->bbits);

	if (!only_metadata)
	{
		p = bmp_read_color_table(ctx, info, p, begin + info->offset);
		if (p - begin < info->offset)
			p = begin + info->offset;
		return bmp_read_bitmap(ctx, info, p, end);
	}

	return NULL;
}

fz_pixmap *
fz_load_bmp(fz_context *ctx, unsigned char *p, int total)
{
	struct info bmp;
	fz_pixmap *image;

	image = bmp_read_image(ctx, &bmp, p, total, 0);
	image->xres = bmp.xres / (1000.0f / 25.4f);
	image->yres = bmp.yres / (1000.0f / 25.4f);

	return image;
}

void
fz_load_bmp_info(fz_context *ctx, unsigned char *p, int total, int *wp, int *hp, int *xresp, int *yresp, fz_colorspace **cspacep)
{
	struct info bmp;

	bmp_read_image(ctx, &bmp, p, total, 1);

	*cspacep = fz_device_rgb(ctx);
	*wp = bmp.width;
	*hp = bmp.height;
	*xresp = bmp.xres / (1000.0f / 25.4f);
	*yresp = bmp.yres / (1000.0f / 25.4f);
}
