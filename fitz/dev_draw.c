#include "fitz.h"

#define QUANT(x,a) (((int)((x) * (a))) / (a))
#define HSUBPIX 5.0
#define VSUBPIX 5.0

#define MAXCLIP 64

typedef struct fz_drawdevice_s fz_drawdevice;

struct fz_drawdevice_s
{
	int maskonly;
	fz_colorspace *model;
	fz_glyphcache *cache;
	fz_gel *gel;
	fz_ael *ael;
	fz_pixmap *dest;
	struct {
		fz_pixmap *dest;
		fz_pixmap *mask;
	} clipstack[MAXCLIP];
	int cliptop;
};

static void
blendover(fz_pixmap *src, fz_pixmap *dst)
{
	unsigned char *sp, *dp;
	fz_irect sr, dr;
	int x, y, w, h;

	sr.x0 = src->x;
	sr.y0 = src->y;
	sr.x1 = src->x + src->w;
	sr.y1 = src->y + src->h;

	dr.x0 = dst->x;
	dr.y0 = dst->y;
	dr.x1 = dst->x + dst->w;
	dr.y1 = dst->y + dst->h;

	dr = fz_intersectirects(sr, dr);
	x = dr.x0;
	y = dr.y0;
	w = dr.x1 - dr.x0;
	h = dr.y1 - dr.y0;

	sp = src->samples + ((y - src->y) * src->w + (x - src->x)) * src->n;
	dp = dst->samples + ((y - dst->y) * dst->w + (x - dst->x)) * dst->n;

	if (src->n == 1 && dst->n == 1)
		fz_duff_1o1(sp, src->w, dp, dst->w, w, h);
	else if (src->n == 4 && dst->n == 4)
		fz_duff_4o4(sp, src->w * 4, dp, dst->w * 4, w, h);
	else if (src->n == dst->n)
		fz_duff_non(sp, src->w * src->n, src->n, dp, dst->w * dst->n, w, h);
	else
		assert(!"blendover src and dst mismatch");
}

static void
blendmaskover(fz_pixmap *src, fz_pixmap *msk, fz_pixmap *dst)
{
	unsigned char *sp, *dp, *mp;
	fz_irect sr, dr, mr;
	int x, y, w, h;

	sr.x0 = src->x;
	sr.y0 = src->y;
	sr.x1 = src->x + src->w;
	sr.y1 = src->y + src->h;

	dr.x0 = dst->x;
	dr.y0 = dst->y;
	dr.x1 = dst->x + dst->w;
	dr.y1 = dst->y + dst->h;

	mr.x0 = msk->x;
	mr.y0 = msk->y;
	mr.x1 = msk->x + msk->w;
	mr.y1 = msk->y + msk->h;

	dr = fz_intersectirects(sr, dr);
	dr = fz_intersectirects(dr, mr);
	x = dr.x0;
	y = dr.y0;
	w = dr.x1 - dr.x0;
	h = dr.y1 - dr.y0;

	sp = src->samples + ((y - src->y) * src->w + (x - src->x)) * src->n;
	mp = msk->samples + ((y - msk->y) * msk->w + (x - msk->x)) * msk->n;
	dp = dst->samples + ((y - dst->y) * dst->w + (x - dst->x)) * dst->n;

	if (src->n == 1 && msk->n == 1 && dst->n == 1)
		fz_duff_1i1o1(sp, src->w, mp, msk->w, dp, dst->w, w, h);
	else if (src->n == 4 && msk->n == 1 && dst->n == 4)
		fz_duff_4i1o4(sp, src->w * 4, mp, msk->w, dp, dst->w * 4, w, h);
	else if (src->n == dst->n)
		fz_duff_nimon(sp, src->w * src->n, src->n, mp, msk->w * msk->n, msk->n, dp, dst->w * dst->n, w, h);
	else
		assert(!"blendmaskover src and msk and dst mismatch");
}

void fz_drawfillpath(void *user, fz_path *path, fz_colorspace *colorspace, float *color, float alpha)
{
	fz_drawdevice *dev = user;
	float expansion = fz_matrixexpansion(path->ctm);
	float flatness = 0.3 / expansion;
	fz_irect bbox;
	fz_irect clip;
	unsigned char argb[7];
	float rgb[3];

	if (flatness < 0.1)
		flatness = 0.1;

	fz_convertcolor(colorspace, color, dev->model, rgb);
	argb[0] = alpha * 255;
	argb[1] = rgb[0] * alpha * 255;
	argb[2] = rgb[1] * alpha * 255;
	argb[3] = rgb[2] * alpha * 255;
	argb[4] = rgb[0] * 255;
	argb[5] = rgb[1] * 255;
	argb[6] = rgb[2] * 255;

	clip.x0 = dev->dest->x;
	clip.y0 = dev->dest->y;
	clip.x1 = dev->dest->x + dev->dest->w;
	clip.y1 = dev->dest->y + dev->dest->h;

	fz_resetgel(dev->gel, clip);
	fz_fillpath(dev->gel, path, path->ctm, flatness);
	fz_sortgel(dev->gel);

	bbox = fz_boundgel(dev->gel);
	bbox = fz_intersectirects(bbox, clip);
	if (fz_isemptyrect(bbox))
		return;

	fz_scanconvert(dev->gel, dev->ael, path->winding == FZ_EVENODD, bbox, dev->dest, argb, 1);
}

void fz_drawstrokepath(void *user, fz_path *path, fz_colorspace *colorspace, float *color, float alpha)
{
	fz_drawdevice *dev = user;
	float expansion = fz_matrixexpansion(path->ctm);
	float flatness = 0.3 / expansion;
	float linewidth = path->linewidth;
	fz_irect bbox;
	fz_irect clip;
	unsigned char argb[7];
	float rgb[3];

	if (flatness < 0.1)
		flatness = 0.1;
	if (linewidth * expansion < 0.1)
		linewidth = 1.0 / expansion;

	fz_convertcolor(colorspace, color, dev->model, rgb);
	argb[0] = alpha * 255;
	argb[1] = rgb[0] * alpha * 255;
	argb[2] = rgb[1] * alpha * 255;
	argb[3] = rgb[2] * alpha * 255;
	argb[4] = rgb[0] * 255;
	argb[5] = rgb[1] * 255;
	argb[6] = rgb[2] * 255;

	clip.x0 = dev->dest->x;
	clip.y0 = dev->dest->y;
	clip.x1 = dev->dest->x + dev->dest->w;
	clip.y1 = dev->dest->y + dev->dest->h;

	fz_resetgel(dev->gel, clip);
	if (path->dashlen > 0)
		fz_dashpath(dev->gel, path, path->ctm, flatness, linewidth);
	else
		fz_strokepath(dev->gel, path, path->ctm, flatness, linewidth);
	fz_sortgel(dev->gel);

	bbox = fz_boundgel(dev->gel);
	bbox = fz_intersectirects(bbox, clip);
	if (fz_isemptyrect(bbox))
		return;

	fz_scanconvert(dev->gel, dev->ael, 0, bbox, dev->dest, argb, 1);
}

void fz_drawclippath(void *user, fz_path *path)
{
	fz_drawdevice *dev = user;
	float expansion = fz_matrixexpansion(path->ctm);
	float flatness = 0.3 / expansion;
	fz_irect clip, bbox;
	fz_pixmap *mask, *dest;

	if (dev->cliptop == MAXCLIP)
	{
		fz_warn("assert: too many clip masks on stack");
		return;
	}

	if (flatness < 0.1)
		flatness = 0.1;

	clip.x0 = dev->dest->x;
	clip.y0 = dev->dest->y;
	clip.x1 = dev->dest->x + dev->dest->w;
	clip.y1 = dev->dest->y + dev->dest->h;

	fz_resetgel(dev->gel, clip);
	fz_fillpath(dev->gel, path, path->ctm, flatness);
	fz_sortgel(dev->gel);

	bbox = fz_boundgel(dev->gel);
	bbox = fz_intersectirects(bbox, clip);
	if (fz_isemptyrect(bbox))
		return;

	mask = fz_newpixmapwithrect(bbox, 1);
	dest = fz_newpixmapwithrect(bbox, 4);

	memset(mask->samples, 0, mask->w * mask->h * mask->n);
	memset(dest->samples, 0, dest->w * dest->h * dest->n);

	fz_scanconvert(dev->gel, dev->ael, path->winding == FZ_EVENODD, bbox, mask, NULL, 1);

	dev->clipstack[dev->cliptop].mask = mask;
	dev->clipstack[dev->cliptop].dest = dev->dest;
	dev->dest = dest;
	dev->cliptop++;
}

static void drawglyph(unsigned char *argb, fz_pixmap *dst, fz_glyph *src, int xorig, int yorig)
{
	unsigned char *dp, *sp;
	int w, h;

	int dx0 = dst->x;
	int dy0 = dst->y;
	int dx1 = dst->x + dst->w;
	int dy1 = dst->y + dst->h;

	int x0 = xorig + src->x;
	int y0 = yorig + src->y;
	int x1 = x0 + src->w;
	int y1 = y0 + src->h;

	int sx0 = 0;
	int sy0 = 0;
	int sx1 = src->w;
	int sy1 = src->h;

	if (x1 <= dx0 || x0 >= dx1) return;
	if (y1 <= dy0 || y0 >= dy1) return;
	if (x0 < dx0) { sx0 += dx0 - x0; x0 = dx0; }
	if (y0 < dy0) { sy0 += dy0 - y0; y0 = dy0; }
	if (x1 > dx1) { sx1 += dx1 - x1; x1 = dx1; }
	if (y1 > dy1) { sy1 += dy1 - y1; y1 = dy1; }

	sp = src->samples + (sy0 * src->w + sx0);
	dp = dst->samples + ((y0 - dst->y) * dst->w + (x0 - dst->x)) * dst->n;

	w = sx1 - sx0;
	h = sy1 - sy0;

	fz_text_w4i1o4(argb, sp, src->w, dp, dst->w * 4, w, h);
}

void fz_drawfilltext(void *user, fz_text *text, fz_colorspace *colorspace, float *color, float alpha)
{
	fz_drawdevice *dev = user;
	unsigned char argb[7];
	float rgb[3];
	fz_irect clip;
	fz_matrix tm, trm;
	fz_glyph glyph;
	int i, x, y, gid;

	fz_convertcolor(colorspace, color, dev->model, rgb);
	argb[0] = alpha * 255;
	argb[1] = rgb[0] * alpha * 255;
	argb[2] = rgb[1] * alpha * 255;
	argb[3] = rgb[2] * alpha * 255;
	argb[4] = rgb[0] * 255;
	argb[5] = rgb[1] * 255;
	argb[6] = rgb[2] * 255;

	clip.x0 = dev->dest->x;
	clip.y0 = dev->dest->y;
	clip.x1 = dev->dest->x + dev->dest->w;
	clip.y1 = dev->dest->y + dev->dest->h;

	tm = text->trm;

	for (i = 0; i < text->len; i++)
	{
		gid = text->els[i].gid;
		tm.e = text->els[i].x;
		tm.f = text->els[i].y;
		trm = fz_concat(tm, text->ctm);
		x = fz_floor(trm.e);
		y = fz_floor(trm.f);
		trm.e = QUANT(trm.e - fz_floor(trm.e), HSUBPIX);
		trm.f = QUANT(trm.f - fz_floor(trm.f), VSUBPIX);

		fz_renderglyph(dev->cache, &glyph, text->font, gid, trm);
		drawglyph(argb, dev->dest, &glyph, x, y);
	}
}

void fz_drawstroketext(void *user, fz_text *text, fz_colorspace *colorspace, float *color, float alpha)
{
	fz_warn("/%s setfont", text->font->name);
	fz_debugtext(text, 0);
	fz_warn("charpath stroke");
}

void fz_drawcliptext(void *user, fz_text *text)
{
	fz_warn("gsave");
	fz_warn("/%s setfont", text->font->name);
	fz_debugtext(text, 0);
	fz_warn("charpath clip");
}

void fz_drawignoretext(void *user, fz_text *text)
{
}

void fz_drawpopclip(void *user)
{
	fz_drawdevice *dev = user;
	if (dev->cliptop > 0)
	{
		fz_pixmap *mask = dev->clipstack[dev->cliptop-1].mask;
		fz_pixmap *dest = dev->clipstack[dev->cliptop-1].dest;
		fz_pixmap *scratch = dev->dest;
		blendmaskover(scratch, mask, dest);
		fz_freepixmap(mask);
		fz_freepixmap(scratch);
		dev->cliptop--;
		dev->dest = dest;
	}
}

void fz_drawdrawshade(void *user, fz_shade *shade, fz_matrix ctm)
{
	fz_drawdevice *dev = user;
	fz_rect bounds;
	fz_irect bbox;
	fz_irect clip;
	fz_pixmap *temp;
	float rgb[3];
	unsigned char argb[4];
	unsigned char *s;
	int n;

	bounds = fz_transformaabb(fz_concat(shade->matrix, ctm), shade->bbox);
	bbox = fz_roundrect(bounds);

	clip.x0 = dev->dest->x;
	clip.y0 = dev->dest->y;
	clip.x1 = dev->dest->x + dev->dest->w;
	clip.y1 = dev->dest->y + dev->dest->h;
	clip = fz_intersectirects(clip, bbox);

	temp = fz_newpixmapwithrect(clip, dev->model->n + 1);

	if (shade->usebackground)
	{
		fz_convertcolor(shade->cs, shade->background, dev->model, rgb);
		argb[0] = 255;
		argb[1] = rgb[0] * 255;
		argb[2] = rgb[1] * 255;
		argb[3] = rgb[2] * 255;
		s = temp->samples;
		n = temp->w * temp->h;
		while (n--)
		{
			*s++ = argb[0];
			*s++ = argb[1];
			*s++ = argb[2];
			*s++ = argb[3];
		}
		blendover(temp, dev->dest);
	}

	fz_rendershade(shade, ctm, dev->model, temp);
	blendover(temp, dev->dest);

	fz_freepixmap(temp);
}

static inline void
calcimagescale(fz_matrix ctm, int w, int h, int *odx, int *ody)
{
	float sx, sy;
	int dx, dy;

	sx = sqrt(ctm.a * ctm.a + ctm.b * ctm.b);
	dx = 1;
	while (((w+dx-1)/dx)/sx > 2.0 && (w+dx-1)/dx > 1)
		dx++;

	sy = sqrt(ctm.c * ctm.c + ctm.d * ctm.d);
	dy = 1;
	while (((h+dy-1)/dy)/sy > 2.0 && (h+dy-1)/dy > 1)
		dy++;

	*odx = dx;
	*ody = dy;
}

void fz_drawdrawimage(void *user, fz_image *image, fz_matrix ctm)
{
	fz_drawdevice *dev = user;
	fz_error error;
	fz_rect bounds;
	fz_irect bbox;
	fz_irect clip;
	int dx, dy;
	fz_pixmap *tile;
	fz_pixmap *temp;
	fz_matrix imgmat;
	fz_matrix invmat;
	int fa, fb, fc, fd;
	int u0, v0;
	int x0, y0;
	int w, h;

	bounds.x0 = 0;
	bounds.y0 = 0;
	bounds.x1 = 1;
	bounds.y1 = 1;
	bounds = fz_transformaabb(ctm, bounds);
	bbox = fz_roundrect(bounds);

	clip.x0 = dev->dest->x;
	clip.y0 = dev->dest->y;
	clip.x1 = dev->dest->x + dev->dest->w;
	clip.y1 = dev->dest->y + dev->dest->h;
	clip = fz_intersectirects(clip, bbox);

	if (fz_isemptyrect(clip))
		return;
	if (image->w == 0 || image->h == 0)
		return;

	calcimagescale(ctm, image->w, image->h, &dx, &dy);

	tile = fz_newpixmap(0, 0, image->w, image->h, image->n + 1);

	error = image->loadtile(image, tile);
	if (error)
	{
		fz_catch(error, "cannot load image data");
		return;
	}

	if (dx != 1 || dy != 1)
	{
		temp = fz_scalepixmap(tile, dx, dy);
		fz_freepixmap(tile);
		tile = temp;
	}

	if (image->cs && image->cs != dev->model)
	{
		temp = fz_newpixmap(tile->x, tile->y, tile->w, tile->h, dev->model->n + 1);
		fz_convertpixmap(image->cs, tile, dev->model, temp);
		fz_freepixmap(tile);
		tile = temp;
	}

	imgmat.a = 1.0 / tile->w;
	imgmat.b = 0.0;
	imgmat.c = 0.0;
	imgmat.d = -1.0 / tile->h;
	imgmat.e = 0.0;
	imgmat.f = 1.0;
	invmat = fz_invertmatrix(fz_concat(imgmat, ctm));

	invmat.e -= 0.5;
	invmat.f -= 0.5;

	w = clip.x1 - clip.x0;
	h = clip.y1 - clip.y0;
	x0 = clip.x0;
	y0 = clip.y0;
	u0 = (invmat.a * (x0+0.5) + invmat.c * (y0+0.5) + invmat.e) * 65536;
	v0 = (invmat.b * (x0+0.5) + invmat.d * (y0+0.5) + invmat.f) * 65536;
	fa = invmat.a * 65536;
	fb = invmat.b * 65536;
	fc = invmat.c * 65536;
	fd = invmat.d * 65536;

#define PDST(p) p->samples + ((y0-p->y) * p->w + (x0-p->x)) * p->n, p->w * p->n

	if (image->cs)
		fz_img_4o4(tile->samples, tile->w, tile->h, PDST(dev->dest),
			u0, v0, fa, fb, fc, fd, w, h);

	fz_freepixmap(tile);
}

fz_device *fz_newdrawdevice(fz_colorspace *colorspace, fz_pixmap *dest)
{
	fz_drawdevice *ddev = fz_malloc(sizeof(fz_drawdevice));
	ddev->model = fz_keepcolorspace(colorspace);
	ddev->cache = fz_newglyphcache(512, 512 * 512);
	ddev->gel = fz_newgel();
	ddev->ael = fz_newael();
	ddev->dest = dest;
	ddev->cliptop = 0;

	fz_device *dev = fz_malloc(sizeof(fz_device));
	dev->user = ddev;

	dev->fillpath = fz_drawfillpath;
	dev->strokepath = fz_drawstrokepath;
	dev->clippath = fz_drawclippath;

	dev->filltext = fz_drawfilltext;
	dev->stroketext = fz_drawstroketext;
	dev->cliptext = fz_drawcliptext;
	dev->ignoretext = fz_drawignoretext;

	dev->drawimage = fz_drawdrawimage;
	dev->drawshade = fz_drawdrawshade;

	dev->popclip = fz_drawpopclip;

	return dev;
}

void
fz_freedrawdevice(fz_device *dev)
{
	fz_drawdevice *ddev = dev->user;
	fz_dropcolorspace(ddev->model);
	fz_freeglyphcache(ddev->cache);
	fz_freegel(ddev->gel);
	fz_freeael(ddev->ael);
	fz_free(ddev);
	fz_free(dev);
}
