#include "mupdf/fitz.h"

enum
{
	FZ_SEPARATION_DISABLED_RENDER = 3
};


struct fz_separations_s
{
	int refs;
	int num_separations;
	int controllable;
	uint32_t state[(2*FZ_MAX_SEPARATIONS + 31) / 32];
	uint32_t equiv_rgb[FZ_MAX_SEPARATIONS];
	uint32_t equiv_cmyk[FZ_MAX_SEPARATIONS];
	char *name[FZ_MAX_SEPARATIONS];
};

fz_separations *fz_new_separations(fz_context *ctx, int controllable)
{
	fz_separations *sep;

	sep = fz_malloc_struct(ctx, fz_separations);
	sep->refs = 1;
	sep->controllable = controllable;

	return sep;
}

fz_separations *fz_keep_separations(fz_context *ctx, fz_separations *sep)
{
	return fz_keep_imp(ctx, sep, &sep->refs);
}

void fz_drop_separations(fz_context *ctx, fz_separations *sep)
{
	if (fz_drop_imp(ctx, sep, &sep->refs))
	{
		int i;
		for (i = 0; i < sep->num_separations; i++)
			fz_free(ctx, sep->name[i]);
		fz_free(ctx, sep);
	}
}

void fz_add_separation(fz_context *ctx, fz_separations *sep, uint32_t rgb, uint32_t cmyk, const char *name)
{
	int n;

	if (!sep)
		fz_throw(ctx, FZ_ERROR_GENERIC, "can't add to non-existent separations");

	n = sep->num_separations;
	if (n == FZ_MAX_SEPARATIONS)
		fz_throw(ctx, FZ_ERROR_GENERIC, "too many separations");

	sep->name[n] = fz_strdup(ctx, name);
	sep->equiv_rgb[n] = rgb;
	sep->equiv_cmyk[n] = cmyk;

	sep->num_separations++;
}

int fz_separations_controllable(fz_context *ctx, const fz_separations *sep)
{
	return (!sep || sep->controllable);
}

void fz_set_separation_behavior(fz_context *ctx, fz_separations *sep, int separation, fz_separation_behavior beh)
{
	int shift;
	fz_separation_behavior old;

	if (!sep || separation < 0 || separation >= sep->num_separations)
		fz_throw(ctx, FZ_ERROR_GENERIC, "can't control non-existent separation");

	if (beh == FZ_SEPARATION_DISABLED && !sep->controllable)
		beh = FZ_SEPARATION_DISABLED_RENDER;

	shift = ((2*separation) & 31);
	separation >>= 4;

	old = (sep->state[separation]>>shift) & 3;

	if (old == (fz_separation_behavior)FZ_SEPARATION_DISABLED_RENDER)
		old = FZ_SEPARATION_DISABLED;

	/* If no change, great */
	if (old == beh)
		return;

	sep->state[separation] = (sep->state[separation] & ~(3<<shift)) | (beh<<shift);

	/* FIXME: Could only empty images from the store, or maybe only
	 * images that depend on separations. */
	fz_empty_store(ctx);
}

static inline fz_separation_behavior
sep_state(const fz_separations *sep, int i)
{
	return (fz_separation_behavior)((sep->state[i>>5]>>((2*i) & 31)) & 3);
}

fz_separation_behavior fz_separation_current_behavior_internal(fz_context *ctx, const fz_separations *sep, int separation)
{
	if (!sep || separation < 0 || separation >= sep->num_separations)
		fz_throw(ctx, FZ_ERROR_GENERIC, "can't disable non-existent separation");

	return sep_state(sep, separation);
}

fz_separation_behavior fz_separation_current_behavior(fz_context *ctx, const fz_separations *sep, int separation)
{
	int beh = fz_separation_current_behavior_internal(ctx, sep, separation);

	if (beh == FZ_SEPARATION_DISABLED_RENDER)
		return FZ_SEPARATION_DISABLED;
	return beh;
}

int fz_separations_all_composite(fz_context *ctx, const fz_separations *sep)
{
	int i;

	if (!sep)
		return 1;

	for (i = 0; i < (FZ_MAX_SEPARATIONS + 31) / 32; i++)
		if (sep->state[i] != FZ_SEPARATION_COMPOSITE)
			return 0;

	return 1;
}

const char *fz_get_separation(fz_context *ctx, const fz_separations *sep, int separation, uint32_t *rgb, uint32_t *cmyk)
{
	if (!sep || separation < 0 || separation >= sep->num_separations)
		fz_throw(ctx, FZ_ERROR_GENERIC, "can't access non-existent separation");

	if (rgb)
		*rgb = sep->equiv_rgb[separation];
	if (cmyk)
		*cmyk = sep->equiv_cmyk[separation];

	return sep->name[separation];
}

int fz_count_separations(fz_context *ctx, const fz_separations *sep)
{
	if (!sep)
		return 0;
	return sep->num_separations;
}

int fz_count_active_separations(fz_context *ctx, const fz_separations *sep)
{
	int i, n, c;

	if (!sep)
		return 0;
	n = sep->num_separations;
	c = 0;
	for (i = 0; i < n; i++)
		if (sep_state(sep, i) == FZ_SEPARATION_SPOT)
			c++;
	return c;
}

fz_separations *fz_clone_separations_for_overprint(fz_context *ctx, fz_separations *sep)
{
	int i, j, n, c;
	fz_separations *clone;

	if (!sep)
		return NULL;

	n = sep->num_separations;
	c = 0;
	for (i = 0; i < n; i++)
	{
		fz_separation_behavior state = sep_state(sep, i);
		if (state == FZ_SEPARATION_COMPOSITE)
			c++;
	}

	/* If no composites, then we are fine to render direct. */
	if (c == 0)
		return NULL;

	/* We need to clone us a separation structure, with all
	 * the composite separations marked as enabled. */
	clone = fz_malloc_struct(ctx, fz_separations);

	fz_try(ctx)
	{
		clone->refs = 1;
		clone->controllable = 0;
		for (i = 0; i < n; i++)
		{
			fz_separation_behavior beh = sep_state(sep, i);
			if (beh == FZ_SEPARATION_DISABLED)
				continue;
			j = clone->num_separations++;
			if (beh == FZ_SEPARATION_COMPOSITE)
				beh = FZ_SEPARATION_SPOT;
			fz_set_separation_behavior(ctx, clone, j, beh);
			clone->name[j] = sep->name[i] ? fz_strdup(ctx, sep->name[i]) : NULL;
			clone->equiv_rgb[j] = sep->equiv_rgb[i];
			clone->equiv_cmyk[j] = sep->equiv_cmyk[i];
		}
	}
	fz_catch(ctx)
	{
		fz_drop_separations(ctx, clone);
		fz_rethrow(ctx);
	}

	return clone;
}

fz_pixmap *
fz_clone_pixmap_area_with_different_seps(fz_context *ctx, fz_pixmap *src, const fz_irect *bbox, fz_colorspace *dcs, fz_separations *dseps, fz_colorspace *prf, fz_default_colorspaces *default_cs)
{
	fz_irect local_bbox;
	fz_pixmap *dst;
	fz_colorspace *oi = fz_default_output_intent(ctx, default_cs);

	if (fz_colorspace_n(ctx, dcs) == fz_colorspace_n(ctx, oi))
		dcs = oi;

	if (bbox == NULL)
	{
		local_bbox.x0 = src->x;
		local_bbox.y0 = src->y;
		local_bbox.x1 = src->x + src->w;
		local_bbox.y1 = src->y + src->h;
		bbox = &local_bbox;
	}

	dst = fz_new_pixmap_with_bbox(ctx, dcs, bbox, dseps, src->alpha);
	if (src->flags & FZ_PIXMAP_FLAG_INTERPOLATE)
		dst->flags |= FZ_PIXMAP_FLAG_INTERPOLATE;
	else
		dst->flags &= ~FZ_PIXMAP_FLAG_INTERPOLATE;

	return fz_copy_pixmap_area_converting_seps(ctx, dst, src, prf, default_cs);
}

fz_pixmap *
fz_copy_pixmap_area_converting_seps(fz_context *ctx, fz_pixmap *dst, fz_pixmap *src, fz_colorspace *prf, fz_default_colorspaces *default_cs)
{
	int dw = dst->w;
	int dh = dst->h;
	fz_separations *sseps = src->seps;
	fz_separations *dseps = dst->seps;
	int sseps_n = sseps ? sseps->num_separations : 0;
	int dseps_n = dseps ? dseps->num_separations : 0;
	int sstride = src->stride;
	int dstride = dst->stride;
	int sn = src->n;
	int dn = dst->n;
	int sa = src->alpha;
	int da = dst->alpha;
	int ss = src->s;
	int ds = dst->s;
	int sc = sn - ss - sa;
	int dc = dn - ds - da;
	const unsigned char *sdata = src->samples + sstride * (dst->y - src->y) + (dst->x - src->x) * sn;
	unsigned char *ddata = dst->samples;
	signed char map[FZ_MAX_COLORS];
	int x, y, i, j, k;
	unsigned char mapped[FZ_MAX_COLORS];
	int unmapped = sseps_n;

	assert(da == sa);
	assert(ss == fz_count_active_separations(ctx, sseps));
	assert(ds == fz_count_active_separations(ctx, dseps));

	dstride -= dn * dw;
	sstride -= sn * dw;

	/* Process colorants first */
	if (dst->colorspace == src->colorspace)
	{
		/* Simple copy */
		unsigned char *dd = ddata;
		const unsigned char *sd = sdata;
		for (y = dh; y > 0; y--)
		{
			for (x = dw; x > 0; x--)
			{
				for (i = 0; i < dn; i++)
					dd[i] = sd[i];
				dd += dn;
				sd += sn;
			}
			dd += dstride;
			sd += sstride;
		}
	}
	else
	{
		fz_pixmap_converter *pc = fz_lookup_pixmap_converter(ctx, dst->colorspace, src->colorspace);

		pc(ctx, dst, src, prf, default_cs, NULL, 0);
	}

	/* Make a map of what spots go where */
	for (i = 0, k = 0; i < dseps_n; i++)
	{
		const char *name;

		if (sep_state(dseps, i) >= FZ_SEPARATION_DISABLED)
			continue;
		name = dseps->name[i];
		map[k] = -1;
		mapped[k] = 0;
		for (j = 0; j < sseps_n; j++)
		{
			if (sep_state(sseps, j) >= FZ_SEPARATION_DISABLED)
				continue;
			if (!strcmp(name, sseps->name[j]))
			{
				map[k] = j;
				unmapped--;
				mapped[k] = 1;
				break;
			}
		}
		k++;
	}
	if (sa)
		map[k] = sseps_n;

	/* Now we need to make d[i] = map[i] < 0 : 255 ? s[map[i]] */

	{
		unsigned char *dd = ddata + dc;
		const unsigned char *sd = sdata + sc;
		for (y = dh; y > 0; y--)
		{
			for (x = dw; x > 0; x--)
			{
				for (i = 0; i < ds; i++)
					dd[i] = map[i] < 0 ? 255 : sd[map[i]];
				dd += dn;
				sd += sn;
			}
			dd += dstride;
			sd += sstride;
		}
	}

	/* If we've handled all the spots, we're done. */
	if (unmapped == 0)
		return dst;

	/* Still need to handle mapping 'lost' spots down to process colors */
	for (i = 0; i < sseps_n; i++)
	{
		uint8_t convert[4];
		uint32_t c;

		if (mapped[i])
			continue;
		/* Src spot i is not mapped. We need to convert that down. */
		switch (dc)
		{
		case 1: /* Grey */
			/* FIXME: Should we hold a grey equivalent in each spot? */
			c = sseps->equiv_rgb[i];
			convert[0] = ((c & 0xff) * 77 + ((c>>8) & 0xff) * 150 + ((c>>16) & 0xff) * 28 + 255)>>8;
			break;
		case 3: /* RGB */
			c = sseps->equiv_rgb[i];
			convert[0] = c;
			convert[1] = c>>8;
			convert[2] = c>>16;
			break;
		case 4: /* CMYK */
			c = sseps->equiv_cmyk[i];
			convert[0] = c;
			convert[1] = c>>8;
			convert[2] = c>>16;
			convert[3] = c>>24;
			break;
		}

		{
			unsigned char *dd = ddata;
			const unsigned char *sd = sdata + sc;
			for (y = dh; y > 0; y--)
			{
				for (x = dw; x > 0; x--)
				{
					unsigned char  v = sd[i];
					if (v == 0)
						continue;
					for (i = 0; i < dc; i++)
						dd[i] = fz_clampi(dd[i] + fz_mul255(v, convert[i]), 0, 255);
					dd += dn;
					sd += sn;
				}
				dd += dstride;
				sd += sstride;
			}
		}
	}

	return dst;
}

void fz_convert_separation_colors(fz_context *ctx, const fz_color_params *color_params, const fz_colorspace *dst_cs, const fz_separations *dst_seps, float *dst_color, const fz_colorspace *src_cs, const float *src_color)
{
	int i, j, n, dc, ds, dn, pred;
	float remainders[FZ_MAX_COLORS];
	int remaining = 0;

	assert(dst_cs && dst_seps && src_cs && dst_color && src_color);
	assert(fz_colorspace_is_device_n(ctx, src_cs));

	dc = fz_colorspace_n(ctx, dst_cs);
	ds = dst_seps->num_separations;
	dn = dc + ds;

	i = 0;
	if (!fz_colorspace_is_subtractive(ctx, dst_cs))
		for (; i < dc; i++)
			dst_color[i] = 1;
	for (; i < dn; i++)
		dst_color[i] = 0;

	n = fz_colorspace_n(ctx, src_cs);
	pred = 0;
	for (i = 0; i < n; i++)
	{
		const char *name = fz_colorspace_colorant(ctx, src_cs, i);

		if (i == 0 && !strcmp(name, "All"))
		{
			/* This is only supposed to happen in separation spaces, not DeviceN */
			if (n != 1)
				fz_warn(ctx, "All found in DeviceN space");
			for (i = 0; i < dn; i++)
				dst_color[i] = src_color[0];
			break;
		}
		if (!strcmp(name, "None"))
			continue;

		/* The most common case is that the colorant we match is the
		 * one after the one we matched before, so optimise for that. */
		for (j = pred; j < ds; j++)
		{
			const char *dname = dst_seps->name[j];
			if (!strcmp(name, dname))
				goto found_sep;
		}
		for (j = 0; j < pred; j++)
		{
			const char *dname = dst_seps->name[j];
			if (!strcmp(name, dname))
				goto found_sep;
		}
		for (j = 0; j < dc; j++)
		{
			const char *dname = fz_colorspace_colorant(ctx, dst_cs, j);
			if (!strcmp(name, dname))
				goto found_process;
		}
		if (0) {
found_sep:
			dst_color[j+dc] = src_color[i];
			pred = j+1;
		}
		else if (0)
		{
found_process:
			dst_color[j] += src_color[i];
		}
		else
		{
			if (remaining == 0)
			{
				memset(remainders, 0, sizeof(float) * n);
				remaining = 1;
			}
			remainders[i] = src_color[i];
		}
	}

	if (remaining)
	{
		/* There were some spots that didn't copy over */
		float converted[FZ_MAX_COLORS];
		fz_convert_color(ctx, color_params, NULL, dst_cs, converted, src_cs, remainders);

		for (i = 0; i < dc; i++)
			dst_color[i] += converted[i];
	}
}
