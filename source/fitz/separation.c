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
