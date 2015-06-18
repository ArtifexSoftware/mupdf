#ifndef MUPDF_FITZ_SEPARATION_H
#define MUPDF_FITZ_SEPARATION_H

#include "mupdf/fitz/system.h"
#include "mupdf/fitz/context.h"

enum
{
	FZ_MAX_SEPARATIONS = 64
};

typedef struct fz_separations_s fz_separations;

fz_separations *fz_new_separations(fz_context *ctx);
fz_separations *fz_keep_separations(fz_context *ctx, fz_separations *sep);
void fz_drop_separations(fz_context *ctx, fz_separations *sep);
void fz_add_separation(fz_context *ctx, fz_separations *sep, uint32_t rgb, uint32_t cmyk, char *name);
void fz_control_separation(fz_context *ctx, fz_separations *sep, int separation, int disable);
int fz_separation_disabled(fz_context *ctx, fz_separations *sep, int separation);
int fz_separations_all_enabled(fz_context *ctx, fz_separations *sep);
const char *fz_get_separation(fz_context *ctx, fz_separations *sep, int separation, uint32_t *rgb, uint32_t *cmyk);
int fz_count_separations(fz_context *ctx, fz_separations *sep);

#endif
