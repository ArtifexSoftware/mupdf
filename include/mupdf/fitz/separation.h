#ifndef MUPDF_FITZ_SEPARATION_H
#define MUPDF_FITZ_SEPARATION_H

#include "mupdf/fitz/system.h"
#include "mupdf/fitz/context.h"

/*
	An fz_separation structure holds details of a set of separations
	(such as might be used on within a page of the document).

	The app might control the separations by enabling/disabling them,
	and subsequent renders would take this into account.
*/

enum
{
	FZ_MAX_SEPARATIONS = 64
};

typedef struct fz_separations_s fz_separations;

/* Create a new separations structure (initially empty) */
fz_separations *fz_new_separations(fz_context *ctx);

/* Add a reference */
fz_separations *fz_keep_separations(fz_context *ctx, fz_separations *sep);

/* Drop a reference */
void fz_drop_separations(fz_context *ctx, fz_separations *sep);

/* Add a separation (RGBA and CYMK equivalents, null terminated name) */
void fz_add_separation(fz_context *ctx, fz_separations *sep, uint32_t rgba, uint32_t cmyk, char *name);

/* Enable or disable a given separation */
void fz_control_separation(fz_context *ctx, fz_separations *sep, int separation, int disable);

/* Test for a separation being enabled or disabled */
int fz_separation_disabled(fz_context *ctx, fz_separations *sep, int separation);

/* Quick test for all separations enabled (the common case) */
int fz_separations_all_enabled(fz_context *ctx, fz_separations *sep);

/* Read separation details */
const char *fz_get_separation(fz_context *ctx, fz_separations *sep, int separation, uint32_t *rgb, uint32_t *cmyk);

/* Count the number of separations */
int fz_count_separations(fz_context *ctx, fz_separations *sep);

#endif
