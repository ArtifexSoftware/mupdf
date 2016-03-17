#ifndef MUPDF_FITZ_OUTPUT_PNM_H
#define MUPDF_FITZ_OUTPUT_PNM_H

#include "mupdf/fitz/system.h"
#include "mupdf/fitz/context.h"
#include "mupdf/fitz/output.h"
#include "mupdf/fitz/pixmap.h"
#include "mupdf/fitz/bitmap.h"

/*
	fz_save_pixmap_as_pnm: Save a pixmap as a PNM image file.
*/
void fz_save_pixmap_as_pnm(fz_context *ctx, fz_pixmap *pixmap, char *filename);

void fz_write_pixmap_as_pnm(fz_context *ctx, fz_output *out, fz_pixmap *pixmap);
void fz_write_pnm_header(fz_context *ctx, fz_output *out, int w, int h, int n);
void fz_write_pnm_band(fz_context *ctx, fz_output *out, int w, int h, int n, int band, int bandheight, unsigned char *p);

/*
	fz_save_pixmap_as_pam: Save a pixmap as a PAM image file.
*/
void fz_save_pixmap_as_pam(fz_context *ctx, fz_pixmap *pixmap, char *filename, int savealpha);

void fz_write_pixmap_as_pam(fz_context *ctx, fz_output *out, fz_pixmap *pixmap, int savealpha);
void fz_write_pam_header(fz_context *ctx, fz_output *out, int w, int h, int n, int savealpha);
void fz_write_pam_band(fz_context *ctx, fz_output *out, int w, int h, int n, int band, int bandheight, unsigned char *sp, int savealpha);

/*
	fz_save_bitmap_as_pbm: Save a bitmap as a PBM image file.
*/
void fz_save_bitmap_as_pbm(fz_context *ctx, fz_bitmap *bitmap, char *filename);

void fz_write_bitmap_as_pbm(fz_context *ctx, fz_output *out, fz_bitmap *bitmap);

void fz_write_pbm_header(fz_context *ctx, fz_output *out, int w, int h);

void fz_write_pbm_band(fz_context *ctx, fz_output *out, fz_bitmap *bitmap);

/*
	fz_save_bitmap_as_pkm: Save a 4bpp cmyk bitmap as a PAM image file.
*/
void fz_save_bitmap_as_pkm(fz_context *ctx, fz_bitmap *bitmap, char *filename);

void fz_write_bitmap_as_pkm(fz_context *ctx, fz_output *out, fz_bitmap *bitmap);

void fz_write_pkm_header(fz_context *ctx, fz_output *out, int w, int h);

void fz_write_pkm_band(fz_context *ctx, fz_output *out, fz_bitmap *bitmap);

#endif
