#ifndef MUPDF_FITZ_OUTPUT_PCL_H
#define MUPDF_FITZ_OUTPUT_PCL_H

#include "mupdf/fitz/system.h"
#include "mupdf/fitz/context.h"
#include "mupdf/fitz/output.h"
#include "mupdf/fitz/band-writer.h"
#include "mupdf/fitz/pixmap.h"
#include "mupdf/fitz/bitmap.h"

/*
	PCL output
*/
typedef struct fz_pcl_options_s fz_pcl_options;

struct fz_pcl_options_s
{
	/* Features of a particular printer */
	int features;
	const char *odd_page_init;
	const char *even_page_init;

	/* Options for this job */
	int tumble;
	int duplex_set;
	int duplex;
	int paper_size;
	int manual_feed_set;
	int manual_feed;
	int media_position_set;
	int media_position;
	int orientation;

	/* Updated as we move through the job */
	int page_count;
};

/*
	fz_pcl_preset: Initialize PCL option struct for a given preset.

	Currently defined presets include:

		generic	Generic PCL printer
		ljet4	HP DeskJet
		dj500	HP DeskJet 500
		fs600	Kyocera FS-600
		lj	HP LaserJet, HP LaserJet Plus
		lj2	HP LaserJet IIp, HP LaserJet IId
		lj3	HP LaserJet III
		lj3d	HP LaserJet IIId
		lj4	HP LaserJet 4
		lj4pl	HP LaserJet 4 PL
		lj4d	HP LaserJet 4d
		lp2563b	HP 2563B line printer
		oce9050	Oce 9050 Line printer
*/
void fz_pcl_preset(fz_context *ctx, fz_pcl_options *opts, const char *preset);

/*
	fz_parse_pcl_options: Parse PCL options.

	Currently defined options and values are as follows:

		preset=X	Either "generic" or one of the presets as for fz_pcl_preset.
		spacing=0	No vertical spacing capability
		spacing=1	PCL 3 spacing (<ESC>*p+<n>Y)
		spacing=2	PCL 4 spacing (<ESC>*b<n>Y)
		spacing=3	PCL 5 spacing (<ESC>*b<n>Y and clear seed row)
		mode2		Disable/Enable mode 2 graphics compression
		mode3		Disable/Enable mode 3 graphics compression
		eog_reset	End of graphics (<ESC>*rB) resets all parameters
		has_duplex	Duplex supported (<ESC>&l<duplex>S)
		has_papersize	Papersize setting supported (<ESC>&l<sizecode>A)
		has_copies	Number of copies supported (<ESC>&l<copies>X)
		is_ljet4pjl	Disable/Enable HP 4PJL model-specific output
		is_oce9050	Disable/Enable Oce 9050 model-specific output
*/
fz_pcl_options *fz_parse_pcl_options(fz_context *ctx, fz_pcl_options *opts, const char *args);

fz_band_writer *fz_new_mono_pcl_band_writer(fz_context *ctx, fz_output *out, const fz_pcl_options *options);
void fz_write_bitmap_as_pcl(fz_context *ctx, fz_output *out, const fz_bitmap *bitmap, const fz_pcl_options *pcl);
void fz_save_bitmap_as_pcl(fz_context *ctx, fz_bitmap *bitmap, char *filename, int append, const fz_pcl_options *pcl);

fz_band_writer *fz_new_color_pcl_band_writer(fz_context *ctx, fz_output *out, const fz_pcl_options *options);
void fz_write_pixmap_as_pcl(fz_context *ctx, fz_output *out, const fz_pixmap *pixmap, const fz_pcl_options *pcl);
void fz_save_pixmap_as_pcl(fz_context *ctx, fz_pixmap *pixmap, char *filename, int append, const fz_pcl_options *pcl);

#endif
