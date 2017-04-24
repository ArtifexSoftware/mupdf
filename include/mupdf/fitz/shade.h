#ifndef MUPDF_FITZ_SHADE_H
#define MUPDF_FITZ_SHADE_H

#include "mupdf/fitz/system.h"
#include "mupdf/fitz/context.h"
#include "mupdf/fitz/geometry.h"
#include "mupdf/fitz/store.h"
#include "mupdf/fitz/colorspace.h"
#include "mupdf/fitz/pixmap.h"
#include "mupdf/fitz/compressed-buffer.h"

/*
 * The shading code uses gouraud shaded triangle meshes.
 */

enum
{
	FZ_FUNCTION_BASED = 1,
	FZ_LINEAR = 2,
	FZ_RADIAL = 3,
	FZ_MESH_TYPE4 = 4,
	FZ_MESH_TYPE5 = 5,
	FZ_MESH_TYPE6 = 6,
	FZ_MESH_TYPE7 = 7
};

/*
	Structure is public to allow derived classes. Do not
	access the members directly.
*/
typedef struct fz_shade_s
{
	fz_storable storable;

	fz_rect bbox;		/* can be fz_infinite_rect */
	fz_colorspace *colorspace;

	fz_matrix matrix;	/* matrix from pattern dict */
	int use_background;	/* background color for fills but not 'sh' */
	float background[FZ_MAX_COLORS];

	int use_function;
	float function[256][FZ_MAX_COLORS + 1];

	int type; /* function, linear, radial, mesh */
	union
	{
		struct
		{
			int extend[2];
			float coords[2][3]; /* (x,y,r) twice */
		} l_or_r;
		struct
		{
			int vprow;
			int bpflag;
			int bpcoord;
			int bpcomp;
			float x0, x1;
			float y0, y1;
			float c0[FZ_MAX_COLORS];
			float c1[FZ_MAX_COLORS];
		} m;
		struct
		{
			fz_matrix matrix;
			int xdivs;
			int ydivs;
			float domain[2][2];
			float *fn_vals;
		} f;
	} u;

	fz_compressed_buffer *buffer;
} fz_shade;

/*
	fz_keep_shade: Add a reference to a fz_shade.

	shade: The reference to keep.

	Returns shade.
*/
fz_shade *fz_keep_shade(fz_context *ctx, fz_shade *shade);

/*
	fz_drop_shade: Drop a reference to a fz_shade.

	shade: The reference to drop. If this is the last
	reference, shade will be destroyed.
*/
void fz_drop_shade(fz_context *ctx, fz_shade *shade);

/*
	fz_drop_shade_imp: Internal function to destroy a
	shade. Only exposed for use with the fz_store.

	shade: The reference to destroy.
*/
void fz_drop_shade_imp(fz_context *ctx, fz_storable *shade);

/*
	fz_bound_shade: Bound a given shading.

	shade: The shade to bound.

	ctm: The transform to apply to the shade before bounding.

	r: Pointer to storage to put the bounds in.

	Returns r, updated to contain the bounds for the shading.
*/
fz_rect *fz_bound_shade(fz_context *ctx, fz_shade *shade, const fz_matrix *ctm, fz_rect *r);

/*
	fz_paint_shade: Render a shade to a given pixmap.

	shade: The shade to paint.

	ctm: The transform to apply.

	dest: The pixmap to render into.

	bbox: Pointer to a bounding box to limit the rendering
	of the shade.
*/
void fz_paint_shade(fz_context *ctx, fz_shade *shade, const fz_matrix *ctm, fz_pixmap *dest, const fz_irect *bbox);

/*
 *	Handy routine for processing mesh based shades
 */
typedef struct fz_vertex_s fz_vertex;

struct fz_vertex_s
{
	fz_point p;
	float c[FZ_MAX_COLORS];
};

/*
	fz_shade_prepare_fn: Callback function type for use with
	fz_process_shade.

	arg: Opaque pointer from fz_process_shade caller.

	v: Pointer to a fz_vertex structure to populate.

	c: Pointer to an array of floats used to populate v.
*/
typedef void (fz_shade_prepare_fn)(fz_context *ctx, void *arg, fz_vertex *v, const float *c);

/*
	fz_shade_process_fn: Callback function type for use with
	fz_process_shade.

	arg: Opaque pointer from fz_process_shade caller.

	av, bv, cv: Pointers to a fz_vertex structure describing
	the corner locations and colors of a triangle to be
	filled.
*/
typedef void (fz_shade_process_fn)(fz_context *ctx, void *arg, fz_vertex *av, fz_vertex *bv, fz_vertex *cv);

/*
	fz_process_shade: Process a shade, using supplied callback
	functions. This decomposes the shading to a mesh (even ones
	that are not natively meshes, such as linear or radial
	shadings), and processes triangles from those meshes.

	shade: The shade to process.

	ctm: The transform to use

	prepare: Callback function to 'prepare' each vertex.
	This function is passed an array of floats, and populates
	a fz_vertex structure.

	process: This function is passed 3 pointers to vertex
	structures, and actually performs the processing (typically
	filling the area between the vertexes).

	process_arg: An opaque argument passed through from caller
	to callback functions.
*/
void fz_process_shade(fz_context *ctx, fz_shade *shade, const fz_matrix *ctm,
			fz_shade_prepare_fn *prepare,
			fz_shade_process_fn *process,
			void *process_arg);

#endif
