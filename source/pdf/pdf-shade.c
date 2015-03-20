#include "mupdf/pdf.h"

/* FIXME: Remove this somehow */
#define FUNSEGS 32 /* size of sampled mesh for function-based shadings */

/* Sample various functions into lookup tables */

static void
pdf_sample_composite_shade_function(fz_context *ctx, fz_shade *shade, fz_function *func, float t0, float t1)
{
	int i;
	float t;

	for (i = 0; i < 256; i++)
	{
		t = t0 + (i / 255.0f) * (t1 - t0);
		fz_eval_function(ctx, func, &t, 1, shade->function[i], shade->colorspace->n);
		shade->function[i][shade->colorspace->n] = 1;
	}
}

static void
pdf_sample_component_shade_function(fz_context *ctx, fz_shade *shade, int funcs, fz_function **func, float t0, float t1)
{
	int i, k;
	float t;

	for (i = 0; i < 256; i++)
	{
		t = t0 + (i / 255.0f) * (t1 - t0);
		for (k = 0; k < funcs; k++)
			fz_eval_function(ctx, func[k], &t, 1, &shade->function[i][k], 1);
		shade->function[i][k] = 1;
	}
}

static void
pdf_sample_shade_function(fz_context *ctx, fz_shade *shade, int funcs, fz_function **func, float t0, float t1)
{
	shade->use_function = 1;
	if (funcs == 1)
		pdf_sample_composite_shade_function(ctx, shade, func[0], t0, t1);
	else
		pdf_sample_component_shade_function(ctx, shade, funcs, func, t0, t1);
}

/* Type 1-3 -- Function-based, linear and radial shadings */

static void
pdf_load_function_based_shading(fz_context *ctx, pdf_document *doc, fz_shade *shade, pdf_obj *dict, fz_function *func)
{
	pdf_obj *obj;
	float x0, y0, x1, y1;
	float fv[2];
	fz_matrix matrix;
	int xx, yy;
	float *p;

	x0 = y0 = 0;
	x1 = y1 = 1;
	obj = pdf_dict_get(ctx, dict, PDF_NAME_Domain);
	if (obj)
	{
		x0 = pdf_to_real(ctx, pdf_array_get(ctx, obj, 0));
		x1 = pdf_to_real(ctx, pdf_array_get(ctx, obj, 1));
		y0 = pdf_to_real(ctx, pdf_array_get(ctx, obj, 2));
		y1 = pdf_to_real(ctx, pdf_array_get(ctx, obj, 3));
	}

	obj = pdf_dict_get(ctx, dict, PDF_NAME_Matrix);
	if (obj)
		pdf_to_matrix(ctx, obj, &matrix);
	else
		matrix = fz_identity;
	shade->u.f.matrix = matrix;
	shade->u.f.xdivs = FUNSEGS;
	shade->u.f.ydivs = FUNSEGS;
	shade->u.f.fn_vals = fz_malloc(ctx, (FUNSEGS+1)*(FUNSEGS+1)*shade->colorspace->n*sizeof(float));
	shade->u.f.domain[0][0] = x0;
	shade->u.f.domain[0][1] = y0;
	shade->u.f.domain[1][0] = x1;
	shade->u.f.domain[1][1] = y1;

	p = shade->u.f.fn_vals;
	for (yy = 0; yy <= FUNSEGS; yy++)
	{
		fv[1] = y0 + (y1 - y0) * yy / FUNSEGS;

		for (xx = 0; xx <= FUNSEGS; xx++)
		{
			fv[0] = x0 + (x1 - x0) * xx / FUNSEGS;

			fz_eval_function(ctx, func, fv, 2, p, shade->colorspace->n);
			p += shade->colorspace->n;
		}
	}
}

static void
pdf_load_linear_shading(fz_context *ctx, pdf_document *doc, fz_shade *shade, pdf_obj *dict, int funcs, fz_function **func)
{
	pdf_obj *obj;
	float d0, d1;
	int e0, e1;

	obj = pdf_dict_get(ctx, dict, PDF_NAME_Coords);
	shade->u.l_or_r.coords[0][0] = pdf_to_real(ctx, pdf_array_get(ctx, obj, 0));
	shade->u.l_or_r.coords[0][1] = pdf_to_real(ctx, pdf_array_get(ctx, obj, 1));
	shade->u.l_or_r.coords[1][0] = pdf_to_real(ctx, pdf_array_get(ctx, obj, 2));
	shade->u.l_or_r.coords[1][1] = pdf_to_real(ctx, pdf_array_get(ctx, obj, 3));

	d0 = 0;
	d1 = 1;
	obj = pdf_dict_get(ctx, dict, PDF_NAME_Domain);
	if (obj)
	{
		d0 = pdf_to_real(ctx, pdf_array_get(ctx, obj, 0));
		d1 = pdf_to_real(ctx, pdf_array_get(ctx, obj, 1));
	}

	e0 = e1 = 0;
	obj = pdf_dict_get(ctx, dict, PDF_NAME_Extend);
	if (obj)
	{
		e0 = pdf_to_bool(ctx, pdf_array_get(ctx, obj, 0));
		e1 = pdf_to_bool(ctx, pdf_array_get(ctx, obj, 1));
	}

	pdf_sample_shade_function(ctx, shade, funcs, func, d0, d1);

	shade->u.l_or_r.extend[0] = e0;
	shade->u.l_or_r.extend[1] = e1;
}

static void
pdf_load_radial_shading(fz_context *ctx, pdf_document *doc, fz_shade *shade, pdf_obj *dict, int funcs, fz_function **func)
{
	pdf_obj *obj;
	float d0, d1;
	int e0, e1;

	obj = pdf_dict_get(ctx, dict, PDF_NAME_Coords);
	shade->u.l_or_r.coords[0][0] = pdf_to_real(ctx, pdf_array_get(ctx, obj, 0));
	shade->u.l_or_r.coords[0][1] = pdf_to_real(ctx, pdf_array_get(ctx, obj, 1));
	shade->u.l_or_r.coords[0][2] = pdf_to_real(ctx, pdf_array_get(ctx, obj, 2));
	shade->u.l_or_r.coords[1][0] = pdf_to_real(ctx, pdf_array_get(ctx, obj, 3));
	shade->u.l_or_r.coords[1][1] = pdf_to_real(ctx, pdf_array_get(ctx, obj, 4));
	shade->u.l_or_r.coords[1][2] = pdf_to_real(ctx, pdf_array_get(ctx, obj, 5));

	d0 = 0;
	d1 = 1;
	obj = pdf_dict_get(ctx, dict, PDF_NAME_Domain);
	if (obj)
	{
		d0 = pdf_to_real(ctx, pdf_array_get(ctx, obj, 0));
		d1 = pdf_to_real(ctx, pdf_array_get(ctx, obj, 1));
	}

	e0 = e1 = 0;
	obj = pdf_dict_get(ctx, dict, PDF_NAME_Extend);
	if (obj)
	{
		e0 = pdf_to_bool(ctx, pdf_array_get(ctx, obj, 0));
		e1 = pdf_to_bool(ctx, pdf_array_get(ctx, obj, 1));
	}

	pdf_sample_shade_function(ctx, shade, funcs, func, d0, d1);

	shade->u.l_or_r.extend[0] = e0;
	shade->u.l_or_r.extend[1] = e1;
}

/* Type 4-7 -- Triangle and patch mesh shadings */

struct mesh_params
{
	int vprow;
	int bpflag;
	int bpcoord;
	int bpcomp;
	float x0, x1;
	float y0, y1;
	float c0[FZ_MAX_COLORS];
	float c1[FZ_MAX_COLORS];
};

static void
pdf_load_mesh_params(fz_context *ctx, pdf_document *doc, fz_shade *shade, pdf_obj *dict)
{
	pdf_obj *obj;
	int i, n;

	shade->u.m.x0 = shade->u.m.y0 = 0;
	shade->u.m.x1 = shade->u.m.y1 = 1;
	for (i = 0; i < FZ_MAX_COLORS; i++)
	{
		shade->u.m.c0[i] = 0;
		shade->u.m.c1[i] = 1;
	}

	shade->u.m.vprow = pdf_to_int(ctx, pdf_dict_get(ctx, dict, PDF_NAME_VerticesPerRow));
	shade->u.m.bpflag = pdf_to_int(ctx, pdf_dict_get(ctx, dict, PDF_NAME_BitsPerFlag));
	shade->u.m.bpcoord = pdf_to_int(ctx, pdf_dict_get(ctx, dict, PDF_NAME_BitsPerCoordinate));
	shade->u.m.bpcomp = pdf_to_int(ctx, pdf_dict_get(ctx, dict, PDF_NAME_BitsPerComponent));

	obj = pdf_dict_get(ctx, dict, PDF_NAME_Decode);
	if (pdf_array_len(ctx, obj) >= 6)
	{
		n = (pdf_array_len(ctx, obj) - 4) / 2;
		shade->u.m.x0 = pdf_to_real(ctx, pdf_array_get(ctx, obj, 0));
		shade->u.m.x1 = pdf_to_real(ctx, pdf_array_get(ctx, obj, 1));
		shade->u.m.y0 = pdf_to_real(ctx, pdf_array_get(ctx, obj, 2));
		shade->u.m.y1 = pdf_to_real(ctx, pdf_array_get(ctx, obj, 3));
		for (i = 0; i < n; i++)
		{
			shade->u.m.c0[i] = pdf_to_real(ctx, pdf_array_get(ctx, obj, 4 + i * 2));
			shade->u.m.c1[i] = pdf_to_real(ctx, pdf_array_get(ctx, obj, 5 + i * 2));
		}
	}

	if (shade->u.m.vprow < 2 && shade->type == 5)
	{
		fz_warn(ctx, "Too few vertices per row (%d)", shade->u.m.vprow);
		shade->u.m.vprow = 2;
	}

	if (shade->u.m.bpflag != 2 && shade->u.m.bpflag != 4 && shade->u.m.bpflag != 8 &&
		shade->type != 5)
	{
		fz_warn(ctx, "Invalid number of bits per flag (%d)", shade->u.m.bpflag);
		shade->u.m.bpflag = 8;
	}

	if (shade->u.m.bpcoord != 1 && shade->u.m.bpcoord != 2 && shade->u.m.bpcoord != 4 &&
		shade->u.m.bpcoord != 8 && shade->u.m.bpcoord != 12 && shade->u.m.bpcoord != 16 &&
		shade->u.m.bpcoord != 24 && shade->u.m.bpcoord != 32)
	{
		fz_warn(ctx, "Invalid number of bits per coordinate (%d)", shade->u.m.bpcoord);
		shade->u.m.bpcoord = 8;
	}

	if (shade->u.m.bpcomp != 1 && shade->u.m.bpcomp != 2 && shade->u.m.bpcomp != 4 &&
		shade->u.m.bpcomp != 8 && shade->u.m.bpcomp != 12 && shade->u.m.bpcomp != 16)
	{
		fz_warn(ctx, "Invalid number of bits per component (%d)", shade->u.m.bpcomp);
		shade->u.m.bpcomp = 8;
	}
}

static void
pdf_load_type4_shade(fz_context *ctx, pdf_document *doc, fz_shade *shade, pdf_obj *dict, int funcs, fz_function **func)
{

	pdf_load_mesh_params(ctx, doc, shade, dict);

	if (funcs > 0)
		pdf_sample_shade_function(ctx, shade, funcs, func, shade->u.m.c0[0], shade->u.m.c1[0]);

	shade->buffer = pdf_load_compressed_stream(ctx, doc, pdf_to_num(ctx, dict), pdf_to_gen(ctx, dict));
}

static void
pdf_load_type5_shade(fz_context *ctx, pdf_document *doc, fz_shade *shade, pdf_obj *dict, int funcs, fz_function **func)
{

	pdf_load_mesh_params(ctx, doc, shade, dict);

	if (funcs > 0)
		pdf_sample_shade_function(ctx, shade, funcs, func, shade->u.m.c0[0], shade->u.m.c1[0]);

	shade->buffer = pdf_load_compressed_stream(ctx, doc, pdf_to_num(ctx, dict), pdf_to_gen(ctx, dict));
}

/* Type 6 & 7 -- Patch mesh shadings */

static void
pdf_load_type6_shade(fz_context *ctx, pdf_document *doc, fz_shade *shade, pdf_obj *dict, int funcs, fz_function **func)
{

	pdf_load_mesh_params(ctx, doc, shade, dict);

	if (funcs > 0)
		pdf_sample_shade_function(ctx, shade, funcs, func, shade->u.m.c0[0], shade->u.m.c1[0]);

	shade->buffer = pdf_load_compressed_stream(ctx, doc, pdf_to_num(ctx, dict), pdf_to_gen(ctx, dict));
}

static void
pdf_load_type7_shade(fz_context *ctx, pdf_document *doc, fz_shade *shade, pdf_obj *dict, int funcs, fz_function **func)
{

	pdf_load_mesh_params(ctx, doc, shade, dict);

	if (funcs > 0)
		pdf_sample_shade_function(ctx, shade, funcs, func, shade->u.m.c0[0], shade->u.m.c1[0]);

	shade->buffer = pdf_load_compressed_stream(ctx, doc, pdf_to_num(ctx, dict), pdf_to_gen(ctx, dict));
}

/* Load all of the shading dictionary parameters, then switch on the shading type. */

static fz_shade *
pdf_load_shading_dict(fz_context *ctx, pdf_document *doc, pdf_obj *dict, const fz_matrix *transform)
{
	fz_shade *shade = NULL;
	fz_function *func[FZ_MAX_COLORS] = { NULL };
	pdf_obj *obj;
	int funcs = 0;
	int type = 0;
	int i, in, out;

	fz_var(shade);
	fz_var(func);
	fz_var(funcs);
	fz_var(type);

	fz_try(ctx)
	{
		shade = fz_malloc_struct(ctx, fz_shade);
		FZ_INIT_STORABLE(shade, 1, fz_drop_shade_imp);
		shade->type = FZ_MESH_TYPE4;
		shade->use_background = 0;
		shade->use_function = 0;
		shade->matrix = *transform;
		shade->bbox = fz_infinite_rect;

		shade->colorspace = NULL;

		funcs = 0;

		obj = pdf_dict_get(ctx, dict, PDF_NAME_ShadingType);
		type = pdf_to_int(ctx, obj);

		obj = pdf_dict_get(ctx, dict, PDF_NAME_ColorSpace);
		if (!obj)
			fz_throw(ctx, FZ_ERROR_GENERIC, "shading colorspace is missing");
		shade->colorspace = pdf_load_colorspace(ctx, doc, obj);

		obj = pdf_dict_get(ctx, dict, PDF_NAME_Background);
		if (obj)
		{
			shade->use_background = 1;
			for (i = 0; i < shade->colorspace->n; i++)
				shade->background[i] = pdf_to_real(ctx, pdf_array_get(ctx, obj, i));
		}

		obj = pdf_dict_get(ctx, dict, PDF_NAME_BBox);
		if (pdf_is_array(ctx, obj))
			pdf_to_rect(ctx, obj, &shade->bbox);

		obj = pdf_dict_get(ctx, dict, PDF_NAME_Function);
		if (pdf_is_dict(ctx, obj))
		{
			funcs = 1;

			if (type == 1)
				in = 2;
			else
				in = 1;
			out = shade->colorspace->n;

			func[0] = pdf_load_function(ctx, doc, obj, in, out);
			if (!func[0])
				fz_throw(ctx, FZ_ERROR_GENERIC, "cannot load shading function (%d %d R)", pdf_to_num(ctx, obj), pdf_to_gen(ctx, obj));
		}
		else if (pdf_is_array(ctx, obj))
		{
			funcs = pdf_array_len(ctx, obj);
			if (funcs != 1 && funcs != shade->colorspace->n)
			{
				funcs = 0;
				fz_throw(ctx, FZ_ERROR_GENERIC, "incorrect number of shading functions");
			}
			if (funcs > FZ_MAX_COLORS)
			{
				funcs = 0;
				fz_throw(ctx, FZ_ERROR_GENERIC, "too many shading functions");
			}

			if (type == 1)
				in = 2;
			else
				in = 1;
			out = 1;

			for (i = 0; i < funcs; i++)
			{
				func[i] = pdf_load_function(ctx, doc, pdf_array_get(ctx, obj, i), in, out);
				if (!func[i])
					fz_throw(ctx, FZ_ERROR_GENERIC, "cannot load shading function (%d %d R)", pdf_to_num(ctx, obj), pdf_to_gen(ctx, obj));
			}
		}
		else if (type < 4)
		{
			/* Functions are compulsory for types 1,2,3 */
			fz_throw(ctx, FZ_ERROR_GENERIC, "cannot load shading function (%d %d R)", pdf_to_num(ctx, obj), pdf_to_gen(ctx, obj));
		}

		shade->type = type;
		switch (type)
		{
		case 1: pdf_load_function_based_shading(ctx, doc, shade, dict, func[0]); break;
		case 2: pdf_load_linear_shading(ctx, doc, shade, dict, funcs, func); break;
		case 3: pdf_load_radial_shading(ctx, doc, shade, dict, funcs, func); break;
		case 4: pdf_load_type4_shade(ctx, doc, shade, dict, funcs, func); break;
		case 5: pdf_load_type5_shade(ctx, doc, shade, dict, funcs, func); break;
		case 6: pdf_load_type6_shade(ctx, doc, shade, dict, funcs, func); break;
		case 7: pdf_load_type7_shade(ctx, doc, shade, dict, funcs, func); break;
		default:
			fz_throw(ctx, FZ_ERROR_GENERIC, "unknown shading type: %d", type);
		}
	}
	fz_always(ctx)
	{
		for (i = 0; i < funcs; i++)
			if (func[i])
				fz_drop_function(ctx, func[i]);
	}
	fz_catch(ctx)
	{
		fz_drop_shade(ctx, shade);

		fz_rethrow_message(ctx, "cannot load shading type %d (%d %d R)", type, pdf_to_num(ctx, dict), pdf_to_gen(ctx, dict));
	}
	return shade;
}

static unsigned int
fz_shade_size(fz_shade *s)
{
	if (s == NULL)
		return 0;
	if (s->type == FZ_FUNCTION_BASED)
		return sizeof(*s) + sizeof(float) * s->u.f.xdivs * s->u.f.ydivs * s->colorspace->n;
	return sizeof(*s) + fz_compressed_buffer_size(s->buffer);
}

fz_shade *
pdf_load_shading(fz_context *ctx, pdf_document *doc, pdf_obj *dict)
{
	fz_matrix mat;
	pdf_obj *obj;
	fz_shade *shade;

	if ((shade = pdf_find_item(ctx, fz_drop_shade_imp, dict)) != NULL)
	{
		return shade;
	}

	/* Type 2 pattern dictionary */
	if (pdf_dict_get(ctx, dict, PDF_NAME_PatternType))
	{
		obj = pdf_dict_get(ctx, dict, PDF_NAME_Matrix);
		if (obj)
			pdf_to_matrix(ctx, obj, &mat);
		else
			mat = fz_identity;

		obj = pdf_dict_get(ctx, dict, PDF_NAME_ExtGState);
		if (obj)
		{
			if (pdf_dict_get(ctx, obj, PDF_NAME_CA) || pdf_dict_get(ctx, obj, PDF_NAME_ca))
			{
				fz_warn(ctx, "shading with alpha not supported");
			}
		}

		obj = pdf_dict_get(ctx, dict, PDF_NAME_Shading);
		if (!obj)
			fz_throw(ctx, FZ_ERROR_GENERIC, "syntaxerror: missing shading dictionary");

		shade = pdf_load_shading_dict(ctx, doc, obj, &mat);
	}

	/* Naked shading dictionary */
	else
	{
		shade = pdf_load_shading_dict(ctx, doc, dict, &fz_identity);
	}

	pdf_store_item(ctx, dict, shade, fz_shade_size(shade));

	return shade;
}
