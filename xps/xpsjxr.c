/* JPEG-XR (formerly HD-Photo (formerly Windows Media Photo)) support */

#include "fitz.h"
#include "muxps.h"

#ifdef HAVE_JPEGXR

#ifdef _MSC_VER
#undef _MSC_VER
#endif

#include "jpegxr.h"

struct state { xps_context_t *ctx; xps_image_t *output; };

static const char *
jxr_error_string(int code)
{
	switch (code)
	{
	case JXR_EC_OK: return "No error";
	default:
	case JXR_EC_ERROR: return "Unspecified error";
	case JXR_EC_BADMAGIC: return "Stream lacks proper magic number";
	case JXR_EC_FEATURE_NOT_IMPLEMENTED: return "Feature not implemented";
	case JXR_EC_IO: return "Error reading/writing data";
	case JXR_EC_BADFORMAT: return "Bad file format";
	}
}

#define CLAMP(v, mn, mx) (v < mn ? mn : v > mx ? mx : v)

static inline int
scale_bits(int depth, int value)
{
	union { int iv; float fv; } bd32f;

	switch (depth)
	{
	case JXR_BD1WHITE1:
		return value * 255;
	case JXR_BD1BLACK1:
		return value ? 0 : 255;
	case JXR_BD8:
		return value;
	case JXR_BD16:
		return value >> 8;
	case JXR_BD16S: /* -4 .. 4 ; 8192 = 1.0 */
		value = value >> 5;
		return CLAMP(value, 0, 255);
	case JXR_BD32S: /* -128 .. 128 ; 16777216 = 1.0 */
		value = value >> 16;
		return CLAMP(value, 0, 255);
	case JXR_BD32F:
		bd32f.iv = value;
		value = bd32f.fv * 255;
		return CLAMP(value, 0, 255);
#if 0
	case JXR_BDRESERVED: return value;
	case JXR_BD16F: return value;
	case JXR_BD5: return value;
	case JXR_BD10: return value;
	case JXR_BD565: return value;
#endif
	}
	return value;
}

static void
xps_decode_jpegxr_block(jxr_image_t image, int mx, int my, int *data)
{
	struct state *state = jxr_get_user_data(image);
	xps_context_t *ctx = state->ctx;
	xps_image_t *output = state->output;
	int depth;
	unsigned char *p;
	int x, y, k;

	if (!output->samples)
	{
		output->width = jxr_get_IMAGE_WIDTH(image);
		output->height = jxr_get_IMAGE_HEIGHT(image);
		output->comps = jxr_get_IMAGE_CHANNELS(image);
		output->hasalpha = jxr_get_ALPHACHANNEL_FLAG(image);
		output->bits = 8;
		output->stride = output->width * output->comps;
		output->samples = xps_alloc(ctx, output->stride * output->height);

		switch (output->comps)
		{
		default:
		case 1: output->colorspace = ctx->gray; break;
		case 3: output->colorspace = ctx->srgb; break;
		case 4: output->colorspace = ctx->cmyk; break;
		}
	}

	depth = jxr_get_OUTPUT_BITDEPTH(image);

	my = my * 16;
	mx = mx * 16;

	for (y = 0; y < 16; y++)
	{
		if (my + y >= output->height)
			return;
		p = output->samples + (my + y) * output->stride + mx * output->comps;
		for (x = 0; x < 16; x++)
		{
			if (mx + x >= output->width)
				data += output->comps;
			else
				for (k = 0; k < output->comps; k++)
					*p++ = scale_bits(depth, *data++);
		}
	}
}

static void
xps_decode_jpegxr_alpha_block(jxr_image_t image, int mx, int my, int *data)
{
	struct state *state = jxr_get_user_data(image);
	xps_context_t *ctx = state->ctx;
	xps_image_t *output = state->output;
	int depth;
	unsigned char *p;
	int x, y, k;

	if (!output->alpha)
	{
		output->alpha = xps_alloc(ctx, output->width * output->height);
	}

	depth = jxr_get_OUTPUT_BITDEPTH(image);

	my = my * 16;
	mx = mx * 16;

	for (y = 0; y < 16; y++)
	{
		if (my + y >= output->height)
			return;
		p = output->alpha + (my + y) * output->width + mx;
		for (x = 0; x < 16; x++)
		{
			if (mx + x >= output->width)
				data ++;
			else
				*p++ = scale_bits(depth, *data++);
		}
	}
}

int
xps_decode_jpegxr(xps_context_t *ctx, byte *buf, int len, xps_image_t *output)
{
	FILE *file;
	char name[gp_file_name_sizeof];
	struct state state;
	jxr_container_t container;
	jxr_image_t image;
	int offset, alpha_offset;
	int rc;

	memset(output, 0, sizeof(*output));

	file = gp_open_scratch_file(ctx->memory, "jpegxr-scratch-", name, "wb+");
	if (!file)
		return gs_throw(gs_error_invalidfileaccess, "cannot open scratch file");
	rc = fwrite(buf, 1, len, file);
	if (rc != len)
		return gs_throw(gs_error_invalidfileaccess, "cannot write to scratch file");
	fseek(file, 0, SEEK_SET);

	container = jxr_create_container();
	rc = jxr_read_image_container(container, file);
	if (rc < 0)
		return gs_throw1(-1, "jxr_read_image_container: %s", jxr_error_string(rc));

	offset = jxrc_image_offset(container, 0);
	alpha_offset = jxrc_alpha_offset(container, 0);

	output->xres = jxrc_width_resolution(container, 0);
	output->yres = jxrc_height_resolution(container, 0);

	image = jxr_create_input();
	jxr_set_PROFILE_IDC(image, 111);
	jxr_set_LEVEL_IDC(image, 255);
	jxr_set_pixel_format(image, jxrc_image_pixelformat(container, 0));
	jxr_set_container_parameters(image,
		jxrc_image_pixelformat(container, 0),
		jxrc_image_width(container, 0),
		jxrc_image_height(container, 0),
		jxrc_alpha_offset(container, 0),
		jxrc_image_band_presence(container, 0),
		jxrc_alpha_band_presence(container, 0), 0);

	jxr_set_block_output(image, xps_decode_jpegxr_block);
	state.ctx = ctx;
	state.output = output;
	jxr_set_user_data(image, &state);

	fseek(file, offset, SEEK_SET);
	rc = jxr_read_image_bitstream(image, file);
	if (rc < 0)
		return gs_throw1(-1, "jxr_read_image_bitstream: %s", jxr_error_string(rc));

	jxr_destroy(image);

	if (alpha_offset > 0)
	{
		image = jxr_create_input();
		jxr_set_PROFILE_IDC(image, 111);
		jxr_set_LEVEL_IDC(image, 255);
		jxr_set_pixel_format(image, jxrc_image_pixelformat(container, 0));
		jxr_set_container_parameters(image,
			jxrc_image_pixelformat(container, 0),
			jxrc_image_width(container, 0),
			jxrc_image_height(container, 0),
			jxrc_alpha_offset(container, 0),
			jxrc_image_band_presence(container, 0),
			jxrc_alpha_band_presence(container, 0), 0);

		jxr_set_block_output(image, xps_decode_jpegxr_alpha_block);
		state.ctx = ctx;
		state.output = output;
		jxr_set_user_data(image, &state);

		fseek(file, alpha_offset, SEEK_SET);
		rc = jxr_read_image_bitstream(image, file);
		if (rc < 0)
			return gs_throw1(-1, "jxr_read_image_bitstream: %s", jxr_error_string(rc));

		jxr_destroy(image);
	}

	jxr_destroy_container(container);

	fclose(file);
	unlink(name);

	return gs_okay;
}

int
xps_jpegxr_has_alpha(xps_context_t *ctx, byte *buf, int len)
{
	return 1;
}

#else

int
xps_decode_jpegxr(xps_context_t *ctx, byte *buf, int len, xps_image_t *image)
{
	return fz_throw("JPEG-XR codec is not available");
}

int
xps_jpegxr_has_alpha(xps_context_t *ctx, byte *buf, int len)
{
	return 0;
}

#endif
