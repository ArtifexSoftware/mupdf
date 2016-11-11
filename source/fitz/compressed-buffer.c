#include "fitz-imp.h"

/* This code needs to be kept out of stm_buffer.c to avoid it being
 * pulled into cmapdump.c */

void
fz_drop_compressed_buffer(fz_context *ctx, fz_compressed_buffer *buf)
{
	if (!buf)
		return;

	fz_drop_buffer(ctx, buf->buffer);
	fz_free(ctx, buf);
}

fz_stream *
fz_open_image_decomp_stream_from_buffer(fz_context *ctx, fz_compressed_buffer *buffer, int *l2factor)
{
	fz_stream *chain = fz_open_buffer(ctx, buffer->buffer);

	return fz_open_image_decomp_stream(ctx, chain, &buffer->params, l2factor);
}

fz_stream *
fz_open_image_decomp_stream(fz_context *ctx, fz_stream *chain, fz_compression_params *params, int *l2factor)
{
	int our_l2factor = 0;

	switch (params->type)
	{
	case FZ_IMAGE_FAX:
		return fz_open_faxd(ctx, chain,
				params->u.fax.k,
				params->u.fax.end_of_line,
				params->u.fax.encoded_byte_align,
				params->u.fax.columns,
				params->u.fax.rows,
				params->u.fax.end_of_block,
				params->u.fax.black_is_1);
	case FZ_IMAGE_JPEG:
		if (l2factor)
		{
			our_l2factor = *l2factor;
			if (our_l2factor > 3)
				our_l2factor = 3;
			*l2factor -= our_l2factor;
		}
		return fz_open_dctd(ctx, chain, params->u.jpeg.color_transform, our_l2factor, NULL);
	case FZ_IMAGE_RLD:
		return fz_open_rld(ctx, chain);
	case FZ_IMAGE_FLATE:
		chain = fz_open_flated(ctx, chain, 15);
		if (params->u.flate.predictor > 1)
			chain = fz_open_predict(ctx, chain, params->u.flate.predictor, params->u.flate.columns, params->u.flate.colors, params->u.flate.bpc);
		return chain;
	case FZ_IMAGE_LZW:
		chain = fz_open_lzwd(ctx, chain, params->u.lzw.early_change, 9, 0, 0);
		if (params->u.lzw.predictor > 1)
			chain = fz_open_predict(ctx, chain, params->u.lzw.predictor, params->u.lzw.columns, params->u.lzw.colors, params->u.lzw.bpc);
		return chain;
	default:
		break;
	}

	return chain;
}

fz_stream *
fz_open_compressed_buffer(fz_context *ctx, fz_compressed_buffer *buffer)
{
	int l2factor = 0;

	return fz_open_image_decomp_stream_from_buffer(ctx, buffer, &l2factor);
}

size_t
fz_compressed_buffer_size(fz_compressed_buffer *buffer)
{
	if (!buffer || !buffer->buffer)
		return 0;
	return (size_t)buffer->buffer->cap;
}
