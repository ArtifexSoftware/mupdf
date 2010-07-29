#include "fitz.h"

#define OPJ_STATIC
#include <openjpeg.h>

typedef struct fz_jpxd_s fz_jpxd;

struct fz_jpxd_s
{
	fz_stream *chain;
	opj_image_t *image;
	int x, y, k;
};

static void fz_opj_error_callback(const char *msg, void *client_data)
{
	fprintf(stderr, "openjpeg error: %s", msg);
}

static void fz_opj_warning_callback(const char *msg, void *client_data)
{
	fprintf(stderr, "openjpeg warning: %s", msg);
}

static void fz_opj_info_callback(const char *msg, void *client_data)
{
	/* fprintf(stdout, "openjpeg info: %s", msg); */
}

static int
readjpxd(fz_stream *stm, unsigned char *outbuf, int outlen)
{
	fz_jpxd *state = stm->state;
	unsigned char *p = outbuf;
	opj_event_mgr_t evtmgr;
	opj_dparameters_t params;
	opj_dinfo_t *info;
	opj_cio_t *cio;
	int format;
	int n, w, h, depth, sgnd;
	int k, v;

	if (!state->image)
	{
		fz_error error;
		fz_buffer *buf;

		error = fz_readall(&buf, state->chain);
		if (error)
			return fz_throw("read error in jpx filter");

		if (buf->len < 2)
		{
			fz_dropbuffer(buf);
			return fz_throw("not enough data to determine image format");
		}

		/* Check for SOC marker -- if found we have a bare J2K stream */
		if (buf->data[0] == 0xFF && buf->data[1] == 0x4F)
			format = CODEC_J2K;
		else
			format = CODEC_JP2;

		memset(&evtmgr, 0, sizeof(evtmgr));
		evtmgr.error_handler = fz_opj_error_callback;
		evtmgr.warning_handler = fz_opj_warning_callback;
		evtmgr.info_handler = fz_opj_info_callback;

		opj_set_default_decoder_parameters(&params);

		info = opj_create_decompress(format);
		opj_set_event_mgr((opj_common_ptr)info, &evtmgr, stderr);
		opj_setup_decoder(info, &params);

		cio = opj_cio_open((opj_common_ptr)info, buf->data, buf->len);

		state->image = opj_decode(info, cio);

		opj_cio_close(cio);
		opj_destroy_decompress(info);
		fz_dropbuffer(buf);

		if (!state->image)
			return fz_throw("opj_decode failed");

		for (k = 1; k < state->image->numcomps; k++)
		{
			if (state->image->comps[k].w != state->image->comps[0].w)
				return fz_throw("image components have different width");
			if (state->image->comps[k].h != state->image->comps[0].h)
				return fz_throw("image components have different height");
			if (state->image->comps[k].prec != state->image->comps[0].prec)
				return fz_throw("image components have different precision");
		}
	}

	n = state->image->numcomps;
	w = state->image->comps[0].w;
	h = state->image->comps[0].h;
	depth = state->image->comps[0].prec;
	sgnd = state->image->comps[0].sgnd;

	while (state->y < h)
	{
		while (state->x < w)
		{
			while (state->k < n)
			{
				if (p == outbuf + outlen)
					return p - outbuf;

				v = state->image->comps[state->k].data[state->y * w + state->x];
				if (sgnd)
					v = v + (1 << (depth - 1));
				if (depth > 8)
					v = v >> (depth - 8);

				*p++ = v;

				state->k ++;
			}
			state->x ++;
			state->k = 0;
		}
		state->y ++;
		state->x = 0;
	}

	return p - outbuf;
}

static void
closejpxd(fz_stream *stm)
{
	fz_jpxd *state = stm->state;
	if (state->image)
		opj_image_destroy(state->image);
	fz_close(state->chain);
	fz_free(state);
}

fz_stream *
fz_openjpxd(fz_stream *chain)
{
	fz_jpxd *state;

	state = fz_malloc(sizeof(fz_jpxd));
	state->chain = chain;
	state->image = nil;
	state->x = 0;
	state->y = 0;
	state->k = 0;

	return fz_newstream(state, readjpxd, closejpxd);
}
