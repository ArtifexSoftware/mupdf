#include <fitz.h>

fz_error fz_kioneedin = {
	.msg = {"<ioneedin>"},
	.func = {"<process>"},
	.file = {"filter.c"},
    .line = 0,
	.frozen = 1
};

fz_error fz_kioneedout = {
	.msg = {"<ioneedout>"},
	.func = {"<process>"},
	.file = {"filter.c"},
    .line = 0,
	.frozen = 1
};

fz_error fz_kiodone = {
	.msg = {"<iodone>"},
	.func = {"<process>"},
	.file = {"filter.c"},
    .line = 0,
	.frozen = 1
};

fz_error *
fz_process(fz_filter *f, fz_buffer *in, fz_buffer *out)
{
	fz_error *reason;
	unsigned char *oldrp;
	unsigned char *oldwp;

	assert(!out->eof);

	oldrp = in->rp;
	oldwp = out->wp;

	reason = f->process(f, in, out);

	assert(in->rp <= in->wp);
	assert(out->wp <= out->ep);

	f->consumed = in->rp > oldrp;
	f->produced = out->wp > oldwp;
	f->count += out->wp - oldwp;

	if (reason != fz_ioneedin && reason != fz_ioneedout)
		out->eof = 1;

	return reason;
}

void
fz_freefilter(fz_filter *f)
{
	f->free(f);
}

