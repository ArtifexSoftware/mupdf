#include <fitz.h>

fz_error fz_kioneedin = { "<ioneedin>", "<process>", "filter.c", 0, 1 };
fz_error fz_kioneedout = { "<ioneedout>", "<process>", "filter.c", 0, 1 };
fz_error fz_kiodone = { "<iodone>", "<process>", "filter.c", 0, 1 };

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
fz_dropfilter(fz_filter *f)
{
	if (f->drop)
		f->drop(f);
	fz_free(f);
}

