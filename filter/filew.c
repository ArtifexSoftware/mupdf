#include <fitz.h>

int
fz_printstring(fz_file *f, char *s)
{
	return fz_write(f, s, strlen(s));
}

int
fz_printobj(fz_file *file, fz_obj *obj, int tight)
{
	char buf[1024];
	char *ptr;
	int n;

	n = fz_sprintobj(nil, 0, obj, tight);
	if (n < sizeof buf)
	{
		fz_sprintobj(buf, sizeof buf, obj, tight);
		return fz_write(file, buf, n);
	}
	else
	{
		ptr = fz_malloc(n);
		if (!ptr) {
			file->error = fz_outofmem;
			return -1;
		}
		fz_sprintobj(ptr, n, obj, tight);
		n = fz_write(file, ptr, n);
		fz_free(ptr);
		return n;
	}
}

int
fz_print(fz_file *f, char *fmt, ...)
{
	va_list ap;
	char buf[1024];
	char *p;
	int n;

	va_start(ap, fmt);
	n = vsnprintf(buf, sizeof buf, fmt, ap);
	va_end(ap);

	if (n < sizeof buf)
		return fz_write(f, buf, n);

	p = fz_malloc(n);
	if (!p) {
		f->error = fz_outofmem;
		return -1;
	}

	va_start(ap, fmt);
	vsnprintf(p, n, fmt, ap);
	va_end(ap);

	n = fz_write(f, p, n);

	fz_free(p);

	return n;
}

static int dowrite(fz_buffer *b, int fd)
{
	int n = write(fd, b->rp, b->wp - b->rp);
	if (n == -1)
		return -1;
	b->rp += n;
	return n;
}

int
fz_write(fz_file *f, char *buf, int n)
{
	fz_error *reason;
	int i = 0;
	int x;

	assert(f->mode == O_WRONLY);
	assert(f->error == nil);

	if (!f->filter)
	{
		while (i < n)
		{
			while (f->in->wp < f->in->ep && i < n)
				*f->in->wp++ = buf[i++];

			if (f->in->wp == f->in->ep)
			{
				x = dowrite(f->in, f->fd);
				if (x < 0) {
					f->error = fz_throw("ioerror in write: %s", strerror(errno));
					return -1;
				}

				if (f->in->rp > f->in->bp)
					f->error = fz_rewindbuffer(f->in);
				else
					f->error = fz_growbuffer(f->in);
				if (f->error)
					return -1;
			}
		}

		return 0;
	}

	while (i < n)
	{
		while (f->in->wp < f->in->ep && i < n)
			*f->in->wp++ = buf[i++];

		if (f->in->wp == f->in->ep)
		{
			reason = fz_process(f->filter, f->in, f->out);

			if (reason == fz_ioneedin)
			{
				if (f->in->wp == f->in->ep) {
					if (f->in->rp > f->in->bp)
						f->error = fz_rewindbuffer(f->in);
					else
						f->error = fz_growbuffer(f->in);
					if (f->error)
						return -1;
				}
			}

			else if (reason == fz_ioneedout)
			{
				x = dowrite(f->out, f->fd);
				if (x < 0) {
					f->error = fz_throw("ioerror in write: %s", strerror(errno));
					return -1;
				}

				if (f->out->rp > f->out->bp)
					f->error = fz_rewindbuffer(f->out);
				else
					f->error = fz_growbuffer(f->out);
				if (f->error)
					return -1;
			}

			else if (reason == fz_iodone)
			{
				while (f->out->rp < f->out->wp)
				{
					x = dowrite(f->out, f->fd);
					if (x < 0) {
						f->error = fz_throw("ioerror in write: %s", strerror(errno));
						return -1;
					}
				}
				break;
			}

			else {
				f->error = reason;
				return -1;
			}
		}
	}

	return i;
}

int
fz_flush(fz_file *f)
{
	fz_error *reason;
	int n;

	assert(f->mode == O_WRONLY);
	assert(f->error == nil);

	f->in->eof = 1;

	if (!f->filter)
	{
		while (f->in->rp < f->in->wp)
		{
			n = dowrite(f->in, f->fd);
			if (n < 0) {
				f->error = fz_throw("ioerror in write: %s", strerror(errno));
				return -1;
			}
		}
		return 0;
	}

	while (!f->out->eof)
	{
		reason = fz_process(f->filter, f->in, f->out);

		if (reason == fz_ioneedin) {
			f->error = fz_throw("ioerror: premature eof in filter");
			return -1;
		}

		else if (reason == fz_ioneedout)
		{
			n = dowrite(f->out, f->fd);
			if (n < 0) {
				f->error = fz_throw("ioerror in write: %s", strerror(errno));
				return -1;
			}

			if (f->out->rp > f->out->bp)
				f->error = fz_rewindbuffer(f->out);
			else
				f->error = fz_growbuffer(f->out);
			if (f->error)
				return -1;
		}

		else if (reason == fz_iodone)
		{
			n = dowrite(f->out, f->fd);
			if (n < 0) {
				f->error = fz_throw("ioerror in write: %s", strerror(errno));
				return -1;
			}
			break;
		}

		else {
			f->error = reason;
			return -1;
		}
	}

	return 0;
}

