#include <fitz.h>

fz_error *
fz_ferror(fz_file *f)
{
	fz_error *e = f->error;
	f->error = nil;
	return e;
}

fz_error *
fz_openfile(fz_file **filep, char *path, int mode)
{
	fz_error *error;
	fz_file *file;
	int fd;

	assert(mode == O_RDONLY || mode == O_WRONLY);

	file = *filep = fz_malloc(sizeof(fz_file));
	if (!file)
		return fz_outofmem;

	fd = open(path, mode, 0);
	if (fd == -1)
		return fz_throw("ioerror: open '%s': %s", path, strerror(errno));

	file->mode = mode;
	file->fd = fd;
	file->depth = 0;
	file->error = nil;
	file->filter = nil;
	file->in = nil;
	file->out = nil;

	error = fz_newbuffer(&file->in, FZ_BUFSIZE);
	if (error)
		goto cleanup;

	error = fz_newbuffer(&file->out, FZ_BUFSIZE);
	if (error)
		goto cleanup;

	return nil;

cleanup:
	*filep = nil;
	close(fd);
	fz_free(file->out);
	fz_free(file->in);
	fz_free(file);
	return error;
}

fz_error *
fz_openbuffer(fz_file **filep, fz_buffer *buf, int mode)
{
	fz_error *error;
	fz_file *file;

	assert(mode == O_RDONLY || mode == O_WRONLY);

	file = *filep = fz_malloc(sizeof(fz_file));
	if (!file)
		return fz_outofmem;

	file->mode = mode;
	file->fd = -1;
	file->depth = 0;
	file->error = nil;
	file->filter = nil;

	if (mode == O_RDONLY)
	{
		file->in = buf;
		error = fz_newbuffer(&file->out, FZ_BUFSIZE);
		if (error)
			goto cleanup;
	}

	else
	{
		error = fz_newbuffer(&file->in, FZ_BUFSIZE);
		if (error)
			goto cleanup;
		file->out = buf;
	}

	return nil;

cleanup:
	*filep = nil;
	fz_free(file);
	return error;
}

void
fz_closefile(fz_file *file)
{
	assert(file->depth == 0);

	if (file->mode != O_RDONLY)
		fz_flush(file);

	if (file->error)
	{
		fz_warn("%s", file->error->msg);
		fz_freeerror(file->error);
		file->error = nil;
	}

	if (file->fd == -1)	/* open to buffer not file */
	{
		if (file->mode == O_RDONLY)
			fz_freebuffer(file->out);
		else
			fz_freebuffer(file->in);
	}
	else
	{
		fz_freebuffer(file->in);
		fz_freebuffer(file->out);
		close(file->fd);
	}

	if (file->filter)
		fz_freefilter(file->filter);

	fz_free(file);
}

fz_error *
fz_pushfilter(fz_file *file, fz_filter *filter)
{
	fz_error *error;

	/* without a filter, one buffer is ignored: unignore. */
	if (file->depth == 0)
	{
		fz_buffer *buf;

		buf = file->out;
		file->out = file->in;
		file->in = buf;

// XXX
		if (file->mode == O_RDONLY)
		{
			file->out->rp = file->out->bp;
			file->out->wp = file->out->bp;
			file->out->eof = 0;
		}

		file->filter = filter;
	}

	else
	{
		if (file->mode == O_RDONLY)
		{
			error = fz_chainpipeline(&file->filter, file->filter, filter, file->out);
			if (error)
				return error;

			error = fz_newbuffer(&file->out, FZ_BUFSIZE);
			if (error)
			{
				fz_unchainpipeline(file->filter, &file->filter, &file->out);
				return error;
			}
		}

		else
		{
			error = fz_chainpipeline(&file->filter, filter, file->filter, file->in);
			if (error)
				return error;

			error = fz_newbuffer(&file->in, FZ_BUFSIZE);
			if (error)
			{
				fz_unchainpipeline(file->filter, &file->filter, &file->in);
				return error;
			}
		}
	}

	file->depth ++;

	return nil;
}

void
fz_popfilter(fz_file *file)
{
	fz_buffer *buf;

	assert(file->depth > 0);

	if (file->mode != O_RDONLY)
		fz_flush(file);

	if (file->error)
	{
		fz_warn("%s", file->error->msg);
		fz_freeerror(file->error);
		file->error = nil;
	}

	if (file->depth == 1)
	{
		fz_freefilter(file->filter);
		file->filter = nil;

		buf = file->out;
		file->out = file->in;
		file->in = buf;

// XXX
		file->in->rp = file->in->bp;
		file->in->wp = file->in->bp;
		file->in->eof = 0;
	}
	else
	{
		if (file->mode == O_RDONLY)
		{
			fz_freebuffer(file->out);
			fz_unchainpipeline(file->filter, &file->filter, &file->out);
		}
		else
		{
			fz_freebuffer(file->in);
			fz_unchainpipeline(file->filter, &file->filter, &file->in);
		}
	}

	file->depth --;
}

int
fz_seek(fz_file *f, int ofs)
{
	int t;
	int c;

	assert(f->mode == O_RDONLY);

	if (f->filter)
	{
		if (ofs < fz_tell(f))
		{
			f->error = fz_throw("ioerror: cannot seek backwards in filter");
			return -1;
		}
		while (fz_tell(f) < ofs)
		{
			c = fz_readbyte(f);
			if (c == EOF)
				return -1;
		}
		return 0;
	}

	t = lseek(f->fd, ofs, 0);
	if (t == -1)
	{
		f->error = fz_throw("ioerror: lseek: %s", strerror(errno));
		return -1;
	}

	f->out->rp = f->out->bp;
	f->out->wp = f->out->bp;
	f->out->eof = 0;

	return 0;
}

int
fz_tell(fz_file *f)
{
	int t;

	if (f->filter)
	{
		assert(f->mode == O_RDONLY);
		return f->filter->count - (f->out->wp - f->out->rp);
	}

	t = lseek(f->fd, 0, 1);
	if (t == -1)
	{
		f->error = fz_throw("ioerror: lseek: %s", strerror(errno));
		return -1;
	}

	if (f->mode == O_RDONLY)
		return t - (f->out->wp - f->out->rp);
	else
		return t - (f->in->wp - f->in->rp);
}

