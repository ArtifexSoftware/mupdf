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
	int realmode;
	int fd;
	int n;

	assert(mode == FZ_READ || mode == FZ_WRITE || mode == FZ_APPEND);

	realmode = 0;
	if (mode == FZ_READ)
		realmode = O_BINARY | O_RDONLY;
	if (mode == FZ_WRITE)
		realmode = O_BINARY | O_WRONLY | O_CREAT | O_TRUNC;
	if (mode == FZ_APPEND)
		realmode = O_BINARY | O_WRONLY;

	fd = open(path, realmode, 0644);
	if (fd == -1)
		return fz_throw("ioerror: open '%s': %s", path, strerror(errno));

	if (mode == FZ_APPEND)
	{
		mode = FZ_WRITE;
		n = lseek(fd, 0, 2);
		if (n == -1) {
			error = fz_throw("ioerror: lseek: %s", strerror(errno));
			close(fd);
			return error;
		}
	}

	file = *filep = fz_malloc(sizeof(fz_file));
	if (!file)
		return fz_outofmem;

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

	assert(mode == FZ_READ || mode == FZ_WRITE);

	file = *filep = fz_malloc(sizeof(fz_file));
	if (!file)
		return fz_outofmem;

	file->mode = mode;
	file->fd = -1;
	file->depth = 0;
	file->error = nil;
	file->filter = nil;

	if (mode == FZ_READ)
	{
		file->out = buf;
		error = fz_newbuffer(&file->in, FZ_BUFSIZE);
		if (error)
			goto cleanup;
	}

	else
	{
		error = fz_newbuffer(&file->out, FZ_BUFSIZE);
		if (error)
			goto cleanup;
		file->in = buf;
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

	if (file->mode == FZ_WRITE)
		fz_flush(file);

	if (file->error)
	{
		fz_warn("%s", file->error->msg);
		fz_droperror(file->error);
		file->error = nil;
	}

	if (file->fd == -1)	/* open to buffer not file */
	{
		if (file->mode == FZ_READ)
			fz_dropbuffer(file->in);
		else
			fz_dropbuffer(file->out);
	}
	else
	{
		fz_dropbuffer(file->in);
		fz_dropbuffer(file->out);
		close(file->fd);
	}

	if (file->filter)
		fz_dropfilter(file->filter);

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

		if (file->mode == FZ_READ)
		{
			file->out->rp = file->out->bp;
			file->out->wp = file->out->bp;
			file->out->eof = 0;
		}
		else
		{
			file->out->eof = 0;
			file->in->rp = file->in->bp;
			file->in->wp = file->in->bp;
			file->in->eof = 0;
		}

		file->filter = filter;
	}

	else
	{
		if (file->mode == FZ_READ)
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

	if (file->mode == FZ_WRITE)
		fz_flush(file);

	if (file->error)
	{
		fz_warn("%s", file->error->msg);
		fz_droperror(file->error);
		file->error = nil;
	}

	if (file->depth == 1)
	{
		fz_dropfilter(file->filter);
		file->filter = nil;

		buf = file->out;
		file->out = file->in;
		file->in = buf;
	}
	else
	{
		if (file->mode == FZ_READ)
		{
			fz_dropbuffer(file->out);
			fz_unchainpipeline(file->filter, &file->filter, &file->out);
		}
		else
		{
			fz_dropbuffer(file->in);
			fz_unchainpipeline(file->filter, &file->filter, &file->in);
		}
	}

	file->depth --;
}

int
fz_seek(fz_file *f, int ofs, int whence)
{
	int t;
	int c;

	if (f->filter)
	{
		assert(f->mode == FZ_READ && whence == 0);

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
		return ofs;
	}

	t = lseek(f->fd, ofs, whence);
	if (t == -1)
	{
		f->error = fz_throw("ioerror: lseek: %s", strerror(errno));
		return -1;
	}

	f->out->rp = f->out->bp;
	f->out->wp = f->out->bp;
	f->out->eof = 0;

	return t;
}

int
fz_tell(fz_file *f)
{
	int t;

	if (f->filter)
	{
		assert(f->mode == FZ_READ);
		return f->filter->count - (f->out->wp - f->out->rp);
	}

	t = lseek(f->fd, 0, 1);
	if (t == -1)
	{
		f->error = fz_throw("ioerror: lseek: %s", strerror(errno));
		return -1;
	}

	if (f->mode == FZ_READ)
		return t - (f->out->wp - f->out->rp);
	else
		return t + (f->in->wp - f->in->rp);
}

