#include "fitz.h"
#include "samus.h"

int runzip(int argc, char **argv)
{
	fz_error *error;
	fz_buffer *buf;
	sa_zip *zip;
	int i;

	error = sa_openzip(&zip, argv[1]);
	if (error)
		fz_abort(error);

	if (argc == 2)
		sa_debugzip(zip);

	for (i = 2; i < argc; i++)
	{
		error = sa_openzipentry(zip, argv[i]);
		if (error)
			fz_abort(error);
		error = fz_readfile(&buf, zip->file);
		if (error)
			fz_abort(error);
		sa_closezipentry(zip);

		fwrite(buf->rp, 1, buf->wp - buf->rp, stdout);

		fz_dropbuffer(buf);
	}

	sa_closezip(zip);
	
	return 0;
}

int runxml(int argc, char **argv)
{
	fz_error *error;
	fz_file *file;
	sa_xmlparser *parser;
	sa_xmlitem *item;

	error = fz_openfile(&file, argv[1], FZ_READ);
	if (error)
		fz_abort(error);

	error = sa_openxml(&parser, file, 0);
	if (error)
		fz_abort(error);

	item = sa_xmlnext(parser);
	if (item)
		sa_debugxml(item, 0);

	sa_closexml(parser);
	fz_closefile(file);

	return 0;
}

extern fz_error *sa_readtiff(fz_file *);

int runtiff(int argc, char **argv)
{
	fz_error *error;
	fz_file *file;

	error = fz_openfile(&file, argv[1], FZ_READ);
	if (error)
		fz_abort(error);

	error = sa_readtiff(file);
	if (error)
		fz_abort(error);
	
	fz_closefile(file);

	return 0;
}

int main(int argc, char **argv)
{
	if (argc >= 2)
	{
		if (strstr(argv[1], "zip"))
			return runzip(argc, argv);
		if (strstr(argv[1], "xml"))
			return runxml(argc, argv);
		if (strstr(argv[1], "tif"))
			return runtiff(argc, argv);
	}

	fprintf(stderr, "usage: samshow <file>\n");
	fprintf(stderr, "usage: samshow <zipfile> <partname>\n");
	return 1;
}

