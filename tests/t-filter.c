#include <fitz.h>

void
usage(void)
{
	printf("usage: filter filt0 param0 filt1 param1 filt2 param2 ...\n");
	exit(1);
}

struct {
	char *name;
	fz_error *(*newf)(fz_filter **, fz_obj*);
} table[] = {
	{ "ASCIIHexDecode",	fz_newahxd },
	{ "ASCII85Decode",	fz_newa85d },
	{ "CCITTFaxDecode",	fz_newfaxd },
	{ "DCTDecode",		fz_newdctd },
	{ "RunLengthDecode",	fz_newrld },
	{ "LZWDecode",		fz_newlzwd },
	{ "FlateDecode",	fz_newflated },

	{ "ASCIIHexEncode",	fz_newahxe },
	{ "ASCII85Encode",	fz_newa85e },
	{ "CCITTFaxEncode",	fz_newfaxe },
	{ "DCTEncode",		fz_newdcte },
	{ "RunLengthEncode",	fz_newrle },
	{ "LZWEncode",		fz_newlzwe },
	{ "FlateEncode",	fz_newflatee },

	{ "PredictDecode",	fz_newpredictd },
	{ "PredictEncode",	fz_newpredicte },

	{ "JBIG2Decode",	fz_newjbig2d },
	{ "JPXDecode",		fz_newjpxd },

	{ nil,			nil, }
};

fz_error *
makefilter(fz_filter **fp, char *f, fz_obj *p)
{
	int i;

	for (i = 0; table[i].name; i++)
		if (strcmp(f, table[i].name) == 0)
			return table[i].newf(fp, p);

	return fz_throw("unknown filter type '%s'", f);
}

int
main(int argc, char **argv)
{
	unsigned char buf[512];
	int i;

	fz_error *err;
	fz_filter *filter;
	fz_filter *pipe;
	fz_file *file;
	fz_obj *param;

	if (argc == 1)
		usage();

	filter = nil;
	pipe = nil;

	for (i = 1; i < argc - 1; i += 2)
	{
		err = fz_parseobj(&param, argv[i+1]);
		if (err) fz_abort(err);

		err = makefilter(&filter, argv[i], param);
		if (err) fz_abort(err);

		if (pipe) {
			err = fz_newpipeline(&pipe, pipe, filter);
			if (err) fz_abort(err);
		}
		else
			pipe = filter;
	}

	err = fz_openfile(&file, "/dev/stdin", FZ_READ);
	if (err) fz_abort(err);

	if (pipe)
	{
		err = fz_pushfilter(file, pipe);
		if (err) fz_abort(err);
	}

	while (1)
	{
		i = fz_read(file, buf, sizeof buf);
		if (i < 0)
			fz_abort(fz_ferror(file));
		if (i == 0)
			break;
		write(1, buf, i);
	}

	if (pipe)
		fz_popfilter(file);

	fz_closefile(file);

	return 0;
}

