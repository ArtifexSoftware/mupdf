#include <fitz.h>
#include <mupdf.h>

static char *password = "";
static int dodecode = 0;
static int dorepair = 0;
static int doprintxref = 0;
static int dosave = 0;

void usage()
{
	fprintf(stderr, "usage: pdfdebug [-drxs] [-u password] file.pdf [oid ...]\n");
	exit(1);
}

/*
 * Debug-print stream contents
 */

static int safecol = 0;

void printsafe(unsigned char *buf, int n)
{
	int i;
	for (i = 0; i < n; i++) {
		if (buf[i] == '\r' || buf[i] == '\n') {
			printf("\n");
			safecol = 0;
		}
		else if (buf[i] < 32 || buf[i] > 126) {
			printf(".");
			safecol ++;
		}
		else {
			printf("%c", buf[i]);
			safecol ++;
		}
		if (safecol == 79) {
			printf("\n");
			safecol = 0;
		}
	}
}

void decodestream(pdf_xref *xref, fz_obj *stream, int oid, int gid, int ofs)
{
	FILE *copy;
	fz_error *error;
	unsigned char buf[512];

	if (dosave)
		copy = fopen("/tmp/dump.stm", "wb");

	safecol = 0;

	error = pdf_openstream0(xref, stream, oid, gid, ofs);
	if (error) fz_abort(error);

	while (1)
	{
		int n = fz_read(xref->file, buf, sizeof buf);
		if (n == 0)
			break;
		if (n < 0)
			fz_abort(fz_ferror(xref->file));
		printsafe(buf, n);

		if (dosave)
			fwrite(buf, 1, n, copy);
	}

	if (dosave)
		fclose(copy);

	pdf_closestream(xref);
}

void copystream(pdf_xref *xref, fz_obj *stream, int ofs)
{
	fz_error *error;
	unsigned char buf[512];
	fz_filter *filter;
	fz_obj *obj;
	int len;

	safecol = 0;

	obj = fz_dictgets(stream, "Length");
	error = pdf_resolve(&obj, xref);
	if (error) fz_abort(error);
	len = fz_toint(obj);
	fz_dropobj(obj);

	error = fz_newnullfilter(&filter, len);
	if (error) fz_abort(error);

	fz_seek(xref->file, ofs, 0);

	error = fz_pushfilter(xref->file, filter);
	if (error) fz_abort(error);

	while (1)
	{
		int n = fz_read(xref->file, buf, sizeof buf);
		if (n == 0)
			break;
		if (n < 0)
			fz_abort(fz_ferror(xref->file));
		printsafe(buf, n);
	}

	fz_popfilter(xref->file);
}

void printobject(pdf_xref *xref, int oid, int gid)
{
	fz_error *error;
	int stmofs;
	fz_obj *obj;

	error = pdf_loadobject0(&obj, xref, oid, gid, &stmofs);
	if (error) fz_abort(error);

	printf("%d %d obj\n", oid, gid);
	fz_debugobj(obj);
	printf("\n");
	if (stmofs != -1) {
		printf("stream\n");
		if (dodecode)
			decodestream(xref, obj, oid, gid, stmofs);
		else
			copystream(xref, obj, stmofs);
		printf("endstream\n");
	}
	printf("endobj\n");

	fz_dropobj(obj);
}

int main(int argc, char **argv)
{
	fz_error *error;
	char *filename;
	pdf_xref *xref;
	int c;

	while ((c = getopt(argc, argv, "drxsopu:")) != -1)
	{
		switch (c)
		{
		case 's':
			dodecode ++;
			dosave ++;
		case 'd':
			dodecode ++;
			break;
		case 'r':
			dorepair ++;
			break;
		case 'x':
			doprintxref ++;
			break;
		case 'u':
			password = optarg;
			break;
		default:
			usage();
		}
	}

	if (argc - optind == 0)
		usage();

	filename = argv[optind++];

	error = pdf_newxref(&xref);
	if (error)
		fz_abort(error);

	if (dorepair)
		error = pdf_repairxref(xref, filename);
	else
		error = pdf_openxref(xref, filename);
	if (error)
		fz_abort(error);

	error = pdf_decryptxref(xref);
	if (error)
		fz_abort(error);

	if (xref->crypt)
	{
		error = pdf_setpassword(xref->crypt, password);
		if (error) fz_abort(error);
	}

	if (doprintxref)
		pdf_debugxref(xref);

	if (optind == argc)
	{
		printf("trailer\n");
		fz_debugobj(xref->trailer);
		printf("\n");
	}

	for ( ; optind < argc; optind++)
	{
		printobject(xref, atoi(argv[optind]), 0);
		printf("\n");
	}

	pdf_closexref(xref);

	return 0;
}

