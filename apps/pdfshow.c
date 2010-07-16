/*
 * pdfshow -- the ultimate pdf debugging tool
 */

#include "fitz.h"
#include "mupdf.h"

static pdf_xref *xref = NULL;
static int showbinary = 0;
static int showraw = 0;
static int showcolumn;

void die(fz_error error)
{
	fz_catch(error, "aborting");
	if (xref)
		pdf_freexref(xref);
	exit(1);
}

static void usage(void)
{
	fprintf(stderr, "usage: pdfshow [-bc] [-p password] <file> [xref] [trailer] [object numbers]\n");
	fprintf(stderr, "\t-b\tprint streams as binary data\n");
	fprintf(stderr, "\t-c\tprint compressed streams (don't decompress)\n");
	fprintf(stderr, "\t-p\tpassword\n");
	exit(1);
}

static void showtrailer(void)
{
	if (!xref)
		die(fz_throw("no file specified"));
	printf("trailer\n");
	fz_debugobj(xref->trailer);
	printf("\n");
}

static void showxref(void)
{
	if (!xref)
		die(fz_throw("no file specified"));
	pdf_debugxref(xref);
	printf("\n");
}

static void showsafe(unsigned char *buf, int n)
{
	int i;
	for (i = 0; i < n; i++) {
		if (buf[i] == '\r' || buf[i] == '\n') {
			putchar('\n');
			showcolumn = 0;
		}
		else if (buf[i] < 32 || buf[i] > 126) {
			putchar('.');
			showcolumn ++;
		}
		else {
			putchar(buf[i]);
			showcolumn ++;
		}
		if (showcolumn == 79) {
			putchar('\n');
			showcolumn = 0;
		}
	}
}

static void showstream(int num, int gen)
{
	fz_error error;
	fz_stream *stm;
	unsigned char buf[2048];
	int n;

	showcolumn = 0;

	if (showraw)
		error = pdf_openrawstream(&stm, xref, num, gen);
	else
		error = pdf_openstream(&stm, xref, num, gen);
	if (error)
		die(error);

	while (1)
	{
		error = fz_read(&n, stm, buf, sizeof buf);
		if (error)
			die(error);
		if (n == 0)
			break;
		if (showbinary)
			fwrite(buf, 1, n, stdout);
		else
			showsafe(buf, n);
	}

	fz_dropstream(stm);
}

static void showobject(int num, int gen)
{
	fz_error error;
	fz_obj *obj;

	if (!xref)
		die(fz_throw("no file specified"));

	error = pdf_loadobject(&obj, xref, num, gen);
	if (error)
		die(error);

	if (pdf_isstream(xref, num, gen))
	{
		if (showraw)
		{
			showstream(num, gen);
		}
		else
		{
			printf("%d %d obj\n", num, gen);
			fz_debugobj(obj);
			printf("stream\n");
			showstream(num, gen);
			printf("endstream\n");
			printf("endobj\n\n");
		}
	}
	else
	{
		printf("%d %d obj\n", num, gen);
		fz_debugobj(obj);
		printf("endobj\n\n");
	}

	fz_dropobj(obj);
}

int main(int argc, char **argv)
{
	char *password = NULL; /* don't throw errors if encrypted */
	fz_error error;
	char *filename;
	int c;

	while ((c = fz_getopt(argc, argv, "p:bc")) != -1)
	{
		switch (c)
		{
		case 'p': password = fz_optarg; break;
		case 'b': showbinary ++; break;
		case 'c': showraw ++; break;
		default: usage(); break;
		}
	}

	if (fz_optind == argc)
		usage();

	filename = argv[fz_optind++];
	error = pdf_openxref(&xref, filename, password);
	if (error)
		die(fz_rethrow(error, "cannot open document: %s", filename));

	if (fz_optind == argc)
		showtrailer();

	while (fz_optind < argc)
	{
		if (!strcmp(argv[fz_optind], "trailer"))
			showtrailer();
		else if (!strcmp(argv[fz_optind], "xref"))
			showxref();
		else
			showobject(atoi(argv[fz_optind]), 0);
		fz_optind++;
	}

	pdf_freexref(xref);

	return 0;
}

