#include <fitz.h>
#include <mupdf.h>

static char *password = "";
static int dodecode = 0;
static int dorepair = 0;
static int doprintxref = 0;

typedef struct psobj_s psobj;

struct pdf_function_s
{
	unsigned short type;	/* 0=sample 2=exponential 3=stitching 4=postscript */
	int m;					/* number of input values */
	int n;					/* number of output values */
	float *domain;			/* even index : min value, odd index : max value */
	float *range;			/* even index : min value, odd index : max value */
	union
	{
		struct {
			unsigned short bps;
			unsigned short order;
			int *size;		/* the num of samples in each input dimension */
			float *encode;
			float *decode;
			int *samples;
		} sa;
		struct {
			float n;
			float *c0;
			float *c1;
		} e;
		struct {
			int k;
			pdf_function **funcs;
			float *bounds;
			float *encode;
		} st;
		struct {
			psobj *code;
			int cap;
		} p;
	}u;
};

void usage()
{
	fprintf(stderr, "usage: pdffunction [-drxs] [-u password] file.pdf oid [input ...]\n");
	exit(1);
}

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

void decodestream(pdf_xref *xref, int oid, int gid)
{
	fz_error *error;
	unsigned char buf[512];

	safecol = 0;

	error = pdf_openstream(xref, oid, gid);
	if (error) fz_abort(error);

	while (1)
	{
		int n = fz_read(xref->stream, buf, sizeof buf);
		if (n == 0)
			break;
		if (n < 0)
			fz_abort(fz_ferror(xref->stream));
		printsafe(buf, n);
	}

	pdf_closestream(xref);
}

void copystream(pdf_xref *xref, int oid, int gid)
{
	fz_error *error;
	unsigned char buf[512];

	safecol = 0;

	error = pdf_openrawstream(xref, oid, gid);
	if (error) fz_abort(error);

	while (1)
	{
		int n = fz_read(xref->stream, buf, sizeof buf);
		if (n == 0)
			break;
		if (n < 0)
			fz_abort(fz_ferror(xref->stream));
		printsafe(buf, n);
	}

	pdf_closestream(xref);
}

void printobject(pdf_xref *xref, int oid, int gid)
{
	fz_error *error;
	fz_obj *obj;

	error = pdf_loadobject(&obj, xref, oid, gid);
	if (error) fz_abort(error);

	printf("%d %d obj\n", oid, gid);
	fz_debugobj(obj);
	printf("\n");

	if (xref->table[oid].stmofs) {
		printf("stream\n");
		if (dodecode)
			decodestream(xref, oid, gid);
		else
			copystream(xref, oid, gid);
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

	while ((c = getopt(argc, argv, "drxopu:")) != -1)
	{
		switch (c)
		{
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

	if (dorepair)
		error = pdf_repairpdf(&xref, filename);
	else
		error = pdf_openpdf(&xref, filename);
	if (error)
		fz_abort(error);

	error = pdf_decryptpdf(xref);
	if (error)
		fz_abort(error);

	if (xref->crypt)
	{
		error = pdf_setpassword(xref->crypt, password);
		if (error) fz_abort(error);
	}

	if (optind == argc)
	{
		printf("trailer\n");
		fz_debugobj(xref->trailer);
		printf("\n");
	}
	else
	{
		int oid = atoi(argv[optind++]);
		if(optind == argc)
			printobject(xref, oid, 0);
		else
		{
			float *in = nil, *out = nil;
			pdf_function *func;
			fz_obj *funcobj;
			int i;

			/* type 0 and type 4 funcs must be indirect to read stream */
			error = fz_newindirect(&funcobj,oid,0);
			if(error) fz_abort(error);
			error = pdf_loadfunction(&func,xref,funcobj);
			if(error) fz_abort(error);
			in = fz_malloc(func->m * sizeof(float));
			out = fz_malloc(func->n * sizeof(float));

			if(!in || !out)
				fz_abort(fz_outofmem);

			for(i = 0; optind < argc; optind++, i++)
			{
				if(i >= func->m)
					fz_abort(fz_throw("too much input values"));

				in[i] = atof(argv[optind]);
			}

			if(i < func->m)
				fz_abort(fz_throw("too few input values"));

			error = pdf_evalfunction(func, in, func->m, out, func->n);
			if(error) fz_abort(error);

			for(i = 0; i < func->n; ++i)
				fprintf(stderr, "output[%d] : %f\n", i, out[i]);

			fz_dropobj(funcobj);
			pdf_dropfunction(func);
		}
	}

	for ( ; optind < argc; optind++)
	{
		printobject(xref, atoi(argv[optind]), 0);
		printf("\n");
	}

	if (doprintxref)
		pdf_debugpdf(xref);

	pdf_closepdf(xref);

	return 0;
}

