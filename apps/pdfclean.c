#include <fitz.h>
#include <mupdf.h>

void usage()
{
	fprintf(stderr,
		"usage: pdfclean [options] infile.pdf outfile.pdf\n"
		"  -r\trebuild xref table\n"
		"  -g\tgarbage collect unused objects\n"
		"  -x\texpand compressed streams\n"
		"  -d -\tset user password for decryption\n"
		"  -e\tencrypt outfile\n"
		"    -u -\tset user password for encryption\n"
		"    -o -\tset owner password\n"
		"    -p -\tset permissions\n"
		"    -n -\tkey length in bits: 40 <= n <= 128\n"
		);
	exit(1);
}

void preloadobjstms(pdf_xref *xref)
{
	fz_error *error;
	fz_obj *obj;
	int i;

	for (i = 0; i < xref->len; i++)
	{
		if (xref->table[i].type == 'o')
		{
			error = pdf_loadobject(&obj, xref, i, 0);
			if (error) fz_abort(error);
			fz_dropobj(obj);
		}
	}
}

void expandstreams(pdf_xref *xref)
{
	fz_error *error;
	fz_obj *stmobj;
	fz_buffer *buf;
	fz_obj *stmlen;
	int i, gen;

	for (i = 0; i < xref->len; i++)
	{
		if (xref->table[i].type == 'n')
		{
			gen = xref->table[i].gen;

			if (pdf_isstream(xref, i, gen))
			{
				error = pdf_loadobject(&stmobj, xref, i, gen);
				if (error) fz_abort(error);

				error = pdf_loadstream(&buf, xref, i, gen);
				if (error) fz_abort(error);

				fz_dictdels(stmobj, "Filter");
				fz_dictdels(stmobj, "DecodeParms");

				error = fz_newint(&stmlen, buf->wp - buf->rp);
				if (error) fz_abort(error);
				error = fz_dictputs(stmobj, "Length", stmlen);
				if (error) fz_abort(error);
				fz_dropobj(stmlen);

				pdf_updateobject(xref, i, gen, stmobj);
				pdf_updatestream(xref, i, gen, buf);

				fz_dropobj(stmobj);
			}
		}
	}
}

int main(int argc, char **argv)
{
	fz_error *error;
	char *infile;
	char *outfile;
	pdf_xref *xref;
	int c;

	pdf_crypt *encrypt = 0;
	int doencrypt = 0;
	int dorepair = 0;
	int doexpand = 0;
	int dogc = 0;

	char *userpw = "";
	char *ownerpw = "";
	int perms = -4; /* 0xfffffffc */
	int keylen = 40;
	char *password = "";

	while ((c = getopt(argc, argv, "rgxd:eu:o:p:n:")) != -1)
	{
		switch (c)
		{
		case 'r': ++ dorepair; break;
		case 'x': ++ doexpand; break;
		case 'g': ++ dogc; break;
		case 'e': ++ doencrypt; break;
		case 'u': userpw = optarg; break;
		case 'o': ownerpw = optarg; break;
		case 'p': perms = atoi(optarg); break;
		case 'n': keylen = atoi(optarg); break;
		case 'd': password = optarg; break;
		default: usage();
		}
	}

	if (argc - optind < 2)
		usage();

	infile = argv[optind++];
	outfile = argv[optind++];

	error = pdf_newxref(&xref);

	if (dorepair)
		error = pdf_repairxref(xref, infile);
	else
		error = pdf_loadxref(xref, infile);
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

	if (doencrypt)
	{
		fz_obj *id = fz_dictgets(xref->trailer, "ID");
		if (!id)
			fz_packobj(&id, "[(ABCDEFGHIJKLMNOP)(ABCDEFGHIJKLMNOP)]");
		else
			fz_keepobj(id);
		error = pdf_newencrypt(&encrypt, userpw, ownerpw, perms, keylen, id);
		if (error)
			fz_abort(error);
		fz_dropobj(id);
	}

	if (doexpand)
		expandstreams(xref);

	if (dogc)
	{
		preloadobjstms(xref);
		pdf_garbagecollect(xref);
	}

	error = pdf_savexref(xref, outfile, encrypt);
	if (error)
		fz_abort(error);

	if (encrypt)
		pdf_dropcrypt(encrypt);

	pdf_closexref(xref);

	return 0;
}

