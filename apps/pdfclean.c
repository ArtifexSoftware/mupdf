#include <fitz.h>
#include <mupdf.h>

void usage()
{
	fprintf(stderr,
		"usage: pdfclean [options] infile.pdf outfile.pdf\n"
		"  -d -\tpassword for decryption\n"
		"  -g  \tgarbage collect unused objects\n"
		"  -r  \trebuild xref table\n"
		"  -x  \texpand compressed streams\n"
		"  -e  \tencrypt outfile\n"
		"    -u -\tset user password for encryption\n"
		"    -o -\tset owner password\n"
		"    -p -\tset permissions (combine letters 'pmca')\n"
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
	unsigned perms = 0xfffff0c0;	/* nothing allowed */
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
		case 'p':
			/* see TABLE 3.15 User access permissions */
			perms = 0xfffff0c0;
			if (strchr(optarg, 'p')) /* print */
				perms |= (1 << 2) | (1 << 11);
			if (strchr(optarg, 'm')) /* modify */
				perms |= (1 << 3) | (1 << 10);
			if (strchr(optarg, 'c')) /* copy */
				perms |= (1 << 4) | (1 << 9);
			if (strchr(optarg, 'a')) /* annotate / forms */
				perms |= (1 << 5) | (1 << 8);
			break;
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

