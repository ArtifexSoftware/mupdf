#include <fitz.h>
#include <mupdf.h>

void usage()
{
	fprintf(stderr,
		"usage: pdfselect [options] infile.pdf outfile.pdf pageranges\n"
		"  -d -\tpassword for decryption\n"
		"  -e  \tselect only even pages\n"
		"  -o  \tselect only odd pages\n"
		"  -r  \toutput in reverse order\n"
		"  -v  \tverbose\n"
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

int main(int argc, char **argv)
{
	fz_error *error;
	char *password = "";
	char *infile;
	char *outfile;
	pdf_xref *xref;
	pdf_pagetree *pages;
	fz_obj *pagesref;
	fz_obj *kids;
	int i, k;
	int c;
	int page;
	int rootoid;
	int rootgid;
	int kidsoid;
	int kidsgid;
	int pagesoid;
	int pagesgid;
	fz_obj *obj;

	int verbose = 0;
	int even = 0;
	int odd = 0;
	int reverse = 0;
	int all = 0;

	while ((c = getopt(argc, argv, "d:eorv")) != -1)
	{
		switch (c)
		{
		case 'd': password = optarg; break;
		case 'e': ++ even; break;
		case 'o': ++ odd; break;
		case 'r': ++ reverse; break;
		case 'v': ++ verbose; break;
		default: usage();
		}
	}

	if (argc - optind < 2)
		usage();

	if (argc - optind < 3 && !even && !odd && !reverse)
		usage();

	if (argc - optind == 2)
		all = 1;

	infile = argv[optind++];
	outfile = argv[optind++];

	if (verbose)
		printf("loading pdf '%s'\n", infile);

	error = pdf_newxref(&xref);
	if (error)
		fz_abort(error);

	error = pdf_loadxref(xref, infile);
	if (error)
		fz_abort(error);

	error = pdf_decryptxref(xref);
	if (error)
		fz_abort(error);

	if (xref->crypt)
	{
		error = pdf_setpassword(xref->crypt, password);
		if (error)
			fz_abort(error);
	}

	error = pdf_loadpagetree(&pages, xref);
	if (error)
		fz_abort(error);

	/*
	 * Kill annotations on all pages
	 */

	if (verbose)
		printf("killing time\n");

	for (k = 0; k < pages->count; k++)
	{
		fz_dictdels(pages->pobj[k], "Parent");
		fz_dictdels(pages->pobj[k], "B");
		fz_dictdels(pages->pobj[k], "PieceInfo");
		fz_dictdels(pages->pobj[k], "Metadata");
		fz_dictdels(pages->pobj[k], "Annots");
		fz_dictdels(pages->pobj[k], "Tabs");
		pdf_updateobject(xref,
			fz_tonum(pages->pref[k]),
			fz_togen(pages->pref[k]),
			pages->pobj[k]);
	}

	/*
	 * Save the pages we want to keep, in the order specified
	 */

	error = fz_newarray(&kids, 100);
	if (error)
		fz_abort(error);

	for ( ; optind < argc; optind++)
	{
		int spage, epage;
		char *spec = argv[optind];
		char *dash = strchr(spec, '-');

		if (dash == spec)
			spage = epage = 1;
		else
			spage = epage = atoi(spec);

		if (dash)
		{
			if (strlen(dash) > 1)
				epage = atoi(dash+1);
			else
				epage = pdf_getpagecount(pages);
		}

		if (spage > epage)
			page = spage, spage = epage, epage = page;

		for (page = spage; page <= epage; page++)
		{
			if (page < 1 || page > pdf_getpagecount(pages))
				continue;
			if (odd && (page & 1) != 1)
				continue;
			if (even && (page & 1) != 0)
				continue;
			error = fz_arraypush(kids, pages->pref[page-1]);
			if (error)
				fz_abort(error);
		}
	}

	if (all)
	{
		for (page = 1; page <= pdf_getpagecount(pages); page++)
		{
			if (odd && (page & 1) != 1)
				continue;
			if (even && (page & 1) != 0)
				continue;
			error = fz_arraypush(kids, pages->pref[page-1]);
			if (error)
				fz_abort(error);
		}
	}

	if (reverse)
	{
		fz_obj *o1, *o2;
		int len = fz_arraylen(kids);
		for (i = 0; i < len / 2; i++)
		{
			o1 = fz_keepobj(fz_arrayget(kids, i));
			o2 = fz_keepobj(fz_arrayget(kids, len - i - 1));
			fz_arrayput(kids, i, o2);
			fz_arrayput(kids, len - i - 1, o1);
		}
	}

	/*
	 * Save the new kids array
	 */

	error = pdf_allocobject(xref, &kidsoid, &kidsgid);
	if (error)
		fz_abort(error);

	pdf_updateobject(xref, kidsoid, kidsgid, kids);

	/*
	 * Save the new pages object
	 */

	error = pdf_allocobject(xref, &pagesoid, &pagesgid);
	if (error)
		fz_abort(error);

	error = fz_packobj(&obj,
				"<</Type/Pages/Count %i/Kids %r>>",
				fz_arraylen(kids), kidsoid, kidsgid);
	if (error)
		fz_abort(error);

	pdf_updateobject(xref, pagesoid, pagesgid, obj);

	fz_dropobj(obj);

	/*
	 * Relink parents to point to new pages object
	 */

	error = fz_newindirect(&pagesref, pagesoid, pagesgid);
	if (error)
		fz_abort(error);

	for (i = 0; i < fz_arraylen(kids); i++)
	{
		int oid = fz_tonum(fz_arrayget(kids, i));
		int gid = fz_togen(fz_arrayget(kids, i));
		error = pdf_loadobject(&obj, xref, oid, gid);
		if (error)
			fz_abort(error);
		error = fz_dictputs(obj, "Parent", pagesref);
		if (error)
			fz_abort(error);
		pdf_updateobject(xref, oid, gid, obj);
		fz_dropobj(obj);
	}

	fz_dropobj(pagesref);

	/*
	 * Create new catalog and trailer
	 */

	error = pdf_allocobject(xref, &rootoid, &rootgid);
	if (error)
		fz_abort(error);

	error = fz_packobj(&obj,
				"<</Type/Catalog/Pages %r>>",
				pagesoid, pagesgid);
	if (error)
		fz_abort(error);

	pdf_updateobject(xref, rootoid, rootgid, obj);

	fz_dropobj(obj);

	error = fz_packobj(&xref->trailer, "<</Root %r>>", rootoid, rootgid);
	if (error)
		fz_abort(error);

	/*
	 * Write out the new PDF
	 */

	if (verbose)
		printf("garbage collecting\n");

	preloadobjstms(xref);
	pdf_garbagecollect(xref);

	if (verbose)
		printf("saving pdf '%s'\n", outfile);

	error = pdf_savexref(xref, outfile, nil);
	if (error)
		fz_abort(error);

	pdf_closexref(xref);

	return 0;
}

