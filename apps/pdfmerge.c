#include <fitz.h>
#include <mupdf.h>

void usage()
{
	fprintf(stderr,
		"usage: pdfmerge [options] file1.pdf file2.pdf ...\n"
		"  -d -\tpassword for decryption\n"
		"  -o -\toutput file name (default out.pdf)\n"
		"  -v  \tverbose\n"
		);
	exit(1);
}

int main(int argc, char **argv)
{
	fz_error *error;
	char *savename = "out.pdf";
	pdf_pagetree *srcpages;
	fz_obj *srcrefs;
	fz_obj *newsrcrefs;
	fz_obj *dstrefs;
	pdf_xref *dst;
	pdf_xref *src;
	int rootoid;
	int rootgid;
	int pagesoid;
	int pagesgid;
	fz_obj *pagesref;
	fz_obj *obj;
	int i, k;
	int c;

	int verbose = 0;
	char *password = "";

	while ((c = getopt(argc, argv, "vo:d:")) != -1)
	{
		switch (c)
		{
		case 'v': ++ verbose; break;
		case 'o': savename = optarg; break;
		case 'd': password = optarg; break;
		default: usage();
		}
	}

	if (argc - optind < 1)
		usage();

	/*
	 * Create new blank xref table
	 */

	error = pdf_newxref(&dst);
	if (error)
		fz_abort(error);

	error = pdf_initxref(dst);
	if (error)
		fz_abort(error);	

	error = fz_newarray(&dstrefs, 100);
	if (error)
		fz_abort(error);

	/*
	 * Copy pages saving refs in dstrefs
	 */

	for (i = optind; i < argc; i++)
	{
		if (verbose)
		{
			printf("loading pdf '%s' ", argv[i]);
			fflush(stdout);
		}

		error = pdf_newxref(&src);
		if (error)
			fz_abort(error);

		error = pdf_loadxref(src, argv[i]);
		if (error)
			fz_abort(error);

		error = pdf_decryptxref(src);
		if (error)
			fz_abort(error);

		if (src->crypt)
		{
			error = pdf_setpassword(src->crypt, password);
			if (error)
				fz_abort(error);
		}

		error = pdf_loadpagetree(&srcpages, src);
		if (error)
			fz_abort(error);

		error = fz_newarray(&srcrefs, 100);
		if (error)
			fz_abort(error);

		if (verbose)
			printf("(%d pages)\n", srcpages->count);

		for (k = 0; k < srcpages->count; k++)
		{
			fz_dictdels(srcpages->pobj[k], "Parent");
			fz_dictdels(srcpages->pobj[k], "B");
			fz_dictdels(srcpages->pobj[k], "PieceInfo");
			fz_dictdels(srcpages->pobj[k], "Metadata");
			fz_dictdels(srcpages->pobj[k], "Annots");
			fz_dictdels(srcpages->pobj[k], "Tabs");

			pdf_updateobject(src,
				fz_tonum(srcpages->pref[k]),
				fz_togen(srcpages->pref[k]),
				srcpages->pobj[k]);
			error = fz_arraypush(srcrefs, srcpages->pref[k]);
			if (error)
				fz_abort(error);
		}

		error = pdf_transplant(dst, src, &newsrcrefs, srcrefs);
		if (error)
			fz_abort(error);

		for (k = 0; k < fz_arraylen(newsrcrefs); k++)
		{
			error = fz_arraypush(dstrefs, fz_arrayget(newsrcrefs, k));
			if (error)
				fz_abort(error);
		}

		fz_dropobj(srcrefs);
		fz_dropobj(newsrcrefs);

		pdf_droppagetree(srcpages);

		pdf_closexref(src);
	}

	/*
	 * Create and relink Pages object
	 */

	if (verbose)
		printf("creating pdf '%s' (%d pages)\n",
				savename, fz_arraylen(dstrefs));

	error = pdf_allocobject(dst, &pagesoid, &pagesgid);
	if (error)
		fz_abort(error);

	error = fz_packobj(&obj,
				"<</Type/Pages/Count %i/Kids %o>>",
				fz_arraylen(dstrefs),
				dstrefs);
	if (error)
		fz_abort(error);

	pdf_updateobject(dst, pagesoid, pagesgid, obj);

	fz_dropobj(obj);

	error = fz_newindirect(&pagesref, pagesoid, pagesgid);
	if (error)
		fz_abort(error);

	for (i = 0; i < fz_arraylen(dstrefs); i++)
	{
		int oid = fz_tonum(fz_arrayget(dstrefs, i));
		int gid = fz_togen(fz_arrayget(dstrefs, i));
		error = pdf_loadobject(&obj, dst, oid, gid);
		if (error)
			fz_abort(error);
		error = fz_dictputs(obj, "Parent", pagesref);
		if (error)
			fz_abort(error);
		pdf_updateobject(dst, oid, gid, obj);
		fz_dropobj(obj);
	}

	fz_dropobj(pagesref);

	/*
	 * Create Catalog and trailer
	 */

	error = pdf_allocobject(dst, &rootoid, &rootgid);
	if (error)
		fz_abort(error);

	error = fz_packobj(&obj,
				"<</Type/Catalog/Pages %r>>",
				pagesoid, pagesgid);
	if (error)
		fz_abort(error);

	pdf_updateobject(dst, rootoid, rootgid, obj);

	fz_dropobj(obj);

	error = fz_packobj(&dst->trailer, "<</Root %r>>", rootoid, rootgid);
	if (error)
		fz_abort(error);

	/*
	 * Write out the new PDF
	 */

	error = pdf_savexref(dst, savename, nil);
	if (error)
		fz_abort(error);

	fz_dropobj(dstrefs);
	pdf_closexref(dst);

	return 0;
}

