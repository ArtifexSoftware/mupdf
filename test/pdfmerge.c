#include <fitz.h>
#include <mupdf.h>

void usage()
{
	fprintf(stderr,
		"usage: pdfmerge [options] file.pdf pages ...\n"
		"  -o -\toutput file name (default out.pdf)\n"
		"  -d -\tset user password for decryption\n"
		"  -e\tencrypt outfile\n"
		"    -U -\tset user password for encryption\n"
		"    -O -\tset owner password\n"
		"    -P -\tset permissions\n"
		"    -N -\tkey length in bits: 40 <= n <= 128\n"
		);
	exit(1);
}

int main(int argc, char **argv)
{
	fz_error *error;
	char *savename = "out.pdf";
	pdf_pagetree *srcpages;
	fz_obj *srcrefs;
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

	pdf_crypt *encrypt = 0;
	int doencrypt = 0;

	char *userpw = "";
	char *ownerpw = "";
	int perms = -4; /* 0xfffffffc */
	int keylen = 40;
	char *password = "";

	while ((c = getopt(argc, argv, "reo:U:O:P:N:")) != -1)
	{
		switch (c)
		{
		case 'e': ++ doencrypt; break;
		case 'o': savename = optarg; break;
		case 'U': userpw = optarg; break;
		case 'O': ownerpw = optarg; break;
		case 'P': perms = atoi(optarg); break;
		case 'N': keylen = atoi(optarg); break;
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

	error = pdf_emptyxref(dst, 1.3);
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
		error = pdf_newxref(&src);
		if (error)
			fz_abort(error);

		error = pdf_openxref(src, argv[i]);
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

		for (k = 0; k < srcpages->count; k++)
		{
			fz_dictdels(srcpages->pobj[k], "Parent");
			fz_dictdels(srcpages->pobj[k], "B");
			fz_dictdels(srcpages->pobj[k], "PieceInfo");
			fz_dictdels(srcpages->pobj[k], "Metadata");
			fz_dictdels(srcpages->pobj[k], "Annots");
			fz_dictdels(srcpages->pobj[k], "Tabs");

			pdf_saveobject(src,
				fz_toobjid(srcpages->pref[k]),
				fz_togenid(srcpages->pref[k]),
				srcpages->pobj[k]);
			error = fz_arraypush(srcrefs, srcpages->pref[k]);
			if (error)
				fz_abort(error);
		}

		error = pdf_transplant(dst, src, &srcrefs, srcrefs);
		if (error)
			fz_abort(error);

		for (k = 0; k < fz_arraylen(srcrefs); k++)
		{
			error = fz_arraypush(dstrefs, fz_arrayget(srcrefs, k));
			if (error)
				fz_abort(error);
		}

		pdf_freepagetree(srcpages);

		pdf_closexref(src);
	}

	/*
	 * Create and relink Pages object
	 */

	error = pdf_createobject(dst, &pagesoid, &pagesgid);
	if (error)
		fz_abort(error);

	error = fz_packobj(&obj,
				"<</Type/Pages/Count %i/Kids %o>>",
				fz_arraylen(dstrefs),
				dstrefs);
	if (error)
		fz_abort(error);

	error = pdf_saveobject(dst, pagesoid, pagesgid, obj);
	if (error)
		fz_abort(error);

	fz_dropobj(obj);

	error = fz_newindirect(&pagesref, pagesoid, pagesgid);
	if (error)
		fz_abort(error);

	for (i = 0; i < fz_arraylen(dstrefs); i++)
	{
		int oid = fz_toobjid(fz_arrayget(dstrefs, i));
		int gid = fz_togenid(fz_arrayget(dstrefs, i));
		error = pdf_loadobject0(&obj, dst, oid, gid, nil);
		if (error)
			fz_abort(error);
		error = fz_dictputs(obj, "Parent", pagesref);
		if (error)
			fz_abort(error);
		error = pdf_saveobject(dst, oid, gid, obj);
		if (error)
			fz_abort(error);
		fz_dropobj(obj);
	}

	fz_dropobj(pagesref);

	/*
	 * Create Catalog and trailer
	 */

	error = pdf_createobject(dst, &rootoid, &rootgid);
	if (error)
		fz_abort(error);

	error = fz_packobj(&obj,
				"<</Type/Catalog/Pages %r>>",
				pagesoid, pagesgid);
	if (error)
		fz_abort(error);

	error = pdf_saveobject(dst, rootoid, rootgid, obj);
	if (error)
		fz_abort(error);

	fz_dropobj(obj);

	error = fz_packobj(&dst->trailer, "<</Root %r>>", rootoid, rootgid);
	if (error)
		fz_abort(error);

	/*
	 * Write out the new PDF
	 */

	if (doencrypt)
	{
		fz_obj *id = fz_dictgets(dst->trailer, "ID");
		if (!id)
			fz_packobj(&id, "[(ABCDEFGHIJKLMNOP)(ABCDEFGHIJKLMNOP)]");
		else
			fz_keepobj(id);
		error = pdf_newencrypt(&encrypt, userpw, ownerpw, perms, keylen, id);
		if (error)
			fz_abort(error);
		fz_dropobj(id);
	}

	error = pdf_savepdf(dst, savename, encrypt);
	if (error)
		fz_abort(error);

	return 0;
}

