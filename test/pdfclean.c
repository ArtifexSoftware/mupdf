#include <fitz.h>
#include <mupdf.h>

#define encrypt encrypt3am

int (*printobj)(FILE*,fz_obj*) = fz_fprintobj;

/*
 * Rewrite PDF with cleaned up syntax, and consolidate the xref table.
 * Remove encryption while we're at it :)
 */

static FILE *out;

static pdf_xref *xt;

static int *ofslist;
static int *genlist;
static int *uselist;

static int dorebuild = 0;
static int doexpand = 0;
static pdf_crypt *encrypt = nil;
static fz_obj *encryptdict = nil;
static fz_obj *id = nil;
static int dogc = 0;

void usage()
{
	fprintf(stderr,
		"usage: pdfclean [options] infile.pdf outfile.pdf\n"
		"  -r\treconstruct broken xref table\n"
		"  -g\tgarbage collect unused objects\n"
		"  -x\texpand compressed streams\n"
		"  -c\twrite compact objects\n"
		"  -d -\tset user password for decryption\n"
		"  -e\tencrypt outfile\n"
		"  -u -\tset user password for encryption\n"
		"  -o -\tset owner password\n"
		"  -p -\tset permissions\n"
		"  -n -\tkey length in bits: 40 <= n <= 128\n"
		);
	exit(1);
}

void garbagecollect(fz_obj *ref);

void gc0(fz_obj *obj)
{
	int i;

	if (fz_isdict(obj))
		for (i = 0; i < fz_dictlen(obj); i++)
			gc0(fz_dictgetval(obj, i));

	if (fz_isarray(obj))
		for (i = 0; i < fz_arraylen(obj); i++)
			gc0(fz_arrayget(obj, i));

	if (fz_isindirect(obj))
		garbagecollect(obj);
}

void garbagecollect(fz_obj *ref)
{
	fz_obj *obj;
	int stmofs;

	if (uselist[fz_toobjid(ref)])
		return;

	uselist[fz_toobjid(ref)] = 1;

	pdf_loadindirect(&obj, xt, ref, &stmofs);

	if (stmofs != -1) {
		fz_obj *len = fz_dictgets(obj, "Length");
		if (fz_isindirect(len)) {
			pdf_loadindirect(&len, xt, len, nil);
			fz_dictputs(obj, "Length", len);
		}
	}

	gc0(obj);
}

void decodestream(fz_obj *obj, int ofs, int oid, int gid)
{
	fz_error *error;
	unsigned char buf[512];
	fz_filter *filter;
	fz_file *sf;
	int n;
	int len;
	fz_obj *lenobj;
	fz_obj *newdict;

	/* count length of decoded data */
	len = 0;

	error = pdf_buildstream(&filter, xt, obj, oid, gid);
	if (error) fz_abort(error);

	n = fz_seek(xt->file, ofs);

	fz_chainfile(&sf, xt->file, filter);

	while (1) {
		n = fz_read(sf, buf, sizeof buf);
		if (n < 0)
			fz_abort(fz_ferror(sf));
		if (n == 0)
			break;
		len += n;
	}

	fz_unchainfile(sf);

	/* change dictionary of object... */
	fz_copydict(&newdict, obj);

	fz_newint(&lenobj, len);
	fz_dictputs(newdict, "Length", lenobj);
	fz_dropobj(lenobj);

	fz_dictdels(newdict, "Filter");
	fz_dictdels(newdict, "DecodeParms");

	/* save object */
	fprintf(out, "%d %d obj\n", oid, gid);
	printobj(out, newdict);
	fprintf(out, "\n");
	fprintf(out, "stream\n");

	fz_dropobj(newdict);

	/* now decode stream for real */
	error = pdf_buildstream(&filter, xt, obj, oid, gid);
	if (error) fz_abort(error);

	fz_seek(xt->file, ofs);

	if (encrypt) {
		fz_filter *cf;
		pdf_cryptstm(&cf, encrypt, oid, gid);
		fz_newpipeline(&filter, filter, cf);
	}

	fz_chainfile(&sf, xt->file, filter);
	while (1) {
		n = fz_read(sf, buf, sizeof buf);
		if (n < 0)
			fz_abort(fz_ferror(sf));
		if (n == 0)
			break;
		fwrite(buf, 1, n, out);
	}
	fz_unchainfile(sf);

	/* the end */
	fprintf(out, "endstream\nendobj\n\n");

	return;
}

void savestream(fz_obj *obj, int ofs, int oid, int gid)
{
	unsigned char buf[512];
	fz_filter *filter;
	fz_file *sf;
	int len;
	int n;

	/* save object */
	fprintf(out, "%d %d obj\n", oid, gid);
	printobj(out, obj);
	fprintf(out, "\n");
	fprintf(out, "stream\n");

	/* copy stream */
	obj = fz_dictgets(obj, "Length");
	if (fz_isindirect(obj)) {
		pdf_loadindirect(&obj, xt, obj, nil);
		len = fz_toint(obj);
		fz_dropobj(obj);
	}
	else {
		len = fz_toint(obj);
	}

	fz_newnullfilter(&filter, len);

	if (xt->crypt) {
		fz_filter *cf;
		pdf_cryptstm(&cf, xt->crypt, oid, gid);
		fz_newpipeline(&filter, cf, filter);
	}

	if (encrypt) {
		fz_filter *cf;
		pdf_cryptstm(&cf, encrypt, oid, gid);
		fz_newpipeline(&filter, filter, cf);
	}

	fz_seek(xt->file, ofs);
	fz_chainfile(&sf, xt->file, filter);
	while (1)
	{
		n = fz_read(sf, buf, sizeof buf);
		if (n == 0)
			break;
		if (n < 0)
			fz_abort(fz_ferror(sf));
		fwrite(buf, 1, n, out);
	}
	fz_unchainfile(sf);

	/* the end */
	fprintf(out, "endstream\nendobj\n\n");
}

void deleteobject(int oid, int gid)
{
	uselist[oid] = 0;
}

void saveobject(int oid, int gid)
{
	fz_error *error;
	fz_obj *obj;
	fz_obj *t;
	int stmofs;

	error = pdf_loadobj(&obj, xt, oid, gid, &stmofs);
	if (error) fz_abort(error);

	/* trash ObjStm and XrefStm objects */
	if (fz_isdict(obj)) {
		t = fz_dictgets(obj, "Type");
		if (fz_isname(t) && strcmp(fz_toname(t), "ObjStm") == 0) {
			deleteobject(oid, gid);
			fz_dropobj(obj);
			return;
		}
		if (fz_isname(t) && strcmp(fz_toname(t), "XRef") == 0) {
			deleteobject(oid, gid);
			fz_dropobj(obj);
			return;
		}
	}

	if (encrypt)
		pdf_cryptobj(encrypt, obj, oid, gid);

	if (stmofs == -1) {
		fprintf(out, "%d %d obj\n", oid, gid);
		printobj(out, obj);
		fprintf(out, "\nendobj\n\n");
	}
	else if (doexpand) {
		decodestream(obj, stmofs, oid, gid);
	}
	else {
		savestream(obj, stmofs, oid, gid);
	}

	fz_dropobj(obj);
}

void savexref(void)
{
	fz_obj *newtrailer;
	fz_obj *obj;
	int startxref;
	int i;

	startxref = ftell(out);

	fprintf(out, "xref\n0 %d\n", xt->size);
	for (i = 0; i < xt->size; i++) {
		if (uselist[i])
			fprintf(out, "%010d %05d n \n", ofslist[i], genlist[i]);
		else
			fprintf(out, "%010d %05d f \n", ofslist[i], genlist[i]);
	}
	fprintf(out, "\n");

	fz_newdict(&newtrailer, 5);

	fz_newint(&obj, xt->size);
	fz_dictputs(newtrailer, "Size", obj);
	fz_dropobj(obj);

	obj = fz_dictgets(xt->trailer, "Info");
	if (obj) fz_dictputs(newtrailer, "Info", obj);

	obj = fz_dictgets(xt->trailer, "Root");
	if (obj) fz_dictputs(newtrailer, "Root", obj);

	fz_dictputs(newtrailer, "ID", id);

	if (encryptdict) {
		fz_newindirect(&obj, xt->size - 1, 0);
		fz_dictputs(newtrailer, "Encrypt", obj);
		fz_dropobj(obj);
	}

	fprintf(out, "trailer\n");
	printobj(out, newtrailer);
	fprintf(out, "\n\n");

	fprintf(out, "startxref\n%d\n%%%%EOF\n", startxref);
}

int main(int argc, char **argv)
{
	fz_error *error;
	fz_obj *obj;
	int lastfree;
	char *filename;
	int i;
	int c;

	int doencrypt = 0;
	char *password = "";
	char *userpw = "";
	char *ownerpw = "";
	int perms = -4; /* 0xfffffffc */
	int keylen = 40;

	while (1)
	{
		c = getopt(argc, argv, "rcxgeu:o:p:n:d:");

		if (c == -1)
			break;

		switch (c)
		{
		case 'r':
			dorebuild ++;
			break;
		case 'x':
			doexpand ++;
			break;
		case 'g':
			dogc ++;
			break;
		case 'c':
			printobj = fz_fprintcobj;
			break;
		case 'd':
			password = optarg;
			break;
		case 'e':
			doencrypt ++;
			break;
		case 'u':
			userpw = optarg;
			break;
		case 'o':
			ownerpw = optarg;
			break;
		case 'p':
			perms = atoi(optarg);
			break;
		case 'n':
			keylen = atoi(optarg);
			break;
		default:
			usage();
		}
	}

	if (argc - optind != 2)
		usage();

	filename = argv[optind];

	if (dorebuild)
		error = pdf_rebuildxref(&xt, filename);
	else
		error = pdf_openxref(&xt, filename);
	if (error) fz_abort(error);

	if (doencrypt && keylen > 40 && xt->version < 1.4)
		xt->version = 1.4;

	id = fz_dictgets(xt->trailer, "ID");
	obj = fz_dictgets(xt->trailer, "Encrypt");
	if (fz_isindirect(obj)) {
		pdf_loadindirect(&obj, xt, obj, nil);
	}
	if (obj && id) {
		pdf_newdecrypt(&xt->crypt, obj, id);
		error = pdf_setpassword(xt->crypt, password);
		if (error) fz_abort(error);
	}

	id = fz_dictgets(xt->trailer, "ID");
	if (!id)
		fz_parseobj(&id, "[ (foobar) (foobar) ]");

	if (doencrypt)
		pdf_newencrypt(&encrypt, &encryptdict, userpw, ownerpw, perms, keylen, id);

	out = fopen(argv[optind + 1], "w");
	if (!out) {
		fz_abort(fz_throw("open(%s): %s", argv[optind + 1], strerror(errno)));
	}

	fprintf(out, "%%PDF-%.1f\n\n", xt->version);

	ofslist = fz_malloc(sizeof(int) * (xt->size + 1));
	genlist = fz_malloc(sizeof(int) * (xt->size + 1));
	uselist = fz_malloc(sizeof(int) * (xt->size + 1));

	lastfree = 0;

	ofslist[0] = 0;
	genlist[0] = 65535;
	uselist[0] = 0;

	for (i = 1; i < xt->size; i++) {
		ofslist[i] = 0;
		genlist[i] = 0;
		uselist[i] = 1;
	}

	/* garbage collect from roots in trailer */
	if (dogc)
	{
		for (i = 1; i < xt->size; i++)
			uselist[i] = 0;

		obj = fz_dictgets(xt->trailer, "Info");
		if (fz_isindirect(obj))
			garbagecollect(obj);

		obj = fz_dictgets(xt->trailer, "Root");
		if (fz_isindirect(obj))
			garbagecollect(obj);

		obj = fz_dictgets(xt->trailer, "ID");
		if (fz_isindirect(obj))
			garbagecollect(obj);
	}

	/* pretty print objects */
	for (i = 0; i < xt->size; i++)
	{
		if (xt->table[i].type == 0)
			uselist[i] = 0;

		if (xt->table[i].type == 0)
			genlist[i] = xt->table[i].gen;
		if (xt->table[i].type == 1)
			genlist[i] = xt->table[i].gen;
		if (xt->table[i].type == 2)
			genlist[i] = 0;

		if (dogc && !uselist[i])
			continue;

		if (xt->table[i].type == 1 || xt->table[i].type == 2)
		{
			ofslist[i] = ftell(out);
			saveobject(i, genlist[i]);
		}
	}

	/* add encryption dictionary if we crypted */
	if (encryptdict) {
		xt->size ++;
		ofslist[xt->size - 1] = ftell(out);
		genlist[xt->size - 1] = 0;
		uselist[xt->size - 1] = 1;
		fprintf(out, "%d %d obj\n", xt->size - 1, 0);
		printobj(out, encryptdict);
		fprintf(out, "\nendobj\n\n");
	}

	/* construct linked list of free object slots */
	lastfree = 0;
	for (i = 1; i < xt->size; i++) {
		if (!uselist[i]) {
			genlist[i] ++;
			ofslist[lastfree] = i;
			lastfree = i;
		}
	}

	savexref();

	pdf_closexref(xt);

	fclose(out);

	return 0;
}

