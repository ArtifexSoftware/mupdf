#include <fitz.h>
#include <mupdf.h>

enum
{
	TUSECMAP = PDF_NTOKENS,
	TBEGINCODESPACERANGE,
	TENDCODESPACERANGE,
	TBEGINBFCHAR,
	TENDBFCHAR,
	TBEGINBFRANGE,
	TENDBFRANGE,
	TBEGINCIDCHAR,
	TENDCIDCHAR,
	TBEGINCIDRANGE,
	TENDCIDRANGE,
};

static int tokenfromkeyword(unsigned char *key)
{
    if (!strcmp(key, "usecmap")) return TUSECMAP;
    if (!strcmp(key, "begincodespacerange")) return TBEGINCODESPACERANGE;
    if (!strcmp(key, "endcodespacerange")) return TENDCODESPACERANGE;
    if (!strcmp(key, "beginbfchar")) return TBEGINBFCHAR;
    if (!strcmp(key, "endbfchar")) return TENDBFCHAR;
    if (!strcmp(key, "beginbfrange")) return TBEGINBFRANGE;
    if (!strcmp(key, "endbfrange")) return TENDBFRANGE;
    if (!strcmp(key, "begincidchar")) return TBEGINCIDCHAR;
    if (!strcmp(key, "endcidchar")) return TENDCIDCHAR;
    if (!strcmp(key, "begincidrange")) return TBEGINCIDRANGE;
    if (!strcmp(key, "endcidrange")) return TENDCIDRANGE;
	return PDF_TKEYWORD;
}

static int codefromstring(unsigned char *buf, int len)
{
	int a = 0;
	while (len--)
		a = (a << 8) | *buf++;
	return a;
}

static int mylex(fz_file *file, unsigned char *buf, int n, int *sl)
{
	int token = pdf_lex(file, buf, n, sl);
	if (token == PDF_TKEYWORD)
		token = tokenfromkeyword(buf);
	return token;
}

static fz_error *parsecmapname(fz_cmap *cmap, fz_file *file)
{
	unsigned char buf[256];
	int token;
	int len;

	token = mylex(file, buf, sizeof buf, &len);
	if (token == PDF_TNAME) {
		fz_setcmapname(cmap, buf);
		return nil;
	}

	return fz_throw("syntaxerror in CMap after /CMapName");
}

static fz_error *parsewmode(fz_cmap *cmap, fz_file *file)
{
	unsigned char buf[256];
	int token;
	int len;

	token = mylex(file, buf, sizeof buf, &len);
	if (token == PDF_TINT) {
		fz_setwmode(cmap, atoi(buf));
		return nil;
	}

	return fz_throw("syntaxerror in CMap after /WMode");
}

static fz_error *parsecodespacerange(fz_cmap *cmap, fz_file *file)
{
	unsigned char buf[256];
	int token;
	int len;
	fz_error *error;
	int lo, hi;

	while (1)
	{
		token = mylex(file, buf, sizeof buf, &len);

		if (token == TENDCODESPACERANGE)
			return nil;

		else if (token == PDF_TSTRING)
		{
			lo = codefromstring(buf, len);
			token = mylex(file, buf, sizeof buf, &len);
			if (token == PDF_TSTRING)
			{
				hi = codefromstring(buf, len);
				error = fz_addcodespacerange(cmap, lo, hi, len);
				if (error)
					return error;
			}
			else break;
		}

		else break;
	}

	return fz_throw("syntaxerror in CMap codespacerange section");
}

static fz_error *parsecidrange(fz_cmap *cmap, fz_file *file)
{
	unsigned char buf[256];
	int token;
	int len;
	fz_error *error;
	int lo, hi, dst;

	while (1)
	{
		token = mylex(file, buf, sizeof buf, &len);

		if (token == TENDCIDRANGE)
			return nil;

		else if (token != PDF_TSTRING)
			goto cleanup;

		lo = codefromstring(buf, len);

		token = mylex(file, buf, sizeof buf, &len);
		if (token != PDF_TSTRING)
			goto cleanup;

		hi = codefromstring(buf, len);

		token = mylex(file, buf, sizeof buf, &len);
		if (token != PDF_TINT)
			goto cleanup;

		dst = atoi(buf);

		error = fz_addcidrange(cmap, lo, hi, dst);
		if (error)
			return error;
	}

cleanup:
	return fz_throw("syntaxerror in CMap cidrange section");
}

static fz_error *parsecidchar(fz_cmap *cmap, fz_file *file)
{
	unsigned char buf[256];
	int token;
	int len;
	fz_error *error;
	int src, dst;

	while (1)
	{
		token = mylex(file, buf, sizeof buf, &len);

		if (token == TENDCIDCHAR)
			return nil;

		else if (token != PDF_TSTRING)
			goto cleanup;

		src = codefromstring(buf, len);

		token = mylex(file, buf, sizeof buf, &len);
		if (token != PDF_TINT)
			goto cleanup;

		dst = atoi(buf);

		error = fz_addcidrange(cmap, src, src, dst);
		if (error)
			return error;
	}

cleanup:
	return fz_throw("syntaxerror in CMap cidchar section");
}

static fz_error *parsebfrange(fz_cmap *cmap, fz_file *file)
{
	unsigned char buf[256];
	int token;
	int len;
	fz_error *error;
	int lo, hi, dst;

	while (1)
	{
		token = mylex(file, buf, sizeof buf, &len);

		if (token == TENDBFRANGE)
			return nil;

		else if (token != PDF_TSTRING)
			goto cleanup;

		lo = codefromstring(buf, len);

		token = mylex(file, buf, sizeof buf, &len);
		if (token != PDF_TSTRING)
			goto cleanup;

		hi = codefromstring(buf, len);

		token = mylex(file, buf, sizeof buf, &len);
		/* Note: does not handle [ /Name /Name /Name ... ] */
		if (token != PDF_TSTRING)
			goto cleanup;

		dst = codefromstring(buf, len);

		error = fz_addcidrange(cmap, lo, hi, dst);
		if (error)
			return error;
	}

cleanup:
	return fz_throw("syntaxerror in CMap bfrange section");
}

static fz_error *parsebfchar(fz_cmap *cmap, fz_file *file)
{
	unsigned char buf[256];
	int token;
	int len;
	fz_error *error;
	int src, dst;

	while (1)
	{
		token = mylex(file, buf, sizeof buf, &len);

		if (token == TENDBFCHAR)
			return nil;

		else if (token != PDF_TSTRING)
			goto cleanup;

		src = codefromstring(buf, len);

		token = mylex(file, buf, sizeof buf, &len);
		/* Note: does not handle /dstName */
		if (token != PDF_TSTRING)
			goto cleanup;

		dst = codefromstring(buf, len);

		error = fz_addcidrange(cmap, src, src, dst);
		if (error)
			return error;
	}

cleanup:
	return fz_throw("syntaxerror in CMap bfchar section");
}

fz_error *
pdf_parsecmap(fz_cmap **cmapp, fz_file *file)
{
	fz_error *error;
	fz_cmap *cmap;
	unsigned char key[64];
	unsigned char buf[256];
	int token;
	int len;

	error = fz_newcmap(&cmap);
	if (error)
		return error;
	*cmapp = cmap;

	strcpy(key, ".notdef");

	while (1)
	{
		token = mylex(file, buf, sizeof buf, &len);

		if (token == PDF_TEOF)
			break;

		else if (token == PDF_TERROR)
		{
			error = fz_throw("syntaxerror in CMap");
			goto cleanup;
		}

		else if (token == PDF_TNAME)
		{
			if (!strcmp(buf, "CMapName"))
			{
				error = parsecmapname(cmap, file);
				if (error)
					goto cleanup;
			}
			else if (!strcmp(buf, "WMode"))
			{
				error = parsewmode(cmap, file);
				if (error)
					goto cleanup;
			}
			else
				strlcpy(key, buf, sizeof key);
		}

		else if (token == TUSECMAP)
		{
			fz_setusecmapname(cmap, key);
		}

		else if (token == TBEGINCODESPACERANGE)
		{
			error = parsecodespacerange(cmap, file);
			if (error)
				goto cleanup;
		}

		else if (token == TBEGINBFCHAR)
		{
			error = parsebfchar(cmap, file);
			if (error)
				goto cleanup;
		}

		else if (token == TBEGINCIDCHAR)
		{
			error = parsecidchar(cmap, file);
			if (error)
				goto cleanup;
		}

		else if (token == TBEGINBFRANGE)
		{
			error = parsebfrange(cmap, file);
			if (error)
				goto cleanup;
		}

		else if (token == TBEGINCIDRANGE)
		{
			error = parsecidrange(cmap, file);
			if (error)
				goto cleanup;
		}

		/* ignore everything else */
	}

	error = fz_endcidrange(cmap);
	if (error)
		goto cleanup;

	return nil;

cleanup:
	fz_freecmap(cmap);
	*cmapp = nil;
	return error;
}

fz_error *
pdf_loadembeddedcmap(fz_cmap **cmapp, pdf_xref *xref, fz_obj *stmref)
{
	fz_obj *stmobj = stmref;
	fz_error *error = nil;
	fz_cmap *cmap = nil;
	fz_cmap *usecmap;
	fz_obj *wmode;
	fz_obj *obj;

	error = pdf_resolve(&stmobj, xref);
	if (error)
		return error;

printf("  embedded cmap: ");
fz_fprintcobj(stdout, stmobj);
printf("\n");
fflush(stdout);

	error = pdf_openstream(xref, stmref);
	if (error)
		goto cleanup;

	error = pdf_parsecmap(&cmap, xref->file);
	if (error)
		goto cleanup;

	pdf_closestream(xref);

	wmode = fz_dictgets(stmobj, "WMode");
	if (fz_isint(wmode))
		fz_setwmode(cmap, fz_toint(wmode));

	obj = fz_dictgets(stmobj, "UseCMap");
	if (fz_isname(obj))
	{
		printf("  usecmap predefined: %s\n", fz_toname(obj));
		error = pdf_loadsystemcmap(&usecmap, fz_toname(obj));
		if (error)
			goto cleanup;
		fz_setusecmap(cmap, usecmap);
	}
	else if (fz_isindirect(obj))
	{
		printf("  usecmap recursive pdf obj\n");
		error = pdf_loadembeddedcmap(&usecmap, xref, obj);
		if (error)
			goto cleanup;
		fz_setusecmap(cmap, usecmap);
	}

	*cmapp = cmap;

	fz_dropobj(stmobj);
	return nil;

cleanup:
	if (cmap)
		fz_freecmap(cmap);
	fz_dropobj(stmobj);
	*cmapp = nil;
	return error;
}

fz_error *
pdf_loadsystemcmap(fz_cmap **cmapp, char *name)
{
	fz_error *error = nil;
	fz_file *file;
	char *cmapdir;
	char *usecmapname;
	fz_cmap *usecmap;
	char path[1024];

	*cmapp = nil;

	cmapdir = getenv("CMAPDIR");
	if (!cmapdir)
		return fz_throw("ioerror: CMAPDIR environment not set");

	strlcpy(path, cmapdir, sizeof path);
	strlcat(path, "/", sizeof path);
	strlcat(path, name, sizeof path);

printf("  system cmap loading %s\n", path);

	error = fz_openfile(&file, path, O_RDONLY);
	if (error)
		goto cleanup;

	error = pdf_parsecmap(cmapp, file);
	if (error)
		goto cleanup;

	fz_closefile(file);

	usecmapname = fz_getusecmapname(*cmapp);
	if (usecmapname)
	{
printf("  system cmap: usecmap %s\n", usecmapname);
		error = pdf_loadsystemcmap(&usecmap, usecmapname);
		if (error)
			goto cleanup;
		fz_setusecmap(*cmapp, usecmap);
	}

	return nil;

cleanup:
	if (*cmapp)
		fz_freecmap(*cmapp);
	if (file)
		fz_closefile(file);
	*cmapp = nil;
	return error;
}

fz_error *
pdf_makeidentitycmap(fz_cmap **cmapp, int wmode)
{
	fz_error *error = nil;

	error = fz_newcmap(cmapp);
	if (error)
		return error;

	error = fz_addcodespacerange(*cmapp, 0x0000, 0xffff, 2);
	if (error) {
		fz_freecmap(*cmapp);
		return error;
	}

	error = fz_addcidrange(*cmapp, 0x0000, 0xffff, 0);
	if (error) {
		fz_freecmap(*cmapp);
		return error;
	}

	error = fz_endcidrange(*cmapp);
	if (error) {
		fz_freecmap(*cmapp);
		return error;
	}

	fz_setwmode(*cmapp, wmode);

	return nil;
}

