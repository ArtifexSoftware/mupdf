#include <fitz.h>
#include <mupdf.h>

struct entry
{
	int oid;
	int gid;
	int ofs;
	int stmlen;
};

static fz_error *
parseobj(fz_file *file, unsigned char *buf, int cap, int *stmlen,
	int *isroot, int *isinfo)
{
	fz_error *error;
	fz_obj *dict = nil;
	fz_obj *length;
	fz_obj *filter;
	fz_obj *type;
	int tok, len;
	int stmofs;

	*stmlen = -1;
	*isroot = 0;
	*isinfo = 0;

	tok = pdf_lex(file, buf, cap, &len);
	if (tok == PDF_TODICT)
	{
		error = pdf_parsedict(&dict, file, buf, cap);
		if (error)
			return error;
	}

	if (fz_isdict(dict))
	{
		type = fz_dictgets(dict, "Type");
		if (fz_isname(type) && !strcmp(fz_toname(type), "Catalog"))
			*isroot = 1;

		filter = fz_dictgets(dict, "Filter");
		if (fz_isname(filter) && !strcmp(fz_toname(filter), "Standard"))
			return fz_throw("cannot repair encrypted files");

		if (fz_dictgets(dict, "Producer"))
			if (fz_dictgets(dict, "Creator"))
				if (fz_dictgets(dict, "Title"))
					*isinfo = 1;
	}

	while (	tok != PDF_TSTREAM &&
			tok != PDF_TENDOBJ &&
			tok != PDF_TERROR &&
			tok != PDF_TEOF )
		tok = pdf_lex(file, buf, cap, &len);

	if (tok == PDF_TSTREAM)
	{
		int c = fz_readbyte(file);
		if (c == '\r') {
			c = fz_peekbyte(file);
			if (c == '\n')
				fz_readbyte(file);
		}

		stmofs = fz_tell(file);
		
		length = fz_dictgets(dict, "Length");
		if (fz_isint(length))
		{
			fz_seek(file, stmofs + fz_toint(length));
			tok = pdf_lex(file, buf, cap, &len);
			if (tok == PDF_TENDSTREAM)
				goto atobjend;
			fz_seek(file, stmofs);
		}

		fz_read(file, buf, 8);
		while (memcmp(buf, "endstream", 8) != 0)
		{
			c = fz_readbyte(file);
			if (c == EOF)
				break;
			memmove(buf, buf + 1, 7);
			buf[7] = c;
		}

		*stmlen = fz_tell(file) - stmofs - 8;

atobjend:
		tok = pdf_lex(file, buf, cap, &len);
		if (tok == PDF_TENDOBJ)
			;
	}

	if (dict)
		fz_dropobj(dict);

	return nil;
}

fz_error *
pdf_repairxref(pdf_xref *xref, char *filename)
{
	fz_error *error;
	fz_file *file;

	struct entry *list = nil;
	int listlen;
	int listcap;
	int maxoid;

	unsigned char buf[65536];

	int oid, gid;
	int tmpofs, oidofs, gidofs;
	int stmlen;
	int isroot, rootoid = 0, rootgid = 0;
	int isinfo, infooid = 0, infogid = 0;
	int tok, len;
	int next;
	int n;
	int i;

	listlen = 0;
	listcap = 1024;
	list = fz_malloc(listcap * sizeof(struct entry));
	if (!list)
		return fz_outofmem;

	error = fz_openfile(&xref->file, filename, O_RDONLY);
	if (error)
		goto cleanup;

	file = xref->file;

	n = fz_seek(file, 0);
	if (n < 0) {
		error = fz_ferror(file);
		goto cleanup;
	}

	maxoid = 0;
	oid = 0;
	gid = 0;
	oidofs = 0;
	gidofs = 0;

	while (1)
	{
		tmpofs = fz_tell(file);

		tok = pdf_lex(file, buf, sizeof buf, &len);
		if (tok == PDF_TINT)
		{
			oidofs = gidofs;
			oid = gid;
			gidofs = tmpofs;
			gid = atoi(buf);
		}

		if (tok == PDF_TOBJ)
		{

			error = parseobj(file, buf, sizeof buf, &stmlen, &isroot, &isinfo);
			if (error)
				goto cleanup;

			if (isroot) {
				rootoid = oid;
				rootgid = gid;
			}

			if (isinfo) {
				infooid = oid;
				infogid = gid;
			}

			if (listlen + 1 == listcap)
			{
				struct entry *newlist;
				listcap = listcap * 2;
				newlist = fz_realloc(list, listcap * sizeof(struct entry));
				if (!newlist) {
					error = fz_outofmem;
					goto cleanup;
				}
				list = newlist;
			}

			list[listlen].oid = oid;
			list[listlen].gid = gid;
			list[listlen].ofs = oidofs;
			list[listlen].stmlen = stmlen;
			listlen ++;

			if (oid > maxoid)
				maxoid = oid;
		}

		if (tok == PDF_TEOF)
			break;
	}

	error = fz_packobj(&xref->trailer,
					"<< /Size %i /Root %r >>",
					maxoid + 1, rootoid, rootgid);
	if (error)
		goto cleanup;

	xref->version = 1.3;	/* FIXME */
	xref->size = maxoid + 1;
	xref->capacity = xref->size;
	xref->table = fz_malloc(xref->capacity * sizeof(pdf_xrefentry));
	if (!xref->table) {
		error = fz_outofmem;
		goto cleanup;
	}

	xref->table[0].type = 'f';
	xref->table[0].mark = 0;
	xref->table[0].ofs = 0;
	xref->table[0].gen = 65535;

	for (i = 1; i < xref->size; i++)
	{
		xref->table[i].type = 'f';
		xref->table[i].mark = 0;
		xref->table[i].ofs = 0;
		xref->table[i].gen = 0;
	}

	for (i = 0; i < listlen; i++)
	{
		xref->table[list[i].oid].type = 'n';
		xref->table[list[i].oid].ofs = list[i].ofs;
		xref->table[list[i].oid].gen = list[i].gid;
		xref->table[list[i].oid].mark = 0;

		/* corrected stream length */
		if (list[i].stmlen >= 0)
		{
			fz_obj *dict, *length;
			error = pdf_loadobject0(&dict, xref, list[i].oid, list[i].gid, nil);
			if (error)
				goto cleanup;
			error = fz_newint(&length, list[i].stmlen);
			if (error)
				goto cleanup;
			error = fz_dictputs(dict, "Length", length);
			if (error)
				goto cleanup;
			error = pdf_saveobject(xref, list[i].oid, list[i].gid, dict);
			if (error)
				goto cleanup;
		}
	}

	next = 0;
	for (i = xref->size - 1; i >= 0; i--)
	{
		if (xref->table[i].type == 'f')
		{
			xref->table[i].ofs = next;
			if (xref->table[i].gen < 65535)
				xref->table[i].gen ++;
			next = i;
		}
	}

	fz_free(list);
	return nil;

cleanup:
	fz_free(list);
	return error;
}

