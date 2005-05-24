/*
 * Metro physical packages and parts, mapped to a zip archive.
 */

#include "fitz.h"
#include "samus.h"

struct sa_package_s
{
	sa_zip *zip;
	fz_obj *defaults;
	fz_obj *overrides;
};

static fz_error *
readcontenttypes(sa_package *pack)
{
	fz_error *error;
	sa_xmlparser *parser;
	sa_xmlitem *item;
	fz_obj *val;

	error = fz_newdict(&pack->defaults, 8);
	if (error)
		return error;

	error = fz_newdict(&pack->overrides, 8);
	if (error)
		return error;

	error = sa_openzipentry(pack->zip, "[Content_Types].xml");
	if (error)
		return error;

	error = sa_openxml(&parser, pack->zip->file, 0);
	if (error)
		goto cleanupzip;

	item = sa_xmlnext(parser);
	if (item && !strcmp(sa_xmlname(item), "Types"))
	{
		sa_xmldown(parser);
		item = sa_xmlnext(parser);
		while (item)
		{
			if (!strcmp(sa_xmlname(item), "Default"))
			{
				char *ext = sa_xmlatt(item, "Extension");
				char *type = sa_xmlatt(item, "ContentType");
				if (ext && type)
				{
					if (strstr(type, ';'))
						strstr(type, ';')[0] = 0;
					error = fz_newname(&val, type);
					if (error)
						goto cleanupxml;
					error = fz_dictputs(pack->defaults, ext, val);
					if (error)
						goto cleanupval;
					val = nil;
				}
			}

			if (!strcmp(sa_xmlname(item), "Override"))
			{
				char *name = sa_xmlatt(item, "PartName");
				char *type = sa_xmlatt(item, "ContentType");
				if (name && type)
				{
					if (strstr(type, ';'))
						strstr(type, ';')[0] = 0;
					error = fz_newname(&val, type);
					if (error)
						goto cleanupxml;
					error = fz_dictputs(pack->overrides, name, val);
					if (error)
						goto cleanupval;
					val = nil;
				}
			}

			item = sa_xmlnext(parser);
		}
		sa_xmlup(parser);
	}

	sa_closexml(parser);
	sa_closezipentry(pack->zip);
	return nil;

cleanupval:
	fz_dropobj(val);
cleanupxml:
	sa_closexml(parser);
cleanupzip:
	sa_closezipentry(pack->zip);
	return error;
}

fz_error *
sa_openpackage(sa_package **packp, char *filename)
{
	fz_error *error;
	sa_package *pack;

	pack = fz_malloc(sizeof(sa_package));
	if (!pack)
		return fz_outofmem;

	pack->zip = nil;
	pack->defaults = nil;
	pack->overrides = nil;

	error = sa_openzip(&pack->zip, filename);
	if (error)
	{
		sa_closepackage(pack);
		return error;
	}

	error = readcontenttypes(pack->zip);
	if (error)
	{
		sa_closepackage(pack);
		return error;
	}

	*packp = pack;
	return nil;
}

void
sa_closepackage(sa_package *pack)
{
	if (pack->zip) sa_closezip(pack->zip);
	if (pack->defaults) fz_dropobj(pack->defaults);
	if (pack->overrides) fz_dropobj(pack->overrides);
	fz_free(pack);
}

/*
 * Check access of a part, return either nil or its mime-type.
 */
char *
sa_accesspart(sa_package *pack, char *partname)
{
	fz_obj *type;
	char *ext;

	if (sa_accesszipentry(pack->zip, partname))
	{
		type = fz_dictgets(pack->overrides, partname);
		if (type)
			return fz_toname(type);

		ext = strrstr(partname, ".");
		if (ext)
		{
			type = fz_dictgets(pack->defaults, ext + 1);
			if (type)
				return fz_toname(type);
		}
	}

	return nil;
}

/*
 * Open a part for reading. It is NOT safe to open more than one
 * part at a time.
 */
fz_error *
sa_openpart(fz_file **filep, sa_package *pack, char *partname)
{
	*filep = pack->zip->file;
	return sa_openzipentry(pack->zip, partname);
}

/*
 * Call this instead of fz_closefile()
 * FIXME i gotto do something about this icky file API
 */
void sa_closepart(sa_package *pack, fz_file *file)
{
	sa_closezipentry(pack->zip);
}

