#include "pdftool.h"

char *basename = nil;
pdf_xref *xref = nil;
int pagecount = 0;
static void (*cleanup)(void) = nil;

void closexref(void);

void die(fz_error error)
{
	fz_catch(error, "aborting");
	if (cleanup)
		cleanup();
	closexref();
	exit(1);
}

void setcleanup(void (*func)(void))
{
	cleanup = func;
}

void openxref(char *filename, char *password, int dieonbadpass)
{
	int okay;

	basename = strrchr(filename, '/');
	if (!basename)
		basename = filename;
	else
		basename++;

	xref = pdf_openxref(filename);
	if (!xref)
		die(-1);

	if (pdf_needspassword(xref))
	{
		okay = pdf_authenticatepassword(xref, password);
		if (!okay && !dieonbadpass)
			fz_warn("invalid password, attempting to continue.");
		else if (!okay && dieonbadpass)
			die(fz_throw("invalid password"));
	}

	pagecount = pdf_getpagecount(xref);
}

void flushxref(void)
{
	if (xref)
	{
		pdf_flushxref(xref, 0);
	}
}

void closexref(void)
{
	if (cleanup)
		cleanup();

	if (xref)
	{
		pdf_closexref(xref);
		xref = nil;
	}

	basename = nil;
}

