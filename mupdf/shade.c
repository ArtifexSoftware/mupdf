#include <fitz.h>
#include <mupdf.h>

fz_error *
pdf_loadshade(fz_shade **shadep, pdf_xref *xref, fz_obj *obj, fz_obj *ref)
{
	fz_error *error;
	fz_shade *shade;

	shade = fz_malloc(sizeof(fz_shade));
	if (!shade)
		return fz_outofmem;

printf("loading shade pattern\n");

	// ...

	*shadep = shade;
	return nil;

cleanup:
	return error;
}

