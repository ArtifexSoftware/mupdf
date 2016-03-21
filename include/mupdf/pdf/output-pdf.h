#ifndef MUPDF_PDF_OUTPUT_PDF_H
#define MUPDF_PDF_OUTPUT_PDF_H

/*
	pdf_new_pdf_device: Create a pdf device. Rendering to the device creates
	new pdf content. WARNING: this device is work in progress. It doesn't
	currently support all rendering cases.

	Note that contents must be a stream (dictionary) to be updated (or
	a reference to a stream). Callers should take care to ensure that it
	is not an array, and that is it not shared with other objects/pages.
*/
fz_device *pdf_new_pdf_device(fz_context *ctx, pdf_document *doc,
	const fz_matrix *topctm, const fz_rect *mediabox, fz_buffer *buf, pdf_obj *resources);

void pdf_localise_page_resources(fz_context *ctx, pdf_document *doc);

#endif
