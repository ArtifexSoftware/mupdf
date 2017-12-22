#ifndef MUPDF_PKCS7_CHECK_H
#define MUPDF_PKCS7_CHECK_H

/*
	pdf_check_signature: check a signature's certificate chain and digest

	This is a helper function defined to provide compatibility with older
	versions of mupdf
*/
int pdf_check_signature(fz_context *ctx, pdf_document *doc, pdf_widget *widget, char *ebuf, int ebufsize);

#endif
