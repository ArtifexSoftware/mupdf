#include <fitz.h>
#include <mupdf.h>

int main(int argc, char **argv)
{
	fz_error *err;
	fz_cmap *cmap;
	fz_file *file;

	err = fz_openfile(&file, argv[1], FZ_READ);
	if (err)
		fz_abort(err);

	err = pdf_parsecmap(&cmap, file);
	if (err)
		fz_abort(err);

	fz_debugcmap(cmap);

	return 0;
}

