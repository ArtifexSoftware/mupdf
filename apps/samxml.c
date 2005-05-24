#include "fitz.h"
#include "samus.h"

int main(int argc, char **argv)
{
	fz_error *error;
	fz_file *file;
	sa_xmlparser *parser;
	sa_xmlitem *item;

	error = fz_openfile(&file, argv[1], FZ_READ);
	if (error)
		fz_abort(error);

	error = sa_openxml(&parser, file, 0);
	if (error)
		fz_abort(error);

	item = sa_xmlnext(parser);
	if (item)
		sa_debugxml(item, 0);

	sa_closexml(parser);
	fz_closefile(file);

	return 0;
}

