#include "fitz.h"
#include "samus.h"

int main(int argc, char **argv)
{
	fz_error *error;
	fz_file *file;
	sa_xmlnode *xml;

	error = fz_openfile(&file, argv[1], FZ_READ);
	if (error)
		fz_abort(error);

	error = sa_parsexml(&xml, file, 0);
	if (error)
		fz_abort(error);
	
	fz_closefile(file);
	
	sa_debugxml(xml, 0);

	sa_dropxml(xml);

	return 0;
}

