#include "fitz.h"
#include "samus.h"

extern fz_error *sa_readtiff(fz_file *);

int main(int argc, char **argv)
{
	fz_error *error;
	fz_file *file;

	error = fz_openfile(&file, argv[1], FZ_READ);
	if (error)
		fz_abort(error);

	error = sa_readtiff(file);
	if (error)
		fz_abort(error);
	
	fz_closefile(file);

	return 0;
}

