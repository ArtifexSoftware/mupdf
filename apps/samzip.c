#include "fitz.h"
#include "samus.h"

int main(int argc, char **argv)
{
	fz_error *error;
	fz_buffer *buf;
	sa_zip *zip;
	int i;

	error = sa_openzip(&zip, argv[1]);
	if (error)
		fz_abort(error);

	if (argc == 2)
		sa_debugzip(zip);

	for (i = 2; i < argc; i++)
	{
		error = sa_openzipstream(zip, argv[i]);
		if (error)
			fz_abort(error);
		error = fz_readfile(&buf, zip->file);
		if (error)
			fz_abort(error);
		sa_closezipstream(zip);

		fwrite(buf->rp, 1, buf->wp - buf->rp, stdout);

		fz_dropbuffer(buf);
	}

	sa_closezip(zip);
	
	return 0;
}

