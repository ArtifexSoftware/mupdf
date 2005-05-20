/*
 * ZIP archive
 */

typedef struct sa_zip_s sa_zip;
typedef struct sa_zipent_s sa_zipent;

struct sa_zipent_s
{
	unsigned offset;
	unsigned csize;
	unsigned usize;
	char *name;
};

struct sa_zip_s
{
	fz_file *file;
	int len;
	sa_zipent *table;
};

fz_error *sa_openzip(sa_zip **zipp, char *filename);
void sa_debugzip(sa_zip *zip);
void sa_closezip(sa_zip *zip);
fz_error *sa_openzipstream(sa_zip *zip, char *name);
void sa_closezipstream(sa_zip *zip);

