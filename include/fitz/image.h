enum
{
	FZ_CSGRAY,
	FZ_CSRGB,
	FZ_CSCMYK
};

struct fz_image_s
{
	fz_node super;
	int w, h, n, bpc;
	int cs;
	unsigned char *data;
};

fz_error *fz_newimage(fz_node **nodep, int w, int h, int n, int bpc, int cs);

