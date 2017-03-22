#ifndef MUPDF_FITZ_COLORSPACE_IMP_H
#define MUPDF_FITZ_COLORSPACE_IMP_H

struct fz_colorspace_s
{
	fz_storable storable;
	size_t size;
	char name[16];
	int n;
	int is_subtractive;
	fz_colorspace_convert_fn *to_rgb;
	fz_colorspace_convert_fn *from_rgb;
	fz_colorspace_destruct_fn *free_data;
	void *data;
};

struct fz_iccprofile_s
{
	int num_devcomp;
	fz_buffer *buffer;
	unsigned char *res_buffer;
	size_t res_size;
	void *cmm_handle;
};

struct fz_icclink_s
{
	int num_in;
	int num_out;
	void *cmm_handle;
	int is_identity;
};

struct fz_rendering_param_s
{
	int rendering_intent;
	int black_point;
};

#endif
