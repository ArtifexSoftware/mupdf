#include "mupdf/fitz.h"
#include "icc34.h"

#define SAVEICCPROFILE 1
#define ICC_HEADER_SIZE 128
#define ICC_TAG_SIZE 12
#define ICC_NUMBER_COMMON_TAGS 2
#define ICC_XYZPT_SIZE 12
#define ICC_DATATYPE_SIZE 8
#define D50_X 0.9642f
#define D50_Y 1.0f
#define D50_Z 0.8249f
static const char desc_name[] = "MuPDF Internal Profile";
static const char copy_right[] = "Copyright Artifex Software 2017";
#if SAVEICCPROFILE
unsigned int icc_debug_index = 0;
#endif

typedef struct fz_icc_tag_s fz_icc_tag;

struct fz_icc_tag_s
{
	icTagSignature sig;
	icUInt32Number offset;
	icUInt32Number size;
	unsigned char byte_padding;
};

#if SAVEICCPROFILE
static void
save_profile(unsigned char *buffer, char filename[], int buffer_size)
{
	char full_file_name[50];
	FILE *fid;

	sprintf(full_file_name, "%d)Profile_%s.icc", icc_debug_index, filename);
	fid = fopen(full_file_name, "wb");
	fclose(fid);
	icc_debug_index++;
}
#endif

static void
write_bigendian_2bytes(unsigned char *curr_ptr, unsigned short input)
{
	*curr_ptr++ = (0xff & (input >> 8));
	*curr_ptr++ = (0xff & input);
}

static void
write_bigendian_4bytes(unsigned char *curr_ptr, int input)
{
	*curr_ptr++ = (0xff & (input >> 24));
	*curr_ptr++ = (0xff & (input >> 16));
	*curr_ptr++ = (0xff & (input >> 8));
	*curr_ptr++ = (0xff & input);
}

static int
get_padding(int x)
{
	return (4 - x % 4) % 4;
}

static void
setdatetime(icDateTimeNumber *datetime)
{
	datetime->day = 0;
	datetime->hours = 0;
	datetime->minutes = 0;
	datetime->month = 0;
	datetime->seconds = 0;
	datetime->year = 0;
}

static void
add_gammadata(unsigned char *input_ptr, unsigned short gamma, icTagTypeSignature curveType)
{
	unsigned char *curr_ptr;

	curr_ptr = input_ptr;
	write_bigendian_4bytes(curr_ptr, curveType);
	curr_ptr += 4;
	memset(curr_ptr, 0, 4);
	curr_ptr += 4;

	/* one entry for gamma */
	write_bigendian_4bytes(curr_ptr, 1);
	curr_ptr += 4;

	/* The encode (8frac8) gamma, with padding */
	write_bigendian_2bytes(curr_ptr, gamma);
	curr_ptr += 2;

	/* pad two bytes */
	memset(curr_ptr, 0, 2);
}

static unsigned short
float2u8Fixed8(float number_in)
{
	return (unsigned short)(number_in * 256);
}

static void
add_xyzdata(unsigned char *input_ptr, icS15Fixed16Number temp_XYZ[])
{
	int j;
	unsigned char *curr_ptr = input_ptr;

	write_bigendian_4bytes(curr_ptr, icSigXYZType);
	curr_ptr += 4;
	memset(curr_ptr, 0, 4);
	curr_ptr += 4;
	for (j = 0; j < 3; j++)
	{
		write_bigendian_4bytes(curr_ptr, temp_XYZ[j]);
		curr_ptr += 4;
	}
}

static icS15Fixed16Number
double2XYZtype(float number_in)
{
	short s;
	unsigned short m;

	if (number_in < 0)
		number_in = 0;
	s = (short)number_in;
	m = (unsigned short)((number_in - s) * 65536.0);
	return (icS15Fixed16Number) ((s << 16) | m);
}

static void
get_D50(icS15Fixed16Number XYZ[])
{
	XYZ[0] = double2XYZtype(D50_X);
	XYZ[1] = double2XYZtype(D50_Y);
	XYZ[2] = double2XYZtype(D50_Z);
}

static void
get_XYZ_doubletr(icS15Fixed16Number XYZ[], float vector[])
{
	XYZ[0] = double2XYZtype(vector[0]);
	XYZ[1] = double2XYZtype(vector[1]);
	XYZ[2] = double2XYZtype(vector[2]);
}

static void
add_desc_tag(unsigned char *buffer, const char text[], fz_icc_tag tag_list[], int curr_tag)
{
	unsigned char *curr_ptr;
	int len = strlen(text) + 1;
	int k;

	curr_ptr = buffer;
	write_bigendian_4bytes(curr_ptr, icSigTextDescriptionType);
	curr_ptr += 4;
	memset(curr_ptr, 0, 4);
	curr_ptr += 4;
	write_bigendian_4bytes(curr_ptr, len);
	curr_ptr += 4;
	for (k = 0; k < strlen(text); k++)
		*curr_ptr++ = text[k];
	memset(curr_ptr, 0, 12 + 67 + 1);
	memset(curr_ptr, 0, tag_list[curr_tag].byte_padding);
}

static void
add_text_tag(unsigned char *buffer, const char text[], fz_icc_tag tag_list[], int curr_tag)
{
	unsigned char *curr_ptr = buffer;
	int k;

	write_bigendian_4bytes(curr_ptr, icSigTextType);
	curr_ptr += 4;
	memset(curr_ptr, 0, 4);
	curr_ptr += 4;
	for (k = 0; k < strlen(text); k++)
		*curr_ptr++ = text[k];
	memset(curr_ptr, 0, 1);
	memset(curr_ptr, 0, tag_list[curr_tag].byte_padding);  /* padding */
}

static void
add_common_tag_data(unsigned char *buffer, fz_icc_tag tag_list[])
{
	unsigned char *curr_ptr = buffer;

	add_desc_tag(curr_ptr, desc_name, tag_list, 0);
	curr_ptr += tag_list[0].size;
	add_text_tag(curr_ptr, copy_right, tag_list, 1);
}

static void
init_common_tags(fz_icc_tag tag_list[], int num_tags, int *last_tag)
{
	int curr_tag, temp_size;

	if (*last_tag < 0)
		curr_tag = 0;
	else
		curr_tag = (*last_tag) + 1;

	tag_list[curr_tag].offset = ICC_HEADER_SIZE + num_tags * ICC_TAG_SIZE + 4;
	tag_list[curr_tag].sig = icSigProfileDescriptionTag;

	/* temp_size = DATATYPE_SIZE + 4 + strlen(desc_name) + 1 + 4 + 4 + 3 + 67; */
	temp_size = 2 * strlen(desc_name) + 28;

	/* +1 for NULL + 4 + 4 for unicode + 3 + 67 script code */
	tag_list[curr_tag].byte_padding = get_padding(temp_size);
	tag_list[curr_tag].size = temp_size + tag_list[curr_tag].byte_padding;
	curr_tag++;
	tag_list[curr_tag].offset = tag_list[curr_tag - 1].offset + tag_list[curr_tag - 1].size;
	tag_list[curr_tag].sig = icSigCopyrightTag;

	/* temp_size = DATATYPE_SIZE + strlen(copy_right) + 1; */
	temp_size = 2 * strlen(copy_right) + 28;
	tag_list[curr_tag].byte_padding = get_padding(temp_size);
	tag_list[curr_tag].size = temp_size + tag_list[curr_tag].byte_padding;
	*last_tag = curr_tag;
}

static void
copy_header(unsigned char *buffer, icHeader *header)
{
	unsigned char *curr_ptr;

	curr_ptr = buffer;
	write_bigendian_4bytes(curr_ptr, header->size);
	curr_ptr += 4;
	memset(curr_ptr, 0, 4);
	curr_ptr += 4;
	write_bigendian_4bytes(curr_ptr, header->version);
	curr_ptr += 4;
	write_bigendian_4bytes(curr_ptr, header->deviceClass);
	curr_ptr += 4;
	write_bigendian_4bytes(curr_ptr, header->colorSpace);
	curr_ptr += 4;
	write_bigendian_4bytes(curr_ptr, header->pcs);
	curr_ptr += 4;

	/* Date and time */
	memset(curr_ptr, 0, 12);
	curr_ptr += 12;
	write_bigendian_4bytes(curr_ptr, header->magic);
	curr_ptr += 4;
	write_bigendian_4bytes(curr_ptr, header->platform);
	curr_ptr += 4;
	memset(curr_ptr, 0, 24);
	curr_ptr += 24;
	write_bigendian_4bytes(curr_ptr, header->illuminant.X);
	curr_ptr += 4;
	write_bigendian_4bytes(curr_ptr, header->illuminant.Y);
	curr_ptr += 4;
	write_bigendian_4bytes(curr_ptr, header->illuminant.Z);
	curr_ptr += 4;
	memset(curr_ptr, 0, 48);
}

static void
setheader_common(icHeader *header)
{
	header->cmmId = 0;
	header->version = 0x04200000;
	setdatetime(&(header->date));
	header->magic = icMagicNumber;
	header->platform = icSigMacintosh;
	header->flags = 0;
	header->manufacturer = 0;
	header->model = 0;
	header->attributes[0] = 0;
	header->attributes[1] = 0;
	header->renderingIntent = 3;
	header->illuminant.X = double2XYZtype((float) 0.9642);
	header->illuminant.Y = double2XYZtype((float) 1.0);
	header->illuminant.Z = double2XYZtype((float) 0.8249);
	header->creator = 0;
	memset(header->reserved, 0, 44);
}

static void
copy_tagtable(unsigned char *buffer, fz_icc_tag *tag_list, int num_tags)
{
	int k;
	unsigned char *curr_ptr;

	curr_ptr = buffer;
	write_bigendian_4bytes(curr_ptr, num_tags);
	curr_ptr += 4;
	for (k = 0; k < num_tags; k++)
	{
		write_bigendian_4bytes(curr_ptr, tag_list[k].sig);
		curr_ptr += 4;
		write_bigendian_4bytes(curr_ptr, tag_list[k].offset);
		curr_ptr += 4;
		write_bigendian_4bytes(curr_ptr, tag_list[k].size);
		curr_ptr += 4;
	}
}

static void
init_tag(fz_icc_tag tag_list[], int *last_tag, icTagSignature tagsig, int datasize)
{
	int curr_tag = (*last_tag) + 1;

	tag_list[curr_tag].offset = tag_list[curr_tag - 1].offset + tag_list[curr_tag - 1].size;
	tag_list[curr_tag].sig = tagsig;
	tag_list[curr_tag].byte_padding = get_padding(ICC_DATATYPE_SIZE + datasize);
	tag_list[curr_tag].size = ICC_DATATYPE_SIZE + datasize + tag_list[curr_tag].byte_padding;
	*last_tag = curr_tag;
}

static void
matrixmult(float leftmatrix[], int nlrow, int nlcol, float rightmatrix[], int nrrow, int nrcol, float result[])
{
	float *curr_row;
	int k, l, j, ncols, nrows;
	float sum;

	nrows = nlrow;
	ncols = nrcol;
	if (nlcol == nrrow)
	{
		for (k = 0; k < nrows; k++)
		{
			curr_row = &(leftmatrix[k*nlcol]);
			for (l = 0; l < ncols; l++)
			{
				sum = 0.0;
				for (j = 0; j < nlcol; j++)
					sum = sum + curr_row[j] * rightmatrix[j*nrcol + l];
				result[k*ncols + l] = sum;
			}
		}
	}
}

static void
apply_adaption(float matrix[], float in[], float out[])
{
	out[0] = matrix[0] * in[0] + matrix[1] * in[1] + matrix[2] * in[2];
	out[1] = matrix[3] * in[0] + matrix[4] * in[1] + matrix[5] * in[2];
	out[2] = matrix[6] * in[0] + matrix[7] * in[1] + matrix[8] * in[2];
}

/*
	Compute the CAT02 transformation to get us from the Cal White point to the
	D50 white point
*/
static void
gsicc_create_compute_cam(float white_src[], float *cam)
{
	float cat02matrix[] = { 0.7328f, 0.4296f, -0.1624f, -0.7036f, 1.6975f, 0.0061f, 0.003f, 0.0136f, 0.9834f };
	float cat02matrixinv[] = { 1.0961f, -0.2789f, 0.1827f, 0.4544f, 0.4735f, 0.0721f, -0.0096f, -0.0057f, 1.0153f };
	float vonkries_diag[9];
	float temp_matrix[9];
	float lms_wp_src[3], lms_wp_des[3];
	int k;
	float d50[3] = { D50_X, D50_Y, D50_Z };

	matrixmult(cat02matrix, 3, 3, white_src, 3, 1, lms_wp_src);
	matrixmult(cat02matrix, 3, 3, d50, 3, 1, lms_wp_des);
	memset(&(vonkries_diag[0]), 0, sizeof(float) * 9);

	for (k = 0; k < 3; k++)
	{
		if (lms_wp_src[k] > 0)
			vonkries_diag[k * 3 + k] = lms_wp_des[k] / lms_wp_src[k];
		else
			vonkries_diag[k * 3 + k] = 1;
	}
	matrixmult(&(vonkries_diag[0]), 3, 3, cat02matrix, 3, 3, temp_matrix);
	matrixmult(&(cat02matrixinv[0]), 3, 3, temp_matrix, 3, 3, cam);
}

/* Create ICC profile from PDF calGray and calRGB definitions */
int
fz_create_icc_from_cal(fz_context *ctx, unsigned char **buff, fz_cal_color *cal)
{
	fz_icc_tag *tag_list;
	icProfile iccprofile;
	icHeader *header = &(iccprofile.header);
	unsigned char *profile;
	int profile_size, k;
	int num_tags;
	unsigned short encode_gamma;
	unsigned char *curr_ptr;
	int last_tag;
	icS15Fixed16Number temp_XYZ[3];
	int tag_location;
	icTagSignature TRC_Tags[3] = { icSigRedTRCTag, icSigGreenTRCTag, icSigBlueTRCTag };
	int trc_tag_size;
	float cat02[9];
	float black_adapt[3];
	int n = cal->n;

	/* common */
	setheader_common(header);
	header->pcs = icSigXYZData;
	profile_size = ICC_HEADER_SIZE;
	header->deviceClass = icSigInputClass;

	if (n == 3)
	{
		header->colorSpace = icSigRgbData;
		num_tags = 10; /* common (2) + rXYZ, gXYZ, bXYZ, rTRC, gTRC, bTRC, bkpt, wtpt */
	}
	else
	{
		header->colorSpace = icSigGrayData;
		num_tags = 5; /* common (2) + GrayTRC, bkpt, wtpt */
		TRC_Tags[0] = icSigGrayTRCTag;
	}

	tag_list = fz_malloc(ctx, sizeof(fz_icc_tag) * num_tags);

	/* precompute sizes and offsets */
	profile_size += ICC_TAG_SIZE * num_tags;
	profile_size += 4; /* number of tags.... */
	last_tag = -1;
	init_common_tags(tag_list, num_tags, &last_tag);
	if (n == 3)
	{
		init_tag(tag_list, &last_tag, icSigRedColorantTag, ICC_XYZPT_SIZE);
		init_tag(tag_list, &last_tag, icSigGreenColorantTag, ICC_XYZPT_SIZE);
		init_tag(tag_list, &last_tag, icSigBlueColorantTag, ICC_XYZPT_SIZE);
	}
	init_tag(tag_list, &last_tag, icSigMediaWhitePointTag, ICC_XYZPT_SIZE);
	init_tag(tag_list, &last_tag, icSigMediaBlackPointTag, ICC_XYZPT_SIZE);

	/* 4 for count, 2 for gamma, Extra 2 bytes for 4 byte alignment requirement */
	trc_tag_size = 8;
	for (k = 0; k < n; k++)
		init_tag(tag_list, &last_tag, TRC_Tags[k], trc_tag_size);
	for (k = 0; k < num_tags; k++)
		profile_size += tag_list[k].size;

	/* Allocate buffer */
	fz_var(tag_list);
	fz_try(ctx)
	{
		profile = fz_malloc(ctx, profile_size);
	}
	fz_catch(ctx)
	{
		fz_free(ctx, tag_list);
	}
	curr_ptr = profile;

	/* Header */
	header->size = profile_size;
	copy_header(curr_ptr, header);
	curr_ptr += ICC_HEADER_SIZE;

	/* Tag table */
	copy_tagtable(curr_ptr, tag_list, num_tags);
	curr_ptr += ICC_TAG_SIZE * num_tags;
	curr_ptr += 4;

	/* Common tags */
	add_common_tag_data(curr_ptr, tag_list);
	for (k = 0; k < ICC_NUMBER_COMMON_TAGS; k++)
		curr_ptr += tag_list[k].size;
	tag_location = ICC_NUMBER_COMMON_TAGS;

	/* Get the cat02 matrix */
	gsicc_create_compute_cam(cal->wp, cat02);

	/* The matrix */
	if (n == 3)
	{
		float primary[3];

		for (k = 0; k < 3; k++)
		{
			/* Apply the cat02 matrix to the primaries */
			apply_adaption(cat02, &(cal->matrix[k * 3]), &(primary[0]));
			get_XYZ_doubletr(temp_XYZ, &(primary[0]));
			add_xyzdata(curr_ptr, temp_XYZ);
			curr_ptr += tag_list[tag_location].size;
			tag_location++;
		}
	}

	/* White and black points. WP is D50 */
	get_D50(temp_XYZ);
	add_xyzdata(curr_ptr, temp_XYZ);
	curr_ptr += tag_list[tag_location].size;
	tag_location++;

	/* Black point. Apply cat02*/
	apply_adaption(cat02, cal->bp, &(black_adapt[0]));
	get_XYZ_doubletr(temp_XYZ, &(black_adapt[0]));
	add_xyzdata(curr_ptr, temp_XYZ);
	curr_ptr += tag_list[tag_location].size;
	tag_location++;

	/* Gamma */
	for (k = 0; k < n; k++)
	{
		encode_gamma = float2u8Fixed8(cal->gamma[k]);
		add_gammadata(curr_ptr, encode_gamma, icSigCurveType);
		curr_ptr += tag_list[tag_location].size;
		tag_location++;
	}

	fz_free(ctx, tag_list);
	*buff = profile;

#if SAVEICCPROFILE
	if (n == 3)
		save_profile(profile, "calRGB", profile_size);
	else
		save_profile(profile, "calGray", profile_size);
#endif
	return profile_size;
}
