typedef struct pdf_function_s pdf_function;
typedef struct psobj_s psobj;

struct pdf_function_s
{
	unsigned short type;	/* 0=sample 2=exponential 3=stitching 4=postscript */
	int m;					/* number of input values */
	int n;					/* number of output values */
	float *domain;			/* even index : min value, odd index : max value */
	float *range;			/* even index : min value, odd index : max value */
	union
	{
		struct {
			unsigned short bps;
			unsigned short order;
			int *size;		/* the num of samples in each input dimension */
			float *encode;
			float *decode;
			int *samples;
		} sa;
		struct {
			float n;
			float *c0;
			float *c1;
		} e;
		struct {
			int k;
			pdf_function **funcs;
			float *bounds;
			float *encode;
		} st;
		struct {
			psobj *code;
			int cap;
		} p;
	}u;
};

struct psobj_s
{
	unsigned short type;
	union {
		int booln;			// boolean (stack only)
		int intg;			// integer (stack and code)
		float real;			// real (stack and code)
		int op;			// operator (code only)
		int blk;			// if/ifelse block pointer (code only)
	};
};

fz_error *pdf_loadfunction(pdf_function **func, pdf_xref *xref, fz_obj *obj);
fz_error *pdf_execfunction(pdf_function *func, float *in, int inlen, float *out, int outlen);
void pdf_freefunc(pdf_function *func);