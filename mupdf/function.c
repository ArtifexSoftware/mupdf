#include <fitz.h>
#include <mupdf.h>

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
		int booln;			/* boolean (stack only) */
		int intg;			/* integer (stack and code) */
		float real;			/* real (stack and code) */
		int op;				/* operator (code only) */
		int blk;			/* if/ifelse block pointer (code only) */
	};
};

#define ARRAY_SIZE(a) sizeof(a) / sizeof(a[0])

#define MIN_MAX(a,min,max) \
	if(a < (min)) a = (min);\
else if(a > (max)) a = (max);

#define INTERPOLATE(x,xmin,xmax,ymin,ymax) \
(ymin) + ((x)-(xmin)) * ((ymax)-(ymin)) / ((xmax) - (xmin));

#define SAFE_PUSHINT(st,a)\
	{err = pushint(st,a);\
	if(err) goto cleanup;}

#define SAFE_PUSHREAL(st,a)\
	{err = pushreal(st,a);\
	if(err) goto cleanup;}

#define SAFE_PUSHBOOL(st,a)\
	{err = pushbool(st,a);\
	if(err) goto cleanup;}

#define SAFE_POPINT(st,a)\
	{err = popint(st,a);\
	if(err) goto cleanup;}

#define SAFE_POPNUM(st,a)\
	{err = popnum(st,a);\
	if(err) goto cleanup;}

#define SAFE_POPBOOL(st,a)\
	{err = popbool(st,a);\
	if(err) goto cleanup;}

#define SAFE_POP(st)\
	{err = pop(st);\
	if(err) goto cleanup;}

#define SAFE_INDEX(st,i)\
	{err = index(st,i);\
	if(err) goto cleanup;}

#define SAFE_COPY(st,n)\
	{err = copy(st,n);\
	if(err) goto cleanup;}

#define RADIAN 57.2957795

enum pdf_funckind_e
{
	PDF_FUNC_SAMPLE = 0,
	PDF_FUNC_EXPONENTIAL = 2,
	PDF_FUNC_STITCHING = 3,
	PDF_FUNC_POSTSCRIPT = 4
};

enum psop_e {
	psOpAbs,
	psOpAdd,
	psOpAnd,
	psOpAtan,
	psOpBitshift,
	psOpCeiling,
	psOpCopy,
	psOpCos,
	psOpCvi,
	psOpCvr,
	psOpDiv,
	psOpDup,
	psOpEq,
	psOpExch,
	psOpExp,
	psOpFalse,
	psOpFloor,
	psOpGe,
	psOpGt,
	psOpIdiv,
	psOpIndex,
	psOpLe,
	psOpLn,
	psOpLog,
	psOpLt,
	psOpMod,
	psOpMul,
	psOpNe,
	psOpNeg,
	psOpNot,
	psOpOr,
	psOpPop,
	psOpRoll,
	psOpRound,
	psOpSin,
	psOpSqrt,
	psOpSub,
	psOpTrue,
	psOpTruncate,
	psOpXor,
	psOpIf,
	psOpIfelse,
	psOpReturn
};

// Note: 'if' and 'ifelse' are parsed separately.
// The rest are listed here in alphabetical order.
// The index in this table is equivalent to the entry in PSOp.
char *psOpNames[] = {
	"abs",
	"add",
	"and",
	"atan",
	"bitshift",
	"ceiling",
	"copy",
	"cos",
	"cvi",
	"cvr",
	"div",
	"dup",
	"eq",
	"exch",
	"exp",
	"false",
	"floor",
	"ge",
	"gt",
	"idiv",
	"index",
	"le",
	"ln",
	"log",
	"lt",
	"mod",
	"mul",
	"ne",
	"neg",
	"not",
	"or",
	"pop",
	"roll",
	"round",
	"sin",
	"sqrt",
	"sub",
	"true",
	"truncate",
	"xor"
};

enum psobjtype_e {
	psBool,
	psInt,
	psReal,
	psOperator,
	psBlock
};

static int bps_supported[] = { 1,2,4,8,12,16,24,32 };

/************************************************************************/
/* Start Stack Impl                                                     */
/************************************************************************/
#define PSSTACKSIZE 100
#define fz_stackoverflow fz_throw("syntaxerror : stackoverflow")
#define fz_stackunderflow fz_throw("syntaxerror : stackunderflow")
#define fz_stacktypemismatch fz_throw("syntaxerror : type mismatching")

typedef struct psstack_s psstack;

struct psstack_s
{
	psobj stack[PSSTACKSIZE];
	int sp;
};

static void
initstack(psstack *st)
{
	memset(st->stack,0,sizeof(st->stack));
	st->sp = PSSTACKSIZE;
}

static int 
checkoverflow(psstack *st, int n)
{
	return st->sp >= n;
}

static int 
checkunderflow(psstack *st)
{
	return st->sp != PSSTACKSIZE;
}

static int 
checktype(psstack *st, unsigned short t1, unsigned short t2)
{
	return (st->stack[st->sp].type == t1 ||
		st->stack[st->sp].type == t2);
}

static fz_error * 
pushbool(psstack *st, int booln)
{
	if (checkoverflow(st, 1)) {
		st->stack[--st->sp].type = psBool;
		st->stack[st->sp].booln = booln;
	}
	else
		return fz_stackoverflow;

	return nil;
}

static fz_error * 
pushint(psstack *st, int intg)
{
	if (checkoverflow(st, 1)) {
		st->stack[--st->sp].type = psInt;
		st->stack[st->sp].intg = intg;
	}
	else
		return fz_stackoverflow;

	return nil;
}

static fz_error * 
pushreal(psstack *st, float real)
{
	if (checkoverflow(st, 1)) {
		st->stack[--st->sp].type = psReal;
		st->stack[st->sp].real = real;
	}
	else
		return fz_stackoverflow;

	return nil;
}

static fz_error *
popbool(psstack *st, int *booln)
{
	if (checkunderflow(st) && checktype(st, psBool, psBool)) {
		*booln = st->stack[st->sp++].booln;
	}
	else if(checkunderflow(st))
		return fz_stackunderflow;
	else
		return fz_stacktypemismatch;

	return nil;
}

static fz_error *
popint(psstack *st, int *intg)
{
	if (checkunderflow(st) && checktype(st, psInt, psInt)) {
		*intg = st->stack[st->sp++].intg;
	}
	else if(checkunderflow(st))
		return fz_stackunderflow;
	else
		return fz_stacktypemismatch;

	return nil;
}

static fz_error *
popnum(psstack *st, float *real)
{
	if (checkunderflow(st) && checktype(st, psInt, psReal)) {
		float ret;
		ret = (st->stack[st->sp].type == psInt) ? 
			(float)st->stack[st->sp].intg : st->stack[st->sp].real;
		++st->sp;
		*real = ret;
	}
	else if(checkunderflow(st))
		return fz_stackunderflow;
	else
		return fz_stacktypemismatch;

	return nil;
}

static int 
topisint(psstack *st)
{
	return st->sp < PSSTACKSIZE && st->stack[st->sp].type == psInt;
}

static int 
toptwoareints(psstack *st)
{
	return st->sp < PSSTACKSIZE - 1 &&
		st->stack[st->sp].type == psInt &&
		st->stack[st->sp+1].type == psInt;
}

static int 
topisreal(psstack *st)
{
	return st->sp < PSSTACKSIZE && st->stack[st->sp].type == psReal;
}

static int 
toptwoarenums(psstack *st)
{
	return st->sp < PSSTACKSIZE - 1 &&
		(st->stack[st->sp].type == psInt || st->stack[st->sp].type == psReal) &&
		(st->stack[st->sp+1].type == psInt || st->stack[st->sp+1].type == psReal);
}

static fz_error *
copy(psstack *st, int n)
{
	int i;
	
	if (!checkoverflow(st,n))
		return fz_stackoverflow;

	for (i = st->sp + n - 1; i <= st->sp; ++i) {
		st->stack[i - n] = st->stack[i];
	}
	st->sp -= n;

	return nil;
}

static void 
roll(psstack *st, int n, int j)
{
	psobj obj;
	int i, k;
	
	if (j >= 0) {
		j %= n;
	} else {
		j = -j % n;
		if (j != 0) {
			j = n - j;
		}
	}
	if (n <= 0 || j == 0) {
		return;
	}
	for (i = 0; i < j; ++i) {
		obj = st->stack[st->sp];
		for (k = st->sp; k < st->sp + n - 1; ++k) {
			st->stack[k] = st->stack[k+1];
		}
		st->stack[st->sp + n - 1] = obj;
	}
}

static fz_error *
index(psstack *st, int i)
{
	if (!checkoverflow(st, 1)) {
		return fz_stackoverflow;
	}
	--st->sp;
	st->stack[st->sp] = st->stack[st->sp + 1 + i];
	return nil;
}

static fz_error *
pop(psstack *st)
{
	if (!checkoverflow(st, 1)) {
		return fz_stackoverflow;
	}
	++st->sp;
	return nil;
}

/************************************************************************/
/* End Stack Impl                                                       */
/************************************************************************/

static fz_error *
loadsamplefunc(pdf_function *func, pdf_xref *xref, fz_obj *dict, int oid, int gid)
{
	fz_error *err = nil;
	fz_obj *tmpobj;
	int i;
	int bps;
	int samplecount, bytetoread;
	int *size;
	unsigned char *streamsamples = nil;
	int *samples = nil;
	float *encode;
	float *decode;
	
	/* required */
	tmpobj = fz_dictgets(dict,"Size");
	if(!fz_isarray(tmpobj) || fz_arraylen(tmpobj) != func->m)
		goto cleanup;
	
	size = fz_malloc(func->m * sizeof(int));
	if(!size) return fz_outofmem;
	
	for(i = 0; i < func->m; ++i)
		size[i] = fz_toint(fz_arrayget(tmpobj,i));
	func->u.sa.size = size;
	
	/* required */
	tmpobj = fz_dictgets(dict,"BitsPerSample");
	if(!fz_isint(tmpobj))
		goto cleanup;
	func->u.sa.bps = bps = fz_toint(tmpobj);
	
	for(i = 0; i < ARRAY_SIZE(bps_supported); ++i)
		if(bps == bps_supported[i]) break;
	if(i == ARRAY_SIZE(bps_supported))
		goto cleanup;
		
	/* optional */
	tmpobj = fz_dictgets(dict, "Order");
	if(!fz_isint(tmpobj))
		func->u.sa.order = 1;		/* default : linear interpolation */
	else
		func->u.sa.order = fz_toint(tmpobj);
	if(func->u.sa.order != 1 && func->u.sa.order != 3)
		goto cleanup;

	if(func->u.sa.order == 3) {
		for(i = 0; i < func->m; ++i)
			if(size[i] < 4) {
				func->u.sa.order = 1;
				break;
			}
	}
		
	/* optional */
	tmpobj = fz_dictgets(dict, "Encode");
	func->u.sa.encode = encode = fz_malloc(func->m*2 * sizeof(float));
	if(!encode) return fz_outofmem;
	if(fz_isarray(tmpobj)) {
		if(fz_arraylen(tmpobj) != func->m*2)
			goto cleanup;
		
		for(i = 0; i < func->m; ++i) {
			encode[i*2] = fz_toreal(fz_arrayget(tmpobj, i*2));
			encode[i*2+1] = fz_toreal(fz_arrayget(tmpobj, i*2+1));
		}
	}
	else {
		for(i = 0; i < func->m; ++i) {
			encode[i*2] = 0;
			encode[i*2+1] = size[i] - 1;
		}
	}
	
	/* optional */
	tmpobj = fz_dictgets(dict, "Decode");
	func->u.sa.decode = decode = fz_malloc(func->n*2 * sizeof(float));
	if(!decode) return fz_outofmem;
	if(fz_isarray(tmpobj)) {
		if(fz_arraylen(tmpobj) != func->n*2)
			goto cleanup;
		
		for(i = 0; i < func->n; ++i) {
			decode[i*2] = fz_toreal(fz_arrayget(tmpobj, i*2));
			decode[i*2+1] = fz_toreal(fz_arrayget(tmpobj, i*2+1));
		}
	}
	else {
		for(i = 0; i < func->n; ++i) {
			decode[i*2] = func->range[i*2];
			encode[i*2+1] = func->range[i*2+1];
		}
	}
	
	/* read samples from stream */
	err = pdf_openstream(xref, oid, gid);
	if (err) goto cleanup;
	
	for(i = 0, samplecount = 1; i < func->m; ++i)
		samplecount *= size[i];
	
	bytetoread = (samplecount*bps + 7)/8;
	streamsamples = fz_malloc(bytetoread);
	samples = fz_malloc(samplecount * sizeof(int));
	func->u.sa.samples = samples;
	if(!streamsamples || !samples) { err = fz_outofmem; goto cleanup2; }
	
	/* read samples */
	{
		int pos;
		unsigned int bitMask = (1 << bps) - 1;
		unsigned int buf = 0;
		int bits = 0;
		int s;
		
		int readbyte =
			fz_read(xref->stream, streamsamples, bytetoread);
		
		if(readbyte != bytetoread)
		{
			err = fz_throw("syntaxerror : ");
			goto cleanup2;
		}
		
		for (i = 0, pos = 0; i < samplecount; ++i) {
			if (bps == 8) {
				s = streamsamples[pos++];
			} else if (samplecount == 16) {
				s = streamsamples[pos++];
				s = (s << 8) + streamsamples[pos++];
			} else if (samplecount == 32) {
				s = streamsamples[pos++];
				s = (s << 8) + streamsamples[pos++];
				s = (s << 8) + streamsamples[pos++];
				s = (s << 8) + streamsamples[pos++];
			} else {
				while (bits < bps) {
					buf = (buf << 8) | (streamsamples[pos++] & 0xff);
					bits += 8;
				}
				s = (buf >> (bits - bps)) & bitMask;
				bits -= bps;
			}
			samples[i] = s;
		}
	}
		
cleanup2:
	if(streamsamples)
		fz_free(streamsamples);
	
	pdf_closestream(xref);
	return err;
		
cleanup:
	if(err)	return err;
	return fz_throw("syntaxerror : ");
}

static fz_error *
evalsamplefunc(pdf_function *func, float *in, float *out)
{
	int i , j, k, idx;
	int e[2][func->m];
	float efrac[func->m];
	float s0[1 << func->m], s1[1 << func->m];
	float x;
	float *domain = func->domain;
	float *encode = func->u.sa.encode;
	float *range = func->range;
	float *decode = func->u.sa.decode;
	int *size = func->u.sa.size;
	
	if(func->type != PDF_FUNC_SAMPLE)
		goto cleanup;
	
	switch(func->u.sa.order) {
	case 3:
		//cubic spline interpolation
	case 1:
		for (i = 0; i < func->m; ++i) {
			x = in[i];
			MIN_MAX(x,domain[i*2],domain[i*2+1]);
			
			if(domain[i*2+1] != domain[i*2])
				x = ((x - domain[i*2]) / (domain[i*2+1] - domain[i*2])) *
				(encode[i*2+1] - encode[i*2]) + encode[i*2];
			
			MIN_MAX(x,0,size[i] - 1);
			
			e[0][i] = (int)floor(x);
			e[1][i] = (int)ceil(x);
			efrac[i] = x - e[0][i];
		}

		// for each output, do m-linear interpolation
		for (i = 0; i < func->n; ++i) {		
			// pull 2^m values out of the sample array
			for (j = 0; j < (1 << func->m); ++j) {
				idx = 0;
				for (k = func->m - 1; k >= 0; --k) {
					idx = idx * func->u.sa.size[k] + e[(j >> k) & 1][k];
				}
				idx = idx * func->n + i;
				s0[j] = func->u.sa.samples[idx];
			}
			
			// do m sets of interpolations
			for (j = 0; j < func->m; ++j) {
				for (k = 0; k < (1 << (func->m - j)); k += 2) {
					s1[k >> 1] = (1 - efrac[j]) * s0[k] + efrac[j] * s0[k+1];
				}
				memcpy(s0, s1, (1 << (func->m - j - 1)) * sizeof(float));
			}
			
			// map output value to range
			out[i] = s0[0] * (decode[i*2+1] - decode[i*2]) + decode[i*2];
			MIN_MAX(out[i],range[i*2],range[i*2+1]);
		}
		break;
	}
	return nil;
	
cleanup:
	return fz_throw("syntaxerror : ");
}

static fz_error *
loadexponentialfunc(pdf_function *func, fz_obj *dict)
{
	fz_error *err = nil;
	fz_obj *tmpobj;
	int i;
	float *c0, *c1;
	
	/* single input */
	if(func->m != 1)
		goto cleanup;
	
	/* required */
	tmpobj = fz_dictgets(dict,"N");
	if(!fz_isint(tmpobj) && !fz_isreal(tmpobj))
		goto cleanup;
	func->u.e.n = fz_toreal(tmpobj);
	
	/* optional */
	tmpobj = fz_dictgets(dict,"C0");
	if(fz_isarray(tmpobj)) {
		if(func->range && fz_arraylen(tmpobj) != func->n)
			goto cleanup;

		func->n = fz_arraylen(tmpobj);
		func->u.e.c0 = c0 = fz_malloc(func->n * sizeof(float));
		if(!c0) { err = fz_outofmem; goto cleanup; }

		fz_obj *objnum;
		for(i = 0; i < func->n; ++i) {
			objnum = fz_arrayget(tmpobj,i);
			if(!fz_isint(objnum) && !fz_isreal(objnum))
				goto cleanup;
			
			c0[i] = fz_toreal(objnum);
		}
	}
	else {
		if(func->range && func->n != 1)
			goto cleanup;

		func->n = 1;
		func->u.e.c0 = c0 = fz_malloc(func->n * sizeof(float));
		if(!c0) { err = fz_outofmem; goto cleanup; }
		
		c0[0] = 0;
	}
	
	/* optional */
	tmpobj = fz_dictgets(dict,"C1");
	func->u.e.c1 = c1 = fz_malloc(func->n * sizeof(float));
	if(!c1) { err = fz_outofmem; goto cleanup; }
	if(fz_isarray(tmpobj)) {
		fz_obj *objnum;

		if(fz_arraylen(tmpobj) != func->n)
			goto cleanup;

		for(i = 0; i < func->n; ++i) {
			objnum = fz_arrayget(tmpobj,i);
			if(!fz_isint(objnum) && !fz_isreal(objnum))
				goto cleanup;
			
			c1[i] = fz_toreal(objnum);
		}
	}
	else {
		if(func->n != 1)
			goto cleanup;
		
		c1[0] = 1;
	}
	
	return nil;
cleanup:
	if(err) return err;
	return fz_throw("syntaxerror : ");
}

static fz_error *
evalexponentialfunc(pdf_function *func, float in, float *out)
{
	fz_error *err = nil;
	float x = in;
	float tmp;
	int i;
	
	if(func->type != PDF_FUNC_EXPONENTIAL)
		goto cleanup;
	
	MIN_MAX(x,func->domain[0],func->domain[1]);
	
	/* constraint */
	if(func->u.e.n != (int)func->u.e.n && x < 0)
		goto cleanup;
	
	if(func->u.e.n < 0 && x == 0)
		goto cleanup;
	
	tmp = pow(x, func->u.e.n);
	for (i = 0; i < func->n; ++i) {
		out[i] = func->u.e.c0[i] + 
			tmp * (func->u.e.c1[i] - func->u.e.c0[i]);
		if (func->range) {
			MIN_MAX(out[i],func->range[i*2],func->range[i*2+1]);
		}
	}
	
	return nil;
cleanup:
	if(err) return err;
	return fz_throw("syntaxerror : ");
}

static fz_error *
loadstitchingfunc(pdf_function *func, pdf_xref *xref, fz_obj *dict)
{
	fz_error *err = nil;
	fz_obj *tmpobj;
	fz_obj *funcobj;
	fz_obj *numobj;
	pdf_function **funcs;
	float *bounds, *encode;
	int i;
	int k;
	
	if(func->m != 1)
		goto cleanup;
	
	/* required */
	tmpobj = fz_dictgets(dict,"Functions");
	if(!fz_isarray(tmpobj))
		goto cleanup;
	k = fz_arraylen(tmpobj);
	
	func->u.st.funcs = funcs = fz_malloc(k*sizeof(pdf_function*));
	if(!funcs) { err = fz_outofmem;	goto cleanup; }
	memset(funcs, 0, k * sizeof(pdf_function*));
	
	for(i = 0; i < k; ++i) {
		funcobj = fz_arrayget(tmpobj,i);
		err = pdf_loadfunction(funcs+i,xref,funcobj);
		if(err) goto cleanup;
		if(funcs[i]->m != 1 || funcs[i]->n != funcs[0]->n)
			goto cleanup;
	}

	if(!func->range)
		func->n = funcs[0]->n;
	else if(func->n != funcs[0]->n)
		goto cleanup;
	
	/* required */
	tmpobj = fz_dictgets(dict,"Bounds");
	if(!fz_isarray(tmpobj) || fz_arraylen(tmpobj) != k-1)
		goto cleanup;
	
	func->u.st.bounds = bounds = fz_malloc((k-1) * sizeof(float));
	if(!bounds) { err = fz_outofmem; goto cleanup; }
	
	for(i = 0; i < k-1; ++i) {
		numobj = fz_arrayget(tmpobj,i);
		if(!fz_isint(numobj) && !fz_isreal(numobj))
			goto cleanup;
		bounds[i] = fz_toreal(numobj);
		if(i && bounds[i-1] >= bounds[i])
			goto cleanup;
	}
	if(k != 1 && 
		(func->domain[0] >= bounds[0] || func->domain[1] <= bounds[k-2]))
		goto cleanup;
	
	/* required */
	tmpobj = fz_dictgets(dict,"Encode");
	if(!fz_isarray(tmpobj) || fz_arraylen(tmpobj) != k*2)
		goto cleanup;
	
	func->u.st.encode = encode = fz_malloc((k*2) * sizeof(float));
	if(!encode) { err = fz_outofmem; goto cleanup; }
	
	for(i = 0; i < k*2; ++i) {
		numobj = fz_arrayget(tmpobj,i);
		if(!fz_isint(numobj) && !fz_isreal(numobj))
			goto cleanup;
		encode[i] = fz_toreal(numobj);
	}
	
	func->u.st.k = k;
	
	return nil;
	
cleanup:
	if(err) return err;
	return fz_throw("syntaxerror : ");
}

static fz_error*
evalstitchingfunc(pdf_function *func, float in, float *out)
{
	fz_error *err = nil;
	float low,high;
	int k = func->u.st.k;
	float *bounds = func->u.st.bounds;
	int i;
	
	MIN_MAX(in,func->domain[0],func->domain[1]);
	
	for(i = 0; i < k - 1; ++i) {
		if (in < bounds[i])
			break;
	}
	if(i == 0) {
		low = func->domain[0];
		high = bounds[0];
	}
	else if(i == k - 1)	{
		low = bounds[k-2];
		high = func->domain[1];
	}
	else {
		low = bounds[i-1];
		high = bounds[i];
	}
	
	in = INTERPOLATE(in,low,high,
		func->u.st.encode[i*2],func->u.st.encode[i*2 + 1]);
	
	err = pdf_evalfunction(func->u.st.funcs[i],&in,1,out,func->n);
	if(err) return err;
	
	return nil;
}

static fz_error *
resizecode(pdf_function *func, int newsize) {
	if (newsize >= func->u.p.cap) {
		int newcodecap = func->u.p.cap + 64;
		psobj *newcode;
		newcode = fz_realloc(func->u.p.code, newcodecap * sizeof(psobj));
		if(!newcode)
			return fz_outofmem;
		func->u.p.cap = newcodecap;
		func->u.p.code = newcode;
	}
	return nil;
}

static fz_error *
parsecode(pdf_function *func, fz_file *stream, int *codeptr)
{
	fz_error *err = nil;
	char buf[64];
	int buflen = sizeof(buf) / sizeof(buf[0]);
	int len;
	int token;
	int opPtr, elsePtr;
	int a, b, mid, cmp;
	
	memset(buf,0,sizeof(buf));
	
	while (1) {
		token = pdf_lex(stream,buf,buflen,&len);
		if(token == PDF_TERROR || token == PDF_TEOF)
			goto cleanup;
		
		switch(token)
		{
		case PDF_TINT:
			resizecode(func,*codeptr);
			func->u.p.code[*codeptr].type = psInt;
			func->u.p.code[*codeptr].intg = atoi(buf);
			++*codeptr;
			break;
		case PDF_TREAL:
			resizecode(func,*codeptr);
			func->u.p.code[*codeptr].type = psReal;
			func->u.p.code[*codeptr].real = atof(buf);
			++*codeptr;
			break;
		case PDF_TOBRACE:
			opPtr = *codeptr;
			*codeptr += 3;
			resizecode(func,opPtr + 2);
			err = parsecode(func, stream, codeptr);
			if(err) goto cleanup;
			
			token = pdf_lex(stream,buf,buflen,&len);
			
			if(token == PDF_TEOF || token == PDF_TERROR)
				goto cleanup;
			
			if(token == PDF_TOBRACE) {
				elsePtr = *codeptr;
				err = parsecode(func, stream, codeptr);
				if(err)	goto cleanup;
				token = pdf_lex(stream,buf,buflen,&len);
				if(token == PDF_TERROR || token == PDF_TEOF)
					goto cleanup;
			}
			else 
				elsePtr = -1;
			
			if(token == PDF_TKEYWORD) {
				if(!strcmp(buf,"if")) {
					if (elsePtr >= 0)
						goto cleanup;
					func->u.p.code[opPtr].type = psOperator;
					func->u.p.code[opPtr].op = psOpIf;
					func->u.p.code[opPtr+2].type = psBlock;
					func->u.p.code[opPtr+2].blk = *codeptr;
				}
				else if(!strcmp(buf,"ifelse")) {
					if (elsePtr < 0)
						goto cleanup;
					func->u.p.code[opPtr].type = psOperator;
					func->u.p.code[opPtr].op = psOpIfelse;
					func->u.p.code[opPtr+1].type = psBlock;
					func->u.p.code[opPtr+1].blk = elsePtr;
					func->u.p.code[opPtr+2].type = psBlock;
					func->u.p.code[opPtr+2].blk = *codeptr;
				}
				else
					goto cleanup;
			}
			else
				goto cleanup;
			break;
		case PDF_TCBRACE:
			resizecode(func,*codeptr);
			func->u.p.code[*codeptr].type = psOperator;
			func->u.p.code[*codeptr].op = psOpReturn;
			++*codeptr;
			return nil;
		case PDF_TKEYWORD:
			a = -1;
			b = sizeof(psOpNames) / sizeof(psOpNames[0]);
			// invariant: psOpNames[a] < op < psOpNames[b]
			while (b - a > 1) {
				mid = (a + b) / 2;
				cmp = strcmp(buf,psOpNames[mid]);
				if (cmp > 0) {
					a = mid;
				} else if (cmp < 0) {
					b = mid;
				} else {
					a = b = mid;
				}
			}
			if (cmp != 0)
				goto cleanup;
			
			resizecode(func,*codeptr);
			func->u.p.code[*codeptr].type = psOperator;
			func->u.p.code[*codeptr].op = a;
			++*codeptr;
			break;
		default:
			goto cleanup;
		}
	}
	return nil;
cleanup:
	if(err) return err;
	return fz_throw("syntaxerror : postscript code");
}

static fz_error *
loadpostscriptfunc(pdf_function *func, pdf_xref *xref, 
				   fz_obj *dict, int oid, int gid)
{
	fz_error *err = nil;
	int codeptr;
	
	/* read postcript from stream */
	err = pdf_openstream(xref, oid, gid);
	if (err) goto cleanup;
	codeptr = 0;
	if(fz_readbyte(xref->stream) != '{')
		goto cleanup;

	err = parsecode(func, xref->stream, &codeptr);
	if(err) goto cleanup;

	pdf_closestream(xref);
	return nil;
	
cleanup:
	pdf_closestream(xref);
	if(err)	return err;
	return fz_throw("syntaxerror : ");
}

static fz_error *
evalpostscriptfunc(pdf_function *func, psstack *st, int codeptr)
{
	fz_error *err = nil;
	int i1, i2;
	float r1, r2;
	int b1, b2;
	
	while (1) {
		switch (func->u.p.code[codeptr].type) {
		case psInt:
			SAFE_PUSHINT(st,func->u.p.code[codeptr++].intg);
			break;
		case psReal:
			SAFE_PUSHREAL(st,func->u.p.code[codeptr++].real);
			break;
		case psOperator:
			switch (func->u.p.code[codeptr++].op) {
			case psOpAbs:
				if (topisint(st)) {
					SAFE_POPINT(st,&i1);
					SAFE_PUSHINT(st,abs(i1));
				} else {
					SAFE_POPNUM(st,&r1);
					SAFE_PUSHREAL(st,fabs(r1));
				}
				break;
			case psOpAdd:
				if (toptwoareints(st)) {
					SAFE_POPINT(st,&i2);
					SAFE_POPINT(st,&i1);
					SAFE_PUSHINT(st,i1 + i2);
				} else {
					SAFE_POPNUM(st,&r2);
					SAFE_POPNUM(st,&r1);
					SAFE_PUSHREAL(st,r1 + r2);
				}
				break;
			case psOpAnd:
				if (toptwoareints(st)) {
					SAFE_POPINT(st, &i2);
					SAFE_POPINT(st, &i1);
					SAFE_PUSHINT(st,i1 & i2);
				} else {
					SAFE_POPBOOL(st, &b2);
					SAFE_POPBOOL(st, &b1);
					SAFE_PUSHBOOL(st,b1 && b2);
				}
				break;
			case psOpAtan:
				SAFE_POPNUM(st, &r2);
				SAFE_POPNUM(st, &r1);
				SAFE_PUSHREAL(st,atan2(r1, r2)*RADIAN);
				break;
			case psOpBitshift:
				SAFE_POPINT(st, &i2);
				SAFE_POPINT(st, &i1);
				if (i2 > 0) {
					SAFE_PUSHINT(st,i1 << i2);
				} else if (i2 < 0) {
					SAFE_PUSHINT(st,(int)((unsigned int)i1 >> i2));
				} else {
					SAFE_PUSHINT(st,i1);
				}
				break;
			case psOpCeiling:
				if (!topisint(st)) {
					SAFE_POPNUM(st,&r1);
					SAFE_PUSHREAL(st,ceil(r1));
				}
				break;
			case psOpCopy:
				SAFE_POPINT(st,&i1);
				SAFE_COPY(st,i1);
				break;
			case psOpCos:
				SAFE_POPNUM(st,&r1);
				SAFE_PUSHREAL(st,cos(r1/RADIAN));
				break;
			case psOpCvi:
				if (!topisint(st)) {
					SAFE_POPNUM(st,&r1);
					SAFE_PUSHINT(st,(int)r1);
				}
				break;
			case psOpCvr:
				if (!topisreal(st)) {
					SAFE_POPNUM(st,&r1);
					SAFE_PUSHREAL(st,r1);
				}
				break;
			case psOpDiv:
				SAFE_POPNUM(st, &r2);
				SAFE_POPNUM(st, &r1);
				SAFE_PUSHREAL(st,r1 / r2);
				break;
			case psOpDup:
				SAFE_COPY(st,1);
				break;
			case psOpEq:
				if (toptwoareints(st)) {
					SAFE_POPINT(st, &i2);
					SAFE_POPINT(st, &i1);
					SAFE_PUSHBOOL(st,i1 == i2);
				} else if (toptwoarenums(st)) {
					SAFE_POPNUM(st, &r1);
					SAFE_POPNUM(st, &r1);
					SAFE_PUSHBOOL(st,r1 == r2);
				} else {
					SAFE_POPBOOL(st, &b2);
					SAFE_POPBOOL(st, &b2);
					SAFE_PUSHBOOL(st,b1 == b2);
				}
				break;
			case psOpExch:
				roll(st,2, 1);
				break;
			case psOpExp:
				SAFE_POPNUM(st, &r2);
				SAFE_POPNUM(st, &r1);
				SAFE_PUSHREAL(st,pow(r1, r2));
				break;
			case psOpFalse:
				SAFE_PUSHBOOL(st,0);
				break;
			case psOpFloor:
				if (!topisint(st)) {
					SAFE_POPNUM(st, &r1);
					SAFE_PUSHREAL(st,floor(r1));
				}
				break;
			case psOpGe:
				if (toptwoareints(st)) {
					SAFE_POPINT(st, &i2);
					SAFE_POPINT(st, &i1);
					SAFE_PUSHBOOL(st,i1 >= i2);
				} else {
					SAFE_POPNUM(st, &r2);
					SAFE_POPNUM(st, &r1);
					SAFE_PUSHBOOL(st,r1 >= r2);
				}
				break;
			case psOpGt:
				if (toptwoareints(st)) {
					SAFE_POPINT(st,&i2);
					SAFE_POPINT(st,&i1);
					SAFE_PUSHBOOL(st,i1 > i2);
				} else {
					SAFE_POPNUM(st, &r2);
					SAFE_POPNUM(st, &r1);
					SAFE_PUSHBOOL(st,r1 > r2);
				}
				break;
			case psOpIdiv:
				SAFE_POPINT(st,&i2);
				SAFE_POPINT(st,&i1);
				SAFE_PUSHINT(st,i1 / i2);
				break;
			case psOpIndex:
				SAFE_POPINT(st, &i1);
				SAFE_INDEX(st, i1);
				break;
			case psOpLe:
				if (toptwoareints(st)) {
					SAFE_POPINT(st,&i2);
					SAFE_POPINT(st,&i1);
					SAFE_PUSHBOOL(st,i1 <= i2);
				} else {
					SAFE_POPNUM(st, &r2);
					SAFE_POPNUM(st, &r1);
					SAFE_PUSHBOOL(st,r1 <= r2);
				}
				break;
			case psOpLn:
				SAFE_POPNUM(st, &r1);
				SAFE_PUSHREAL(st,log(r1));
				break;
			case psOpLog:
				SAFE_POPNUM(st, &r1);
				SAFE_PUSHREAL(st,log10(r1));
				break;
			case psOpLt:
				if (toptwoareints(st)) {
					SAFE_POPINT(st,&i2);
					SAFE_POPINT(st,&i1);
					SAFE_PUSHBOOL(st,i1 < i2);
				} else {
					SAFE_POPNUM(st, &r2);
					SAFE_POPNUM(st, &r1);
					SAFE_PUSHBOOL(st,r1 < r2);
				}
				break;
			case psOpMod:
				SAFE_POPINT(st,&i2);
				SAFE_POPINT(st,&i1);
				SAFE_PUSHINT(st,i1 % i2);
				break;
			case psOpMul:
				if (toptwoareints(st)) {
					SAFE_POPINT(st,&i2);
					SAFE_POPINT(st,&i1);
					//~ should check for out-of-range, and push a real instead
					SAFE_PUSHINT(st,i1 * i2);
				} else {
					SAFE_POPNUM(st, &r2);
					SAFE_POPNUM(st, &r1);
					SAFE_PUSHREAL(st,r1 * r2);
				}
				break;
			case psOpNe:
				if (toptwoareints(st)) {
					SAFE_POPINT(st, &i2);
					SAFE_POPINT(st, &i1);
					SAFE_PUSHBOOL(st, i1 != i2);
				} else if (toptwoarenums(st)) {
					SAFE_POPNUM(st, &r2);
					SAFE_POPNUM(st, &r1);
					SAFE_PUSHBOOL(st, r1 != r2);
				} else {
					SAFE_POPBOOL(st, &b2);
					SAFE_POPBOOL(st, &b1);
					SAFE_PUSHBOOL(st,b1 != b2);
				}
				break;
			case psOpNeg:
				if (topisint(st)) {
					SAFE_POPINT(st, &i1);
					SAFE_PUSHINT(st, -i1);
				} else {
					SAFE_POPNUM(st, &r1);
					SAFE_PUSHREAL(st, -r1);
				}
				break;
			case psOpNot:
				if (topisint(st)) {
					SAFE_POPINT(st, &i1);
					SAFE_PUSHINT(st, ~i1);
				} else {
					SAFE_POPBOOL(st, &b1);
					SAFE_PUSHBOOL(st, !b1);
				}
				break;
			case psOpOr:
				if (toptwoareints(st)) {
					SAFE_POPINT(st,&i2);
					SAFE_POPINT(st,&i1);
					SAFE_PUSHINT(st,i1 | i2);
				} else {
					SAFE_POPBOOL(st, &b2);
					SAFE_POPBOOL(st, &b1);
					SAFE_PUSHBOOL(st,b1 || b2);
				}
				break;
			case psOpPop:
				SAFE_POP(st);
				break;
			case psOpRoll:
				SAFE_POPINT(st,&i2);
				SAFE_POPINT(st,&i1);
				roll(st,i1, i2);
				break;
			case psOpRound:
				if (!topisint(st)) {
					SAFE_POPNUM(st, &r1);
					SAFE_PUSHREAL(st,(r1 >= 0) ? floor(r1 + 0.5) : ceil(r1 - 0.5));
				}
				break;
			case psOpSin:
				SAFE_POPNUM(st, &r1);
				SAFE_PUSHREAL(st, sin(r1/RADIAN));
				break;
			case psOpSqrt:
				SAFE_POPNUM(st, &r1);
				SAFE_PUSHREAL(st, sqrt(r1));
				break;
			case psOpSub:
				if (toptwoareints(st)) {
					SAFE_POPINT(st,&i2);
					SAFE_POPINT(st,&i1);
					SAFE_PUSHINT(st,i1 - i2);
				} else {
					SAFE_POPNUM(st, &r2);
					SAFE_POPNUM(st, &r1);
					SAFE_PUSHREAL(st,r1 - r2);
				}
				break;
			case psOpTrue:
				SAFE_PUSHBOOL(st,1);
				break;
			case psOpTruncate:
				if (!topisint(st)) {
					SAFE_POPNUM(st, &r1);
					SAFE_PUSHREAL(st,(r1 >= 0) ? floor(r1) : ceil(r1));
				}
				break;
			case psOpXor:
				if (toptwoareints(st)) {
					SAFE_POPINT(st,&i2);
					SAFE_POPINT(st,&i1);
					SAFE_PUSHINT(st,i1 ^ i2);
				} else {
					SAFE_POPBOOL(st, &b2);
					SAFE_POPBOOL(st, &b1);
					SAFE_PUSHBOOL(st,b1 ^ b2);
				}
				break;
			case psOpIf:
				SAFE_POPBOOL(st, &b1);
				if (b1) {
					evalpostscriptfunc(func, st, codeptr + 2);
				}
				codeptr = func->u.p.code[codeptr + 1].blk;
				break;
			case psOpIfelse:
				SAFE_POPBOOL(st, &b1);
				if (b1) {
					evalpostscriptfunc(func, st, codeptr + 2);
				} else {
					evalpostscriptfunc(func, st, func->u.p.code[codeptr].blk);
				}
				codeptr = func->u.p.code[codeptr + 1].blk;
				break;
			case psOpReturn:
				return nil;
      }
      break;
    default:
		return fz_throw("syntaxerror : ");
		break;
    }
  }

cleanup:
  return err;
}

void
pdf_freefunc(pdf_function *func)
{
	int i;

	if(func->domain)
		fz_free(func->domain);

	if(func->range)
		fz_free(func->range);

	switch(func->type) {
	case PDF_FUNC_SAMPLE:
		if(func->u.sa.decode)
			fz_free(func->u.sa.decode);
		if(func->u.sa.encode)
			fz_free(func->u.sa.encode);
		if(func->u.sa.samples)
			fz_free(func->u.sa.samples);
		break;
	case PDF_FUNC_EXPONENTIAL:
		if(func->u.e.c0)
			fz_free(func->u.e.c0);
		if(func->u.e.c1)
			fz_free(func->u.e.c1);
		break;
	case PDF_FUNC_STITCHING:
		if(func->u.st.bounds)
			fz_free(func->u.st.bounds);
		if(func->u.st.encode)
			fz_free(func->u.st.encode);
		if(func->u.st.funcs) {
			for(i = 0; i < func->u.st.k; ++i)
				pdf_freefunc(func->u.st.funcs[i]);

			fz_free(func->u.st.funcs);
		}
		break;
	case PDF_FUNC_POSTSCRIPT:
		if(func->u.p.code)
			fz_free(func->u.p.code);
		break;
	}
	fz_free(func);
}

fz_error *
pdf_loadfunction(pdf_function **func, pdf_xref *xref, fz_obj *obj)
{
	fz_error *err = nil;
	fz_obj *objfunc = nil;
	fz_obj *tmpobj;
	pdf_function *newfunc = nil;
	int tmp;
	int i;
	float min,max;
	
	newfunc = fz_malloc(sizeof(pdf_function));
	if(!newfunc) return fz_outofmem;
	memset(newfunc,0,sizeof(pdf_function));
	
	objfunc = obj;
	err = pdf_resolve(&objfunc,xref);
	if(err) { objfunc = nil; goto cleanup; }
	
	if(!fz_isdict(objfunc))
		goto cleanup;
	
	/* required */
	tmpobj = fz_dictgets(objfunc,"FunctionType");
	if(!fz_isint(tmpobj))
		goto cleanup;
	newfunc->type = fz_toint(tmpobj);
	
	/* required */
	tmpobj = fz_dictgets(objfunc,"Domain");
	if(!fz_isarray(tmpobj))
		goto cleanup;
	tmp = fz_arraylen(tmpobj);
	if(tmp % 2)
		goto cleanup;
	newfunc->m = tmp / 2;
	newfunc->domain = fz_malloc(tmp * sizeof(float));
	for (i = 0; i < tmp / 2; ++i)
	{
		min = fz_toreal(fz_arrayget(tmpobj, i*2));
		max = fz_toreal(fz_arrayget(tmpobj, i*2+1));
		if(min > max)
			goto cleanup;
		newfunc->domain[i*2] = min;
		newfunc->domain[i*2+1] = max;
	}
	
	/* required for type0 and type4, optional otherwise */
	tmpobj = fz_dictgets(objfunc,"Range");
	if(fz_isarray(tmpobj)) {
		tmp = fz_arraylen(tmpobj);
		if(tmp % 2)
			goto cleanup;
		newfunc->n = tmp / 2;
		newfunc->range = fz_malloc(tmp * sizeof(float));
		for (i = 0; i < tmp / 2; ++i)
		{
			min = fz_toreal(fz_arrayget(tmpobj, i*2));
			max = fz_toreal(fz_arrayget(tmpobj, i*2+1));
			if(min > max)
				goto cleanup;
			newfunc->range[i*2] = min;
			newfunc->range[i*2+1] = max;
		}
	}
	else if(newfunc->type == PDF_FUNC_SAMPLE ||
		newfunc->type == PDF_FUNC_POSTSCRIPT)
		goto cleanup;
	
	switch(newfunc->type)
	{
	case PDF_FUNC_SAMPLE:
		if(!fz_isindirect(obj))
			goto cleanup;
		if(!pdf_isstream(xref, fz_tonum(obj), fz_togen(obj)))
			goto cleanup;
		err = loadsamplefunc(newfunc, xref, objfunc,
			fz_tonum(obj), fz_togen(obj));
		if(err) goto cleanup;
		break;
	case PDF_FUNC_EXPONENTIAL:
		err = loadexponentialfunc(newfunc, objfunc);
		if(err) goto cleanup;
		break;
	case PDF_FUNC_STITCHING:
		err = loadstitchingfunc(newfunc, xref, objfunc);
		if(err) goto cleanup;
		break;
	case PDF_FUNC_POSTSCRIPT:
		if(!fz_isindirect(obj))
			goto cleanup;
		if(!pdf_isstream(xref, fz_tonum(obj), fz_togen(obj)))
			goto cleanup;
		err = loadpostscriptfunc(newfunc, xref, objfunc,
			fz_tonum(obj), fz_togen(obj));		
		if(err) goto cleanup;
		break;
	default:
		goto cleanup;
	}
	
	fz_dropobj(objfunc);
	
	*func = newfunc;
	
	return nil;
	
cleanup:
	if(objfunc)
		fz_dropobj(objfunc);
	
	pdf_freefunc(newfunc);
	
	if(err) return err;
	return fz_throw("syntaxerror : ");
}

fz_error *
pdf_evalfunction(pdf_function *func, float *in, int inlen, float *out, int outlen)
{
	fz_error *err = nil;
	int i;

	if(func->m != inlen || func->n != outlen)
		return fz_throw("syntaxerror : input lenth or output length mismatch");

	switch(func->type) {
	case PDF_FUNC_SAMPLE:
		err = evalsamplefunc(func, in, out);
		break;
	case PDF_FUNC_EXPONENTIAL:
		err = evalexponentialfunc(func, *in, out);
		break;
	case PDF_FUNC_STITCHING:
		err = evalstitchingfunc(func, *in, out);
		break;
	case PDF_FUNC_POSTSCRIPT:
		{
			psstack st;
			initstack(&st);
			for (i = 0; i < func->m; ++i)
				SAFE_PUSHREAL(&st,in[i]);

			err = evalpostscriptfunc(func, &st, 0);
			if(err) goto cleanup;

			for (i = func->n - 1; i >= 0; --i) {
				SAFE_POPNUM(&st,out+i);
				MIN_MAX(out[i],func->range[i*2],func->range[i*2+1]);
			}
		}
		break;
	}
cleanup:
	return err;
}
