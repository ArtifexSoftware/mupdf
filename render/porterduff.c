#include <fitz.h>

/* Porter-Duff compositing arithmetic on premultiplied ARGB buffers */

void
fz_blendover(unsigned char *C, unsigned char *A, unsigned char *B, int n)
{
	while (n--)
	{
		unsigned char Fa = 255;
		unsigned char Fb = 255 - A[0];
		*C++ = fz_mul255(*A++, Fa) + fz_mul255(*B++, Fb);
		*C++ = fz_mul255(*A++, Fa) + fz_mul255(*B++, Fb);
		*C++ = fz_mul255(*A++, Fa) + fz_mul255(*B++, Fb);
		*C++ = fz_mul255(*A++, Fa) + fz_mul255(*B++, Fb);
	}
}

void
fz_blendin(unsigned char *C, unsigned char *A, unsigned char *B, int n)
{
	while (n--)
	{
		unsigned char Fa = B[0];
		unsigned char Fb = 0;
		*C++ = fz_mul255(*A++, Fa) + fz_mul255(*B++, Fb);
		*C++ = fz_mul255(*A++, Fa) + fz_mul255(*B++, Fb);
		*C++ = fz_mul255(*A++, Fa) + fz_mul255(*B++, Fb);
		*C++ = fz_mul255(*A++, Fa) + fz_mul255(*B++, Fb);
	}
}

void
fz_blendout(unsigned char *C, unsigned char *A, unsigned char *B, int n)
{
	while (n--)
	{
		unsigned char Fa = 255 - B[0];
		unsigned char Fb = 0;
		*C++ = fz_mul255(*A++, Fa) + fz_mul255(*B++, Fb);
		*C++ = fz_mul255(*A++, Fa) + fz_mul255(*B++, Fb);
		*C++ = fz_mul255(*A++, Fa) + fz_mul255(*B++, Fb);
		*C++ = fz_mul255(*A++, Fa) + fz_mul255(*B++, Fb);
	}
}

void
fz_blendatop(unsigned char *C, unsigned char *A, unsigned char *B, int n)
{
	while (n--)
	{
		unsigned char Fa = B[0];
		unsigned char Fb = 255 - A[0];
		*C++ = fz_mul255(*A++, Fa) + fz_mul255(*B++, Fb);
		*C++ = fz_mul255(*A++, Fa) + fz_mul255(*B++, Fb);
		*C++ = fz_mul255(*A++, Fa) + fz_mul255(*B++, Fb);
		*C++ = fz_mul255(*A++, Fa) + fz_mul255(*B++, Fb);
	}
}

void
fz_blendxor(unsigned char *C, unsigned char *A, unsigned char *B, int n)
{
	while (n--)
	{
		unsigned char Fa = 255 - B[0];
		unsigned char Fb = 255 - A[0];
		*C++ = fz_mul255(*A++, Fa) + fz_mul255(*B++, Fb);
		*C++ = fz_mul255(*A++, Fa) + fz_mul255(*B++, Fb);
		*C++ = fz_mul255(*A++, Fa) + fz_mul255(*B++, Fb);
		*C++ = fz_mul255(*A++, Fa) + fz_mul255(*B++, Fb);
	}
}

