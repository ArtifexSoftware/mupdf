/*
x86 specific render optims live here
*/
#include <fitz.h>

/* always surround cpu specific code with HAVE_XXX */
#ifdef HAVE_MMX

/* -mmmx for gcc >= 3.4 enables the mmx intrinsic functions, icc and VC
   shouldn't require anything */
#include <mmintrin.h>

static inline unsigned
getargb(unsigned *s, int w, int h, int u, int v)
{
	if (u < 0 || u >= w) return 0;
	if (v < 0 || v >= h) return 0;
	return s[w * v + u];
}

/* this code has not been tested since refactoring */
static void img_4o4mmx(FZ_PSRC, FZ_PDST, FZ_PCTM)
{
	/* since mmx does not have an unsigned multiply instruction we use
	   17.15 fixed point */
	u0 <<= 1;	v0 <<= 1;
	fa <<= 1;	fb <<= 1;
	fc <<= 1;	fd <<= 1;

	while (h--)
	{
		unsigned *s = (unsigned *)src;
		unsigned *d = (unsigned *)dst0;
		int u = u0;
		int v = v0;
				int w = w0;

		while (w--)
		{
			int iu = u >> 17;
			int iv = u >> 17;

			int fu = u & 0x7fff;
			int fv = v & 0x7fff;

			int atedge =
				iu < 0 | iu >= (srcw - 1) |
				iv < 0 | iv >= (srch - 1);

			__m64 ms0s1;
			__m64 ms2s3;

			if (atedge)
			{
				unsigned s0, s1, s2, s3;

				/* edge cases use scalar loads */
				s0 = getargb(s, srcw, srch, iu + 0, iv + 0);
				s1 = getargb(s, srcw, srch, iu + 1, iv + 0);
				s2 = getargb(s, srcw, srch, iu + 0, iv + 1);
				s3 = getargb(s, srcw, srch, iu + 1, iv + 1);

				/* move to mmx registers */
				ms0s1 = _mm_set_pi32(s0, s1);
				ms2s3 = _mm_set_pi32(s2, s3);
			}
			else
			{
				__m64 *m0s = (__m64*)(s + srcw * (iv + 0) + iu);
				__m64 *m2s = (__m64*)(s + srcw * (iv + 1) + iu);

				/* faster vector loads for interior */
				ms0s1 = *m0s;
				ms2s3 = *m2s;
			}

			/* unpack src into 4x16bit vectors */
			__m64 mzero = _mm_setzero_si64();
			__m64 ms0 = _mm_unpackhi_pi8(ms0s1, mzero);
			__m64 ms1 = _mm_unpacklo_pi8(ms0s1, mzero);
			__m64 ms2 = _mm_unpackhi_pi8(ms2s3, mzero);
			__m64 ms3 = _mm_unpacklo_pi8(ms2s3, mzero);

			/* lerp fu */

			__m64 mfu = _mm_set1_pi16(fu);

			/* t2 = (s1 - s0) * fu + s0 */
			__m64 t0 = _mm_sub_pi16(ms1, ms0);
			__m64 t1 = _mm_mulhi_pi16(t0, mfu);
			__m64 t2 = _mm_add_pi16(t1, ms0);

			/* t3 = (s3 - s2) * fu + s2 */
			__m64 t3 = _mm_sub_pi16(ms3, ms2);
			__m64 t4 = _mm_mulhi_pi16(t3, mfu);
			__m64 t5 = _mm_add_pi16(t4, ms2);

			/* lerp fv */

			__m64 mfv = _mm_set1_pi16(fv);

			/* t8 = (t5 - t2) * fv + t2 */
			__m64 t6 = _mm_sub_pi16(t5, t2);
			__m64 t7 = _mm_mulhi_pi16(t6, mfv);
			__m64 t8 = _mm_add_pi16(t7, t2);

			/* load and prepare dst */
			__m64 d0 = _mm_cvtsi32_si64(*d);

			__m64 d1 = _mm_unpacklo_pi8(d0, mzero);

			/* get src alpha */
			__m64 m256 = _mm_set1_pi16(256);
			__m64 malphamask = _mm_cvtsi32_si64(0xff);

			/* splat alpha TODO: better way? */
			__m64 a0001 = _mm_and_si64(malphamask, t8);
			__m64 a0010 = _mm_slli_si64(a0001, 16);
			__m64 a0011 = _mm_or_si64(a0001, a0010);
			__m64 a1111 = _mm_unpacklo_pi16(a0011, a0011);
			/* 255+1 - sa */
			__m64 sna = _mm_sub_pi16(m256, a1111);

			/* blend src with dst */
			__m64 d2 = _mm_mullo_pi16(d1, sna);
			__m64 d3 = _mm_srli_pi16(d2, 8);
			__m64 d4 = _mm_add_pi16(t8, d3);

			/* pack and store new dst */
			__m64 d5 = _mm_packs_pu16(d4, mzero);

			*d++ = _mm_cvtsi64_si32(d5);

			u += fa;
			v += fb;
		}

		dst0 += dstw;
		u0 += fc;
		v0 += fd;
	}

	_mm_empty();
}

#endif /* HAVE_MMX */

#if defined (ARCH_X86) || defined(ARCH_X86_64)
void
fz_accelrastfuncs(fz_rastfuncs *tab)
{
#  ifdef HAVE_MMX
	if (fz_cpuflags & HAVE_MMX)
	{
		tab->img_4o4 = img_4o4mmx;
	}
#  endif
}
#endif

