/*
PowerPC specific render optims live here
*/
#include <fitz.h>

#ifdef HAVE_ALTIVEC

#endif /* HAVE_ALTIVEC */

#if defined (ARCH_PPC)
void
fz_accelrastfuncs(fz_rastfuncs *tab)
{
#  ifdef HAVE_ALTIVEC
	if (fz_cpuflags & HAVE_ALTIVEC)
	{
	}
#  endif
}
#endif

