/*
SPARC specific render optims live here
*/
#include <fitz.h>

#ifdef HAVE_VIS

#endif

#if defined (ARCH_SPARC)
void
fz_accelrastfuncs(fz_rastfuncs *tab)
{
#  ifdef HAVE_VIS
	if (fz_cpuflags & HAVE_VIS)
	{
	}
#  endif
}
#endif

