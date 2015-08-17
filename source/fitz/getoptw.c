/*
 * This is a version of the public domain getopt implementation by
 * Henry Spencer originally posted to net.sources. Adapted to
 * windows wchar's.
 *
 * This file is in the public domain.
 */

#if defined(_WIN64) || defined(_WIN32)

#include <stdio.h>
#include <string.h>
#include <windows.h>

#define getoptw fz_getoptw
#define optargw fz_optargw
#define optindw fz_optindw

wchar_t *optargw; /* Global argument pointer. */
int optindw = 0; /* Global argv index. */

static wchar_t *scan = NULL; /* Private scan pointer. */

int
getoptw(wchar_t argc, wchar_t *argv[], wchar_t *optstring)
{
	wchar_t c;
	wchar_t *place;

	optargw = NULL;

	if (!scan || *scan == '\0') {
		if (optindw == 0)
			optindw++;

		if (optindw >= argc || argv[optindw][0] != '-' || argv[optindw][1] == '\0')
			return EOF;
		if (argv[optindw][1] == '-' && argv[optindw][2] == '\0') {
			optindw++;
			return EOF;
		}

		scan = argv[optindw]+1;
		optindw++;
	}

	c = *scan++;
	place = wcschr(optstring, c);

	if (!place || c == ':') {
		fprintf(stderr, "%s: unknown option -%C\n", argv[0], c);
		return '?';
	}

	place++;
	if (*place == ':') {
		if (*scan != '\0') {
			optargw = scan;
			scan = NULL;
		} else if( optindw < argc ) {
			optargw = argv[optindw];
			optindw++;
		} else {
			fprintf(stderr, "%s: option requires argument -%C\n", argv[0], c);
			return ':';
		}
	}

	return c;
}

#endif
