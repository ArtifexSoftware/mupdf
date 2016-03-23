/* fontdump.c -- an "xxd -i" workalike for dumping binary fonts as source code */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int
hexdump(FILE *fo, FILE *fi)
{
	int c, n;

	n = 0;
	c = fgetc(fi);
	while (c != -1)
	{
		n += fprintf(fo, "%d,", c);
		if (n > 72) {
			fprintf(fo, "\n");
			n = 0;
		}
		c = fgetc(fi);
	}

	return n;
}

int
main(int argc, char **argv)
{
	FILE *fo;
	FILE *fi;
	char fontname[256];
	char *basename;
	char *p;
	int i, size;

	if (argc < 3)
	{
		fprintf(stderr, "usage: fontdump output.c input.dat\n");
		return 1;
	}

	fo = fopen(argv[1], "wb");
	if (!fo)
	{
		fprintf(stderr, "fontdump: could not open output file '%s'\n", argv[1]);
		return 1;
	}

	fprintf(fo, "#ifndef __STRICT_ANSI__\n");
	fprintf(fo, "#if defined(__linux__) || defined(__FreeBSD__) || defined(__OpenBSD__)\n");
	fprintf(fo, "#if !defined(__ICC)\n");
	fprintf(fo, "#define HAVE_INCBIN\n");
	fprintf(fo, "#endif\n");
	fprintf(fo, "#endif\n");
	fprintf(fo, "#endif\n");

	for (i = 2; i < argc; i++)
	{
		fi = fopen(argv[i], "rb");
		if (!fi)
		{
			fclose(fo);
			fprintf(stderr, "fontdump: could not open input file '%s'\n", argv[i]);
			return 1;
		}

		basename = strrchr(argv[i], '/');
		if (!basename)
			basename = strrchr(argv[i], '\\');
		if (basename)
			basename++;
		else
			basename = argv[i];

		strcpy(fontname, basename);
		for (p = fontname; *p; ++p)
		{
			if (*p == '/' || *p == '.' || *p == '\\' || *p == '-')
				*p = '_';
		}

		fseek(fi, 0, SEEK_END);
		size = ftell(fi);
		fseek(fi, 0, SEEK_SET);

		fprintf(fo, "\n#ifdef HAVE_INCBIN\n");
		fprintf(fo, "const int fz_font_%s_size = %d;\n", fontname, size);
		fprintf(fo, "asm(\".section .rodata\");\n");
		fprintf(fo, "asm(\".global fz_font_%s\");\n", fontname);
		fprintf(fo, "asm(\".type fz_font_%s STT_OBJECT\");\n", fontname);
		fprintf(fo, "asm(\".size fz_font_%s, %d\");\n", fontname, size);
		fprintf(fo, "asm(\".balign 64\");\n");
		fprintf(fo, "asm(\"fz_font_%s:\");\n", fontname);
		fprintf(fo, "asm(\".incbin \\\"%s\\\"\");\n", argv[i]);
		fprintf(fo, "#else\n");
		fprintf(fo, "const int fz_font_%s_size = %d;\n", fontname, size);
		fprintf(fo, "const char fz_font_%s[] = {\n", fontname);
		hexdump(fo, fi);
		fprintf(fo, "};\n");
		fprintf(fo, "#endif\n");

		fclose(fi);
	}

	if (fclose(fo))
	{
		fprintf(stderr, "fontdump: could not close output file '%s'\n", argv[1]);
		return 1;
	}

	return 0;
}
