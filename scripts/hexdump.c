/* hexdump.c -- an "xxd -i" workalike for dumping binary files as source code */

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
	char filename[256];
	char *basename;
	char *p;
	int i, size;

	if (argc < 3)
	{
		fprintf(stderr, "usage: hexdump output.c input.dat\n");
		return 1;
	}

	fo = fopen(argv[1], "wb");
	if (!fo)
	{
		fprintf(stderr, "hexdump: could not open output file '%s'\n", argv[1]);
		return 1;
	}

	fprintf(fo, "#ifndef __STRICT_ANSI__\n");
	fprintf(fo, "#if defined(__linux__) || defined(__FreeBSD__) || defined(__OpenBSD__)\n");
	fprintf(fo, "#if !defined(__ICC) && !defined(__ANDROID__)\n");
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
			fprintf(stderr, "hexdump: could not open input file '%s'\n", argv[i]);
			return 1;
		}

		basename = strrchr(argv[i], '/');
		if (!basename)
			basename = strrchr(argv[i], '\\');
		if (basename)
			basename++;
		else
			basename = argv[i];

		if (strlen(basename) >= sizeof(filename))
		{
			fclose(fi);
			fclose(fo);
			fprintf(stderr, "hexdump: filename '%s' too long\n", basename);
			return 1;
		}

		strcpy(filename, argv[i]);
		for (p = filename; *p; ++p)
		{
			if (*p == '/' || *p == '.' || *p == '\\' || *p == '-')
				*p = '_';
		}

		fseek(fi, 0, SEEK_END);
		size = ftell(fi);
		fseek(fi, 0, SEEK_SET);

		fprintf(fo, "\n#ifdef HAVE_INCBIN\n");
		fprintf(fo, "const int fz_%s_size = %d;\n", filename, size);
		fprintf(fo, "extern const char fz_%s[];\n", filename);
		fprintf(fo, "asm(\".section .rodata\");\n");
		fprintf(fo, "asm(\".global fz_%s\");\n", filename);
		fprintf(fo, "asm(\".type fz_%s STT_OBJECT\");\n", filename);
		fprintf(fo, "asm(\".size fz_%s, %d\");\n", filename, size);
		fprintf(fo, "asm(\".balign 64\");\n");
		fprintf(fo, "asm(\"fz_%s:\");\n", filename);
		fprintf(fo, "asm(\".incbin \\\"%s\\\"\");\n", argv[i]);
		fprintf(fo, "#else\n");
		fprintf(fo, "const int fz_%s_size = %d;\n", filename, size);
		fprintf(fo, "const char fz_%s[] = {\n", filename);
		hexdump(fo, fi);
		fprintf(fo, "0};\n"); /* zero-terminate so we can hexdump text files into C strings */
		fprintf(fo, "#endif\n");

		fclose(fi);
	}

	if (fclose(fo))
	{
		fprintf(stderr, "hexdump: could not close output file '%s'\n", argv[1]);
		return 1;
	}

	return 0;
}
