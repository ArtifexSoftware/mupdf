/* strdump.c -- similar to hexdump but with ascii strings */

#include <stdio.h>
#include <string.h>

int
strdump(FILE *fo, FILE *fi)
{
    int c, n;

    n = 0;
    fputs("\"", fo);
    c = fgetc(fi);
    while (c != -1)
    {
	if (c == '\n' || c == '\r')
	    fputs("\\n\"\n\"", fo);
	else
	    putc(c, fo);
	c = fgetc(fi);
	n ++;
    }
    fputs("\"\n", fo);
    return n;
}


int
main(int argc, char **argv)
{
    FILE *fo;
    FILE *fi;
    char name[256];
    char *realname;
    char *p;
    int i, len;

    if (argc < 3)
    {
	fprintf(stderr, "usage: hexdump output.c input.dat\n");
	return 1;
    }

    fo = fopen(argv[1], "wb");
    if (!fo)
    {
	fprintf(stderr, "hexdump: could not open output file\n");
	return 1;
    }

    for (i = 2; i < argc; i++)
    {
	fi = fopen(argv[i], "rb");
	if (!fi)
	{
	    fprintf(stderr, "hexdump: could not open input file\n");
	    return 1;
	}

	realname = strrchr(argv[i], '/');
	if (!realname)
	    realname = strrchr(argv[i], '\\');
	if (realname)
	    realname ++;
	else
	    realname = argv[i];

	strcpy(name, argv[i]);
	p = name;
	while (*p)
	{
	    if ((*p == '/') || (*p == '.') || (*p == '\\') || (*p == '-'))
		*p = '_';
	    p ++;
	}

	fprintf(fo, "const char %s_name[] = \"%s\";\n", name, realname);
	fprintf(fo, "const char %s_buf[] = {\n", name);

	len = strdump(fo, fi);

	fprintf(fo, "};\n");
	fprintf(fo, "const int %s_len = %d;\n", name, len);
	fprintf(fo, "\n");

	fclose(fi);
    }

    return 0;
}

