/* namedump.c -- parse an alphabetically sorted list of PDF names
 * and generate header files from it. */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

char buffer[256];

static char *get_line(FILE *in)
{
	size_t l;

	if (fgets(buffer, sizeof(buffer), in) == NULL)
	{
		buffer[0] = 0;
		return buffer;
	}
	l = strlen(buffer);
	while (l > 0 && buffer[l-1] <= ' ')
		l--;
	buffer[l] = 0;

	return buffer;
}

int
main(int argc, char **argv)
{
	FILE *in;
	FILE *out_c;
	FILE *out_h;

	if (argc != 4)
	{
		fprintf(stderr, "Syntax:\nnamedump <in-file> <public header> <private header>\n");
		return EXIT_FAILURE;
	}

	in = fopen(argv[1], "rb");
	if (!in)
	{
		fprintf(stderr, "Failed to open '%s' for reading\n", argv[1]);
		return EXIT_FAILURE;
	}

	out_h = fopen(argv[2], "wb");
	if (!out_h)
	{
		fprintf(stderr, "Failed to open '%s' for writing\n", argv[2]);
		return EXIT_FAILURE;
	}

	out_c = fopen(argv[3], "wb");
	if (!out_c)
	{
		fprintf(stderr, "Failed to open '%s' for writing\n", argv[3]);
		return EXIT_FAILURE;
	}

	fprintf(out_c, "char *PDF_NAMES[] =\n{\n\t\"\",\n");

	fprintf(out_h, "enum\n{\n\tPDF_OBJ_ENUM__DUMMY,\n");

	while (!feof(in))
	{
		char *line = get_line(in);
		if (*line == 0)
			continue;

		fprintf(out_c, "\t\"%s\",\n", line);

		{
			char *l;
			for (l = line; *l; l++)
			{
				if (*l == '.' || *l == '-')
					*l = '_';
			}
		}

		fprintf(out_h, "#define PDF_NAME_%s  ((pdf_obj *)(intptr_t)PDF_OBJ_ENUM_NAME_%s)\n", line, line);
		fprintf(out_h, "\tPDF_OBJ_ENUM_NAME_%s,\n", line);
	}

	fprintf(out_h, "#define PDF_OBJ_NAME__LIMIT ((pdf_obj *)(intptr_t)PDF_OBJ_ENUM_NAME__LIMIT)\n\tPDF_OBJ_ENUM_NAME__LIMIT,\n");
	fprintf(out_h, "#define PDF_OBJ_FALSE ((pdf_obj *)(intptr_t)PDF_OBJ_ENUM_BOOL_FALSE)\n\tPDF_OBJ_ENUM_BOOL_FALSE = PDF_OBJ_ENUM_NAME__LIMIT,\n");
	fprintf(out_h, "#define PDF_OBJ_TRUE ((pdf_obj *)(intptr_t)PDF_OBJ_ENUM_BOOL_TRUE)\n\tPDF_OBJ_ENUM_BOOL_TRUE,\n");
	fprintf(out_h, "#define PDF_OBJ_NULL ((pdf_obj *)(intptr_t)PDF_OBJ_ENUM_NULL)\n\tPDF_OBJ_ENUM_NULL,\n");
	fprintf(out_h, "#define PDF_OBJ__LIMIT ((pdf_obj *)(intptr_t)PDF_OBJ_ENUM__LIMIT)\n\tPDF_OBJ_ENUM__LIMIT\n};\n");

	fprintf(out_c, "};\n");

	fclose(out_c);
	fclose(out_h);
	fclose(in);

	return EXIT_SUCCESS;
}
