#include "fitz.h"
#include "samus.h"

void showfixdocseq(sa_package *pack, char *part)
{
	fz_error *error;
	sa_fixdocseq *seq;

	error = sa_loadfixdocseq(&seq, pack, part);
	if (error)
		fz_abort(error);

	sa_debugfixdocseq(seq);

	sa_dropfixdocseq(seq);
}

void showreach(sa_package *pack, sa_relation *rels)
{
	while (rels)
	{
		if (!strcmp(rels->type, SA_REL_FIXEDREPRESENTATION))
		{
			if (!rels->external)
				showfixdocseq(pack, rels->target);
		}
		rels = rels->next;
	}
}

int runpack(int argc, char **argv)
{
	fz_error *error;
	sa_package *pack;
	sa_relation *rels;
	char *s;
	int i;

	error = sa_openpackage(&pack, argv[1]);
	if (error)
		fz_abort(error);

	sa_debugpackage(pack);
	printf("\n");

	error = sa_loadrelations(&rels, pack, "/");
	if (error)
		fz_abort(error);
	sa_debugrelations(rels);
	printf("\n");

	if (argc == 2)
	{
		showreach(pack, rels);
		return 0;
	}

	for (i = 2; i < argc; i++)
	{
		printf("part %s\n", argv[i]);

		s = sa_typepart(pack, argv[i]);
		if (!s)
			printf("has no type!\n");
		else
			printf("type %s\n", s);

		error = sa_loadrelations(&rels, pack, argv[i]);
		if (error)
			fz_abort(error);
		sa_debugrelations(rels);
		sa_droprelations(rels);

		printf("\n");
	}

	sa_closepackage(pack);

	return 0;
}

int runzip(int argc, char **argv)
{
	fz_error *error;
	fz_buffer *buf;
	fz_stream *stm;
	sa_zip *zip;
	int i, n;

	error = sa_openzip(&zip, argv[1]);
	if (error)
		fz_abort(error);

	if (argc == 2)
		sa_debugzip(zip);

	for (i = 2; i < argc; i++)
	{
		error = sa_openzipentry(&stm, zip, argv[i]);
		if (error)
			fz_abort(error);
		n = fz_readall(&buf, stm);
		if (n < 0)
			fz_abort(fz_ioerror(stm));
		fz_dropstream(stm);

		fwrite(buf->rp, 1, buf->wp - buf->rp, stdout);

		fz_dropbuffer(buf);
	}

	sa_closezip(zip);
	
	return 0;
}

int runxml(int argc, char **argv)
{
	fz_error *error;
	fz_stream *file;
	sa_xmlparser *parser;
	sa_xmlitem *item;

	error = fz_openrfile(&file, argv[1]);
	if (error)
		fz_abort(error);

	error = sa_openxml(&parser, file, 0);
	if (error)
		fz_abort(error);

	item = sa_xmlnext(parser);
	if (item)
		sa_debugxml(item, 0);

	sa_closexml(parser);
	fz_dropstream(file);

	return 0;
}

extern fz_error *sa_readtiff(fz_stream *);

int runtiff(int argc, char **argv)
{
	fz_error *error;
	fz_stream *file;

	error = fz_openrfile(&file, argv[1]);
	if (error)
		fz_abort(error);

	error = sa_readtiff(file);
	if (error)
		fz_abort(error);

	fz_dropstream(file);

	return 0;
}

int main(int argc, char **argv)
{
	if (argc >= 2)
	{
		if (strstr(argv[1], "zip"))
			return runzip(argc, argv);
		if (strstr(argv[1], "xml"))
			return runxml(argc, argv);
		if (strstr(argv[1], "tif"))
			return runtiff(argc, argv);
		return runpack(argc, argv);
	}

	fprintf(stderr, "usage: samshow <file>\n");
	fprintf(stderr, "usage: samshow <zipfile> <partname>\n");
	fprintf(stderr, "usage: samshow <package> <partname>\n");
	return 1;
}

