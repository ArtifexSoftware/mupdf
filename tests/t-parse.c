#include <fitz.h>

int
main(int argc, char **argv)
{
	fz_error *err;
	fz_obj *obj;
	int i;

	if (argc == 1)
	{
		err = fz_packobj(&obj,
			"[ %s %r [ %i ] "
			"<< /Float %f /BinString %# /Name %n /Int %i >> "
			"(foo) /bar 3223 [ [ 1 2 3 %i ] %i [ 23 ] %i ]",
			"Hello, world",
				3, 0,
				42,
				23.5,
				"f\0obar", 4,
				"Foo",
				666,
				-1, -2 , -3
			);
		if (err) fz_abort(err);

		printf("pretty:  "); fz_fprintobj(stdout, obj); printf("\n");
		printf("comapct: "); fz_fprintcobj(stdout, obj); printf("\n");
		fz_dropobj(obj);
		printf("\n");
	}

	for (i = 1; i < argc; i++) {
		err = fz_parseobj(&obj, argv[i]);
		if (err) fz_abort(err);
		printf("pretty:  "); fz_fprintobj(stdout, obj); printf("\n");
		printf("compact: "); fz_fprintcobj(stdout, obj); printf("\n");
		fz_dropobj(obj);
		printf("\n");
	}

	return 0;
}

