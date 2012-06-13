#include "fitz.h"
#include "mupdf.h"
#include "muxps.h"
#include "mucbz.h"
#include "pdfapp.h"
#include <ctype.h>

static pdfapp_t gapp;
static int file_open = 0;
static char filename[1024] = "";
static char *scriptname;
static char *output;
static int shotcount = 0;

static char getline_buffer[1024];

void winwarn(pdfapp_t *app, char *msg)
{
	fprintf(stderr, "warning: %s", msg);
}

void winerror(pdfapp_t *app, char *msg)
{
	fprintf(stderr, msg);
	exit(1);
}

static char pd_filename[256] = "The file is encrypted.";
static char pd_password[256] = "";
static char td_textinput[1024] = "";
static int pd_okay = 0;

char *winpassword(pdfapp_t *app, char *filename)
{
	if (pd_password[0] == 0)
		return NULL;
	return pd_password;
}

char *wintextinput(pdfapp_t *app, char *inittext)
{
	if (td_textinput[0] != 0)
		return td_textinput;
	return inittext;
}

void winhelp(pdfapp_t*app)
{
}

void winclose(pdfapp_t *app)
{
	pdfapp_close(app);
	exit(0);
}

void wincursor(pdfapp_t *app, int curs)
{
}

void wintitle(pdfapp_t *app, char *title)
{
}

void windrawrect(pdfapp_t *app, int x0, int y0, int x1, int y1)
{
}

void windrawstring(pdfapp_t *app, int x, int y, char *s)
{
}

void winresize(pdfapp_t *app, int w, int h)
{
}

void winrepaint(pdfapp_t *app)
{
}

void winrepaintsearch(pdfapp_t *app)
{
}

void winfullscreen(pdfapp_t *app, int state)
{
}

/*
 * Event handling
 */

void windocopy(pdfapp_t *app)
{
}

void winreloadfile(pdfapp_t *app)
{
	pdfapp_close(app);
	pdfapp_open(app, filename, 1);
}

void winopenuri(pdfapp_t *app, char *buf)
{
}

static void
usage(void)
{
	fprintf(stderr, "mujstest: Scriptable tester for mupdf + js\n");
	fprintf(stderr, "\nSyntax: mujstest -o <filename> <scriptfile>\n");
	fprintf(stderr, "\n<filename> should sensibly be of the form file-%d.png\n");
	fprintf(stderr, "\nscriptfile contains a list of commands:\n");
	fprintf(stderr, "\tPASSWORD <password>\tSet the password\n");
	fprintf(stderr, "\tOPEN <filename>\tOpen a file\n");
	fprintf(stderr, "\tGOTO <page>\tJump to a particular page\n");
	fprintf(stderr, "\tSCREENSHOT\tSave a screenshot\n");
	fprintf(stderr, "\tRESIZE <w> <h>\tResize the screen to a given size\n");
	fprintf(stderr, "\tCLICK <x> <y> <btn>\tClick at a given position\n");
	fprintf(stderr, "\tTEXT <string>\tSet a value to be entered\n");
	exit(1);
}

static char *
getline(FILE *file)
{
	char c;
	char *d = getline_buffer;

	/* Skip over any prefix of whitespace */
	do
	{
		c = fgetc(file);
	}
	while (isspace(c));

	if (c < 0)
		return NULL;

	do
	{
		*d++ = c;
		c = fgetc(file);
	}
	while (c >= 32);

	*d = 0;

	return getline_buffer;
}

static int
match(char **line, const char *match)
{
	char *s = *line;

	if (s == NULL)
		return 0;

	while (isspace(*s))
		s++;

	while (*s == *match)
	{
		s++;
		match++;
	}

	if (*match != 0)
		return 0;

	/* We matched! Skip over any whitespace */
	while (isspace(*s))
		s++;

	*line = s;

	/* Trim whitespace off the end of the line */
	/* Run to the end of the line */
	while (*s)
		s++;

	/* Run back until we find where we started, or non whitespace */
	while (s != *line && isspace(s[-1]))
		s--;

	/* Remove the suffix of whitespace */
	*s = 0;

	return 1;
}

int
main(int argc, char *argv[])
{
	fz_context *ctx;
	FILE *script = NULL;
	int c;

	while ((c = fz_getopt(argc, argv, "o:")) != -1)
	{
		switch(c)
		{
		case 'o': output = fz_optarg; break;
		default: usage(); break;
		}
	}

	if (fz_optind == argc)
		usage();

	ctx = fz_new_context(NULL, NULL, FZ_STORE_DEFAULT);
	if (!ctx)
	{
		fprintf(stderr, "cannot initialise context\n");
		exit(1);
	}
	pdfapp_init(ctx, &gapp);
	gapp.scrw = 640;
	gapp.scrh = 480;

	fz_try(ctx)
	{
		while (fz_optind < argc)
		{
			scriptname = argv[fz_optind++];
			script = fopen(scriptname, "rb");
			if (script == NULL)
				fz_throw(ctx, "cannot open script: %s", scriptname);

			do
			{
				char *line = getline(script);
				if (match(&line, "%"))
				{
					/* Comment */
				}
				else if (match(&line, "PASSWORD"))
				{
					strcpy(pd_password, line);
				}
				else if (match(&line, "OPEN"))
				{
					if (file_open)
						pdfapp_close(&gapp);
					strcpy(filename, line);
					pdfapp_open(&gapp, line, 0);
					file_open = 1;
				}
				else if (match(&line, "GOTO"))
				{
					pdfapp_gotopage(&gapp, atoi(line)-1);
				}
				else if (match(&line, "SCREENSHOT"))
				{
					char text[1024];

					sprintf(text, output, ++shotcount);
					fz_write_png(ctx, gapp.image, text, 0);
				}
				else if (match(&line, "RESIZE"))
				{
					int w, h;
					sscanf(line, "%d %d", &w, &h);
					pdfapp_onresize(&gapp, w, h);
				}
				else if (match(&line, "CLICK"))
				{
					float x, y, b;
					int n;
					n = sscanf(line, "%f %f %d", &x, &y, &b);
					if (n < 1)
						x = 0.0f;
					if (n < 2)
						y = 0.0f;
					if (n < 3)
						b = 1;
					/* state = 1 = transition down */
					pdfapp_onmouse(&gapp, (int)x, (int)y, b, 0, 1);
					/* state = -1 = transition up */
					pdfapp_onmouse(&gapp, (int)x, (int)y, b, 0, -1);
				}
				else if (match(&line, "TEXT"))
				{
					strcpy(td_textinput, line);
				}
			}
			while (!feof(script));

			fclose(script);
		}
	}
	fz_catch(ctx)
	{
		fprintf(stderr, "error: cannot execute '%s'\n", scriptname);
	}

	if (file_open)
		pdfapp_close(&gapp);

	return 0;
}
