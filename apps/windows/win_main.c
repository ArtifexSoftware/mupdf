#include <fitz.h>
#include <mupdf.h>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <commdlg.h>

static HWND hwnd = NULL;
static HDC hdc;
static BITMAPINFO *dibinf;
static TCHAR szAppName[] = TEXT("mupdf");
static HCURSOR arrowcurs, handcurs, waitcurs;
static LRESULT CALLBACK windproc(HWND, UINT, WPARAM, LPARAM);

static char *doctitle = "<untitled>";
static float zoom = 1.0;
static int rotate = 0;
static int pageno = 1;
static int count = 0;

static char *password = "";
static char *filename = "";

static pdf_page *page = nil;
static fz_obj *pageobj = nil;

static int hist[256];
static int histlen = 0;

/* for 123G commands */
static unsigned char pagebuf[256];
static int pagebufidx = 0;

static pdf_xref *xref;
static pdf_pagetree *pages;
static pdf_outline *outline;
static fz_renderer *rast;
static fz_pixmap *image;

#define fz_abort(eo) winabort(eo->msg)

int getfilename(char *buf, int len)
{
    OPENFILENAME ofn;
	strcpy(buf, "");
    memset(&ofn, 0, sizeof(OPENFILENAME));
    ofn.lStructSize = sizeof(OPENFILENAME);
    ofn.hwndOwner = hwnd;
    ofn.lpstrFile = buf;
    ofn.nMaxFile = len;
    ofn.lpstrInitialDir = NULL;
    ofn.lpstrTitle = "GhostPDF: Open PDF file";
	ofn.lpstrFilter = "PDF Files (*.pdf)\0*.pdf\0All Files\0*\0\0";
    ofn.Flags = OFN_FILEMUSTEXIST|OFN_HIDEREADONLY;
    return GetOpenFileName(&ofn);
}

static char pd_filename[256] = "The file is encrypted.";
static char pd_password[256] = "";
static int pd_okay = 0;

INT CALLBACK
dlogproc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam)
{
	switch(message)
	{
	case WM_INITDIALOG:
		SetDlgItemText(hwnd, 4, pd_filename);
		return TRUE;
	case WM_COMMAND:
		switch(wParam)
		{
		case 1:
			pd_okay = 1;
			GetDlgItemText(hwnd, 3, pd_password, sizeof pd_password);
			EndDialog(hwnd, 0);
			return TRUE;
		case 2:
			pd_okay = 0;
			EndDialog(hwnd, 0);
			return TRUE;
		}
		break;
	}
	return FALSE;
}

char *getpassword(void)
{
	char buf[124], *s;
	strcpy(buf, filename);
	s = buf;
	if (strrchr(s, '\\')) s = strrchr(s, '\\') + 1;
	if (strrchr(s, '/')) s = strrchr(s, '/') + 1;
	if (strlen(s) > 32)
		strcpy(s + 30, "...");
	sprintf(pd_filename, "The file \"%s\" is encrypted.", s);
	DialogBox(NULL, "IDD_DLOGPASS", hwnd, dlogproc);
	if (pd_okay)
		return pd_password;
	return NULL;
}

void help()
{
	char *msg = \
		"ghostpdf [-b] [-pzr page/zoom/rotate] [-u password] file.pdf\n\n"
		/*"key commands:\n" */
		"    h\tdisplay this help\n"
		"    <\trotate left\n"
		"    >\trotate right\n"
		"    +\tzoom in\n"
		"    -\tzoom out\n"
		"    b\tgo back one page\n"
		"    B\tgo back ten pages\n"
		"    f\tgo forward one page\n"
		"    F\tgo forward ten pages\n"
		"    G\tgo to last page\n"
		"    m\tmark page for pop-back\n"
		"    t\tpop back to last mark\n"
		"    123g\tgo to page 123\n"
		"\nGhostPDF is Copyright (C) 2005 artofcode LLC\n"
		;
	MessageBoxA(hwnd, msg, "GhostPDF: Usage", MB_ICONINFORMATION);
}

void usage()
{
	help();
	exit(1);
}

void winwarn(const char *fmt, ...)
{
	char buf[1024];
	va_list ap;
	va_start(ap, fmt);
	vsprintf(buf, fmt, ap);
	va_end(ap);
	MessageBoxA(hwnd, buf, "GhostPDF: Warning", MB_ICONWARNING);
}

void winerror(const char *fmt, ...)
{
	char buf[1024];
	va_list ap;
	va_start(ap, fmt);
	vsprintf(buf, fmt, ap);
	va_end(ap);
	MessageBoxA(hwnd, buf, "GhostPDF: Error", MB_ICONERROR);
	exit(1);
}

void winabort(const char *msg)
{
	winerror("There was a problem with file \"%s\":\n\n%s\n", filename, msg);
}

void winopen()
{
	WNDCLASS wc;

	/* Create and register window class */
	wc.style = CS_HREDRAW | CS_VREDRAW | CS_OWNDC;
	wc.lpfnWndProc = windproc;
	wc.cbClsExtra = 0;
	wc.cbWndExtra = 0;
	wc.hInstance = GetModuleHandle(NULL);
	wc.hIcon = LoadIcon(wc.hInstance, "IDI_ICONGHOST");
	wc.hCursor = NULL; //LoadCursor(NULL, IDC_ARROW);
	wc.hbrBackground = NULL;//(HBRUSH) GetStockObject(BLACK_BRUSH);
	wc.lpszMenuName = NULL;
	wc.lpszClassName = szAppName;
	assert(RegisterClass(&wc) && "Register window class");

	/* Create cursors */
	arrowcurs = LoadCursor(NULL, IDC_ARROW);
	handcurs = LoadCursor(NULL, IDC_HAND);
	waitcurs = LoadCursor(NULL, IDC_WAIT);

	/* Init DIB info for buffer */
	dibinf = malloc(sizeof(BITMAPINFO) + 12);
	assert(dibinf != NULL);
	dibinf->bmiHeader.biSize = sizeof(dibinf->bmiHeader);
	dibinf->bmiHeader.biPlanes = 1;
	dibinf->bmiHeader.biBitCount = 24;
	dibinf->bmiHeader.biCompression = BI_RGB;
	dibinf->bmiHeader.biXPelsPerMeter = 2834;
	dibinf->bmiHeader.biYPelsPerMeter = 2834;
	dibinf->bmiHeader.biClrUsed = 0;
	dibinf->bmiHeader.biClrImportant = 0;
	dibinf->bmiHeader.biClrUsed = 0;

	/* Create window */
	hwnd = CreateWindow(szAppName, // window class name
						NULL, // window caption
						//WS_OVERLAPPEDWINDOW, // window style
						WS_CAPTION|WS_THICKFRAME|WS_SYSMENU|WS_MINIMIZEBOX,
						CW_USEDEFAULT, // initial x position
						5, // CW_USEDEFAULT, // initial y position
						300, // initial x size
						300, // initial y size
						NULL, // parent window handle
						NULL, // window menu handle
						0,//hInstance, // program instance handle
						NULL); // creation parameters

	hdc = NULL;

	SetWindowTextA(hwnd, "GhostPDF");

	SetCursor(arrowcurs);
}

void winblit()
{
	/* TODO: repack image in windows format */
	int stride = ((image->w * 3 + 3) / 4) * 4;
	char *buf;
	char *s;
	char *p;
	int y, x;

	buf = fz_malloc(image->h * stride);
	if (!buf)
		return;

	for (y = 0; y < image->h; y++)
	{
		p = buf + y * stride;
		s = image->samples + y * image->w * 4;
		for (x = 0; x < image->w; x++)
		{
			p[x * 3 + 0] = s[x * 4 + 3];
			p[x * 3 + 1] = s[x * 4 + 2];
			p[x * 3 + 2] = s[x * 4 + 1];
		}
	}

	dibinf->bmiHeader.biWidth = image->w;
	dibinf->bmiHeader.biHeight = -image->h;
	dibinf->bmiHeader.biSizeImage = image->h * stride;

	assert(hdc != NULL);
	SetDIBitsToDevice(hdc,
					  0, /* destx */
					  0, /* desty */
					  image->w, /* destw */
					  image->h, /* desth */
					  0, /* srcx */
					  0, /* srcy */
					  0, /* startscan */
					  image->h, /* numscans */
					  buf, /* pBits */
					  dibinf, /* pInfo */
					  DIB_RGB_COLORS /* color use flag */
					 );

	fz_free(buf);
}

void winresize(int w, int h)
{
	ShowWindow(hwnd, SW_SHOWDEFAULT);
	w += GetSystemMetrics(SM_CXFRAME) * 2;
	h += GetSystemMetrics(SM_CYFRAME) * 2;
	h += GetSystemMetrics(SM_CYCAPTION);
	SetWindowPos(hwnd, 0, 0, 0, w, h, SWP_NOZORDER | SWP_NOMOVE);
}

void winrepaint(void)
{
	RECT wr = (RECT){0, 0, image->w, image->h};
	InvalidateRect(hwnd, &wr, 0);
}

void dragndrop()
{
	SetCapture(hwnd);
	ReleaseCapture();
}

static void showpage(void)
{
	fz_error *error;
	fz_matrix ctm;
	fz_rect bbox;
	fz_obj *obj;

	assert(pageno > 0 && pageno <= pdf_getpagecount(pages));

	SetCursor(waitcurs);

	if (image)
		fz_droppixmap(image);
	image = nil;

	obj = pdf_getpageobject(pages, pageno - 1);
	if (obj == pageobj)
		goto Lskipload;
	pageobj = obj;

	if (page)
		pdf_droppage(page);

	error = pdf_loadpage(&page, xref, pageobj);
	if (error)
		fz_abort(error);

Lskipload:

	ctm = fz_identity();
	ctm = fz_concat(ctm, fz_translate(0, -page->mediabox.max.y));
	ctm = fz_concat(ctm, fz_scale(zoom, -zoom));
	ctm = fz_concat(ctm, fz_rotate(rotate + page->rotate));

	bbox = fz_transformaabb(ctm, page->mediabox);

	error = fz_rendertree(&image, rast, page->tree, ctm, fz_roundrect(bbox), 1);
	if (error)
		fz_abort(error);

	SetCursor(arrowcurs);
	{
		char buf[512];
		sprintf(buf, "%s - %d/%d", doctitle, pageno, count);
		SetWindowTextA(hwnd, buf);
	}

	winresize(image->w, image->h);
	winrepaint();
}

static void pdfopen(void)
{
	fz_error *error;
	fz_obj *obj;

	error = pdf_newxref(&xref);
	if (error)
		fz_abort(error);

	error = pdf_loadxref(xref, filename);
	if (error)
	{
		if (!strncmp(error->msg, "ioerror", 7))
			fz_abort(error);
		winwarn(
			"There was a problem with file \"%s\".\n"
			"It may be corrupted, or generated by broken software.\n\n"
			"%s\n\nTrying to continue anyway...",
				filename, error->msg);
		error = pdf_repairxref(xref, filename);
		if (error)
			fz_abort(error);
	}

	error = pdf_decryptxref(xref);
	if (error)
		fz_abort(error);

	if (xref->crypt)
	{
		error = pdf_setpassword(xref->crypt, password);
		while (error)
		{
			fz_droperror(error);
			password = getpassword();
			if (!password)
				exit(1);
			error = pdf_setpassword(xref->crypt, password);
			if (error)
				winwarn("Invalid password.");
		}
	}

	obj = fz_dictgets(xref->trailer, "Root");
	if (!obj)
		fz_abort(fz_throw("syntaxerror: missing Root object"));
	error = pdf_loadindirect(&xref->root, xref, obj);
	if (error) fz_abort(error);

	obj = fz_dictgets(xref->trailer, "Info");
	if (obj)
	{
		error = pdf_loadindirect(&xref->info, xref, obj);
		if (error) fz_abort(error);
	}

	error = pdf_loadnametrees(xref);
	if (error) fz_abort(error);

	error = pdf_loadoutline(&outline, xref);
	if (error) fz_abort(error);

	doctitle = filename;
	if (strrchr(doctitle, '\\')) doctitle = strrchr(doctitle, '\\') + 1;
	if (strrchr(doctitle, '/')) doctitle = strrchr(doctitle, '/') + 1;
	if (xref->info)
	{
		obj = fz_dictgets(xref->info, "Title");
		if (obj)
		{
			error = pdf_toutf8(&doctitle, obj);
			if (error) fz_abort(error);
		}
	}

//	if (outline)
//		pdf_debugoutline(outline, 0);

	error = pdf_loadpagetree(&pages, xref);
	if (error) fz_abort(error);

	count = pdf_getpagecount(pages);

	error = fz_newrenderer(&rast, pdf_devicergb, 0, 1024 * 512);
	if (error) fz_abort(error);

	image = nil;
}

static void dumptext()
{
	fz_error *error;
	pdf_textline *line;

	error = pdf_loadtextfromtree(&line, page->tree);
	if (error)
		fz_abort(error);

	pdf_debugtextline(line);

	pdf_droptextline(line);
}

static void gotouri(fz_obj *uri)
{
	char cmd[2048];
	char buf[2048];

	memcpy(buf, fz_tostrbuf(uri), fz_tostrlen(uri));
	buf[fz_tostrlen(uri)] = 0;

	if (getenv("BROWSER"))
		sprintf(cmd, "$BROWSER %s &", buf);
	else
		sprintf(cmd, "start %s", buf);
	system(cmd);
}

static void gotopage(fz_obj *obj)
{
	int oid = fz_tonum(obj);
	int i;

	for (i = 0; i < count; i++)
	{
		if (fz_tonum(pages->pref[i]) == oid)
		{
			if (histlen + 1 == 256)
			{
				memmove(hist, hist + 1, sizeof(int) * 255);
				histlen --;
			}
			hist[histlen++] = pageno;
			pageno = i + 1;
			showpage();
			return;
		}
	}
}

static void handlekey(int c)
{
	int oldpage = pageno;
	float oldzoom = zoom;
	int oldrotate = rotate;

	if (c >= '0' && c <= '9')
		pagebuf[pagebufidx++] = c;
	else
		if (c != 'g' && c != 'G')
			pagebufidx = 0;

	switch (c)
	{
	case VK_F1:
	case 'h':
		help();
		break;

	case 'd': fz_debugglyphcache(rast->cache); break;
	case 'a': rotate -= 5; break;
	case 's': rotate += 5; break;
//	case 'x': dumptext(); break;
//	case 'o': drawlinks(); break;

	case VK_LEFT:
	case VK_UP:
	case VK_PRIOR:
	case '\b':
	case 'b':
		pageno--;
		if (pageno < 1)
			pageno = 1;
		break;
	case 'B':
		pageno -= 10;
		if (pageno < 1)
			pageno = 1;
		break;
	case VK_RIGHT:
	case VK_DOWN:
	case VK_NEXT:
	case ' ':
	case 'f':
		pageno++;
		if (pageno > count)
			pageno = count;
		break;
	case 'F':
		pageno += 10;
		if (pageno > count)
			pageno = count;
		break;
	case 'm':
		if (histlen + 1 == 256)
		{
			memmove(hist, hist + 1, sizeof(int) * 255);
			histlen --;
		}
		hist[histlen++] = pageno;
		break;
	case 't':
	case 'T':
		if (histlen > 0)
			pageno = hist[--histlen];
		break;
	case '-':
		zoom -= 0.1;
		if (zoom < 0.1)
			zoom = 0.1;
		break;
	case '+':
		zoom += 0.1;
		if (zoom > 3.0)
			zoom = 3.0;
		break;
	case '<':
		rotate -= 90;
		break;
	case '>':
		rotate += 90;
		break;
	case VK_ESCAPE:
	case 'q':
		exit(0);
	case 'g':
	case 'G':
		if (pagebufidx > 0)
		{
			pagebuf[pagebufidx] = '\0';
			pageno = atoi(pagebuf);
			pagebufidx = 0;
			if (pageno < 1)
				pageno = 1;
			if (pageno > count)
				pageno = count;
		}
		else
		{
			if (c == 'G')
			{
				pageno = count;
			}
		}
		break;
	}

	if (pageno != oldpage || zoom != oldzoom || rotate != oldrotate)
		showpage();
}

static void handlemouse(int x, int y, int btn)
{
	pdf_link *link;
	fz_matrix ctm;
	fz_point p;

	p.x = x + image->x;
	p.y = y + image->y;

	ctm = fz_identity();
	ctm = fz_concat(ctm, fz_translate(0, -page->mediabox.max.y));
	ctm = fz_concat(ctm, fz_scale(zoom, -zoom));
	ctm = fz_concat(ctm, fz_rotate(rotate + page->rotate));
	ctm = fz_invertmatrix(ctm);

	p = fz_transformpoint(ctm, p);

	for (link = page->links; link; link = link->next)
	{
		if (p.x >= link->rect.min.x && p.x <= link->rect.max.x)
			if (p.y >= link->rect.min.y && p.y <= link->rect.max.y)
				break;
	}

	if (link)
	{
		SetCursor(handcurs);
		if (btn)
		{
			if (fz_isstring(link->dest))
				gotouri(link->dest);
			if (fz_isindirect(link->dest))
				gotopage(link->dest);
		}
	}
	else
	{
		SetCursor(arrowcurs);
	}
}

LRESULT CALLBACK
windproc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam)
{
	int x = (signed short) LOWORD(lParam);
	int y = (signed short) HIWORD(lParam);

	switch (message)
	{
	case WM_CREATE:
		//puts("WM_CREATE");
		return 0;

	case WM_DESTROY:
		//puts("WM_DESTROY");
		PostQuitMessage(0);
		return 0;

	case WM_CLOSE:
		//puts("WM_CLOSE");
		PostQuitMessage(0);
		return 0;

	case WM_KILLFOCUS:
		//puts("WM_KILLFOCUS");
		return 0;

	case WM_SIZING:
		//puts("WM_SIZING");
		return 0;

	/* Paint events are low priority and automagically catenated
	 * so we don't need to do any fancy waiting to defer repainting.
	 */
	case WM_PAINT:
	{
		//puts("WM_PAINT");
		PAINTSTRUCT ps;
		hdc = BeginPaint(hwnd, &ps);
		winblit();
		hdc = NULL;
		EndPaint(hwnd, &ps);
		return 0;
	}

	/* Mouse events */

	case WM_LBUTTONDOWN:
		//puts("WM_LBUTTONDOWN");
		handlemouse(x, y, 1);
		return 0;
	case WM_RBUTTONDOWN:
		//puts("WM_RBUTTONDOWN");
		handlemouse(x, y, 4);
		return 0;
	case WM_MBUTTONDOWN:
		//puts("WM_MBUTTONDOWN");
		handlemouse(x, y, 2);
		return 0;

	case WM_LBUTTONUP:
		//puts("WM_LBUTTONUP");
		handlemouse(x, y, 0);
		return 0;
	case WM_RBUTTONUP:
		//puts("WM_RBUTTONUP");
		handlemouse(x, y, 0);
		return 0;
	case WM_MBUTTONUP:
		//puts("WM_RBUTTONUP");
		handlemouse(x, y, 0);
		return 0;

	case WM_MOUSEMOVE:
		//puts("WM_MOUSEMOVE");
		handlemouse(x, y, 0);
		return 0;

	/* Mouse wheel */
	case WM_MOUSEWHEEL:
		if ((signed short)HIWORD(wParam) > 0) {
			// wheel-up
		}
		else {
			// wheel-down
		}
		return 0;

	/* Keyboard events */

	/* Only deal with key-down */
	case WM_KEYUP:
		return 0;
	case WM_SYSKEYUP:
		return 0;

	case WM_SYSCHAR:
		//printf("WM_SYSCHAR: %d '%c'\n", wParam, wParam);
		return 0;

	case WM_SYSKEYDOWN:
		//printf("WM_SYSKEYDOWN: %d '%c'\n", wParam, wParam);
		return 0;

	case WM_KEYDOWN:
		//printf("WM_KEYDOWN: %d '%c'\n", wParam, wParam); 
		/* only handle special keys */
		switch (wParam)
		{
		case VK_F1:
		case VK_LEFT:
		case VK_UP:
		case VK_PRIOR:
		case VK_RIGHT:
		case VK_DOWN:
		case VK_NEXT:
		case VK_ESCAPE:
			handlekey(wParam);
			return 0;
		}
		return 1;

	/* unicode encoded chars, including escape, backspace etc... */
	case WM_CHAR:
		//printf("WM_CHAR: %d '%c'\n", wParam, wParam);
		handlekey(wParam);
		return 0;
	}

	fflush(stdout);

	/* Pass on unhandled events to Windows */
	return DefWindowProc(hwnd, message, wParam, lParam);
}

int main(int argc, char **argv)
{
	char buf[1024];
	int c;

	int benchmark = 0;

	while ((c = getopt(argc, argv, "hbz:r:p:u:")) != -1)
	{
		switch (c)
		{
		case 'b': ++benchmark; break;
		case 'u': password = optarg; break;
		case 'p': pageno = atoi(optarg); break;
		case 'z': zoom = atof(optarg); break;
		case 'r': rotate = atoi(optarg); break;
		case 'h': help(); break;
		default: help(); exit(1); break;
		}
	}

	winopen();

	if (argc - optind == 0)
	{
		if (!getfilename(buf, sizeof buf))
		{
			help();
			exit(0);
		}
		filename = buf;
	}
	else
		filename = argv[optind++];

	fz_cpudetect();
	fz_accelerate();

	pdfopen();

	showpage();

	if (benchmark)
	{
		while (pageno < count)
		{
			pageno ++;
			showpage();
		}
		return 0;
	}

	MSG msg;
	while (GetMessage(&msg, NULL, 0, 0))
	{
		TranslateMessage(&msg);
		DispatchMessage(&msg);
	}

	pdf_closexref(xref);

	return 0;
}

