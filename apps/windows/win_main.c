#include <fitz.h>
#include <mupdf.h>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <commdlg.h>
#include <shellapi.h>

#define fz_abort(eo) winabort(eo->msg)

void showpage(void);

static HWND hwnd = NULL;
static HDC hdc;
static HBRUSH bgbrush;
static HBRUSH shbrush;
static BITMAPINFO *dibinf;
static TCHAR szAppName[] = TEXT("ghostpdf");
static HCURSOR arrowcurs, handcurs, waitcurs;
static LRESULT CALLBACK windproc(HWND, UINT, WPARAM, LPARAM);
static int winwidth = 0;
static int winheight = 0;

static int ispanning = 0;
static int oldx = 0, oldy = 0;
static int iscopying = 0;
static RECT copyrect;
static int firstx = 0, firsty = 0;

static int bmpstride = 0;
static char *bmpdata = NULL;

static int screenwidth = 640;
static int screenheight = 480;
static int shrinkwrap = 1;
static int panx = 0;
static int pany = 0;

static char *password = "";
static char *filename = "";
static char *doctitle = "<untitled>";
static float zoom = 1.0;
static int rotate = 0;
static int pageno = 1;
static int count = 0;

static pdf_page *page = nil;
static fz_obj *pageobj = nil;

static int hist[256];
static int histlen = 0;

static unsigned char pagebuf[256];
static int pagebufidx = 0;

static pdf_xref *xref;
static pdf_pagetree *pages;
static pdf_outline *outline;
static fz_renderer *rast;
static fz_pixmap *image;

/*
 * Associate GhostPDF with PDF files.
 */

void associateme(char *argv0)
{
	char tmp[256];
	char *name = "Adobe PDF Document";
	HKEY key, kicon, kshell, kopen, kcmd;
	DWORD disp;

	/* HKEY_CLASSES_ROOT\.pdf */

	if (RegCreateKeyEx(HKEY_CLASSES_ROOT,
				".pdf", 0, NULL, REG_OPTION_NON_VOLATILE,
				KEY_WRITE, NULL, &key, &disp))
		return;

	if (RegSetValueEx(key, "", 0, REG_SZ, "GhostPDF", strlen("GhostPDF")+1))
		return;

	RegCloseKey(key);

	/* HKEY_CLASSES_ROOT\GhostPDF */

	if (RegCreateKeyEx(HKEY_CLASSES_ROOT,
				"GhostPDF", 0, NULL, REG_OPTION_NON_VOLATILE,
				KEY_WRITE, NULL, &key, &disp))
		return;

	if (RegSetValueEx(key, "", 0, REG_SZ, name, strlen(name)+1))
		return;

	/* HKEY_CLASSES_ROOT\GhostPDF\DefaultIcon */

	if (RegCreateKeyEx(key,
				"DefaultIcon", 0, NULL, REG_OPTION_NON_VOLATILE,
				KEY_WRITE, NULL, &kicon, &disp))
		return;

	sprintf(tmp, "%s,1", argv0);
	if (RegSetValueEx(kicon, "", 0, REG_SZ, tmp, strlen(tmp)+1))
		return;

	RegCloseKey(kicon);

	/* HKEY_CLASSES_ROOT\GhostPDF\Shell\Open\Command */

	if (RegCreateKeyEx(key,
				"shell", 0, NULL, REG_OPTION_NON_VOLATILE,
				KEY_WRITE, NULL, &kshell, &disp))
		return;
	if (RegCreateKeyEx(kshell,
				"open", 0, NULL, REG_OPTION_NON_VOLATILE,
				KEY_WRITE, NULL, &kopen, &disp))
		return;
	if (RegCreateKeyEx(kopen,
				"command", 0, NULL, REG_OPTION_NON_VOLATILE,
				KEY_WRITE, NULL, &kcmd, &disp))
		return;

	sprintf(tmp, "\"%s\" \"%%1\"", argv0);
	if (RegSetValueEx(kcmd, "", 0, REG_SZ, tmp, strlen(tmp)+1))
		return;

	RegCloseKey(kcmd);
	RegCloseKey(kopen);
	RegCloseKey(kshell);

	RegCloseKey(key);
}

/*
 * Dialog boxes
 */

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
	char msg[1024];
	sprintf(msg,
"GhostPDF v%0.2f -- %s\n\n"
"   l <\t\t-- rotate left\n"
"   r >\t\t-- rotate right\n"
"   u up\t\t-- scroll up\n"
"   d down\t\t-- scroll down\n"
"   = +\t\t-- zoom in\n"
"   -\t\t-- zoom out\n"
"   w\t\t-- shrinkwrap\n"
"\n"
"   n pgdn space\t-- next page\n"
"   b pgup back\t-- previous page\n"
"   right\t\t-- next page\n"
"   left\t\t-- previous page\n"
"   N F\t\t-- next 10\n"
"   B\t\t-- back 10\n"
"   m\t\t-- mark page for snap back\n"
"   t\t\t-- pop back to last mark\n"
"   123g\t\t-- go to page\n"
"\n"
"   left drag to pan, right drag to copy text\n"
	    , PDF_VERSION / 100.0, PDF_COPYRIGHT);
	MessageBoxA(hwnd, msg, "GhostPDF: Usage", MB_ICONINFORMATION);
}

void usage()
{
	help();
	exit(1);
}

/*
 * Main window
 */

void winopen()
{
	WNDCLASS wc;
	RECT r;

	/* Create and register window class */
	wc.style = CS_HREDRAW | CS_VREDRAW | CS_OWNDC;
	wc.lpfnWndProc = windproc;
	wc.cbClsExtra = 0;
	wc.cbWndExtra = 0;
	wc.hInstance = GetModuleHandle(NULL);
	wc.hIcon = LoadIcon(wc.hInstance, "IDI_ICONAPPL");
	wc.hCursor = NULL; //LoadCursor(NULL, IDC_ARROW);
	wc.hbrBackground = NULL;//(HBRUSH) GetStockObject(BLACK_BRUSH);
	wc.lpszMenuName = NULL;
	wc.lpszClassName = szAppName;
	assert(RegisterClass(&wc) && "Register window class");

	/* Get screen size */
	SystemParametersInfo(SPI_GETWORKAREA, 0, &r, 0);
	screenwidth = r.right - r.left;
	screenheight = r.bottom - r.top;

	/* Create cursors */
	arrowcurs = LoadCursor(NULL, IDC_ARROW);
	handcurs = LoadCursor(NULL, IDC_HAND);
	waitcurs = LoadCursor(NULL, IDC_WAIT);

	/* And a background color */
	bgbrush = CreateSolidBrush(RGB(0x70,0x70,0x70));
	shbrush = CreateSolidBrush(RGB(0x40,0x40,0x40));

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
						WS_OVERLAPPEDWINDOW,
						5, //CW_USEDEFAULT, // initial x position
						5, //CW_USEDEFAULT, // initial y position
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

void winconvertimage()
{
	int y, x;

	if (bmpdata)
		fz_free(bmpdata);

	bmpstride = ((image->w * 3 + 3) / 4) * 4;
	bmpdata = fz_malloc(image->h * bmpstride);
	if (!bmpdata)
		return;

	for (y = 0; y < image->h; y++)
	{
		char *p = bmpdata + y * bmpstride;
		char *s = image->samples + y * image->w * 4;
		for (x = 0; x < image->w; x++)
		{
			p[x * 3 + 0] = s[x * 4 + 3];
			p[x * 3 + 1] = s[x * 4 + 2];
			p[x * 3 + 2] = s[x * 4 + 1];
		}
	}
}

void invertcopyrect()
{
	int x0 = copyrect.left - panx;
	int x1 = copyrect.right - panx;
	int y0 = copyrect.top - pany;
	int y1 = copyrect.bottom - pany;
	int x, y;

	x0 = CLAMP(x0, 0, image->w - 1);
	x1 = CLAMP(x1, 0, image->w - 1);
	y0 = CLAMP(y0, 0, image->h - 1);
	y1 = CLAMP(y1, 0, image->h - 1);

	unsigned char *p;
	for (y = y0; y < y1; y++)
	{
		p = bmpdata + y * bmpstride + x0 * 3;
		for (x = x0; x < x1; x++)
		{
			p[0] = 255 - p[0];
			p[1] = 255 - p[1];
			p[2] = 255 - p[2];
			p += 3;
		}
	}
}

void winblit()
{
	int x0 = panx;
	int y0 = pany;
	int x1 = panx + image->w;
	int y1 = pany + image->h;
	RECT r;

	if (bmpdata)
	{
		if (iscopying)
			invertcopyrect();
		dibinf->bmiHeader.biWidth = image->w;
		dibinf->bmiHeader.biHeight = -image->h;
		dibinf->bmiHeader.biSizeImage = image->h * bmpstride;
		SetDIBitsToDevice(hdc,
				panx, /* destx */
				pany, /* desty */
				image->w, /* destw */
				image->h, /* desth */
				0, /* srcx */
				0, /* srcy */
				0, /* startscan */
				image->h, /* numscans */
				bmpdata, /* pBits */
				dibinf, /* pInfo */
				DIB_RGB_COLORS /* color use flag */
				);
		if (iscopying)
			invertcopyrect();
	}

	/* Grey background */
	r.top = 0; r.bottom = winheight;
	r.left = 0; r.right = x0;
	FillRect(hdc, &r, bgbrush);
	r.left = x1; r.right = winwidth;
	FillRect(hdc, &r, bgbrush);
	r.left = 0; r.right = winwidth;
	r.top = 0; r.bottom = y0;
	FillRect(hdc, &r, bgbrush);
	r.top = y1; r.bottom = winheight;
	FillRect(hdc, &r, bgbrush);

	/* Drop shadow */
	r.left = x0 + 2;
	r.right = x1 + 2;
	r.top = y1;
	r.bottom = y1 + 2;
	FillRect(hdc, &r, shbrush);
	r.left = x1;
	r.right = x1 + 2;
	r.top = y0 + 2;
	r.bottom = y1;
	FillRect(hdc, &r, shbrush);
}

void winresize(int w, int h)
{
	if (w > screenwidth * 95 / 100)
		w = screenwidth * 95 / 100;
	if (h > screenheight * 95 / 100)
		h = screenheight * 95 / 100;
	ShowWindow(hwnd, SW_SHOWDEFAULT);
	w += GetSystemMetrics(SM_CXFRAME) * 2;
	h += GetSystemMetrics(SM_CYFRAME) * 2;
	h += GetSystemMetrics(SM_CYCAPTION);
	SetWindowPos(hwnd, 0, 0, 0, w, h, SWP_NOZORDER | SWP_NOMOVE);
}

void winrepaint(void)
{
	InvalidateRect(hwnd, NULL, 0);
}

void dragndrop()
{
	SetCapture(hwnd);
	ReleaseCapture();
}

/*
 * Event handling
 */

fz_matrix makectm(void)
{
	fz_matrix ctm;
	ctm = fz_identity();
	ctm = fz_concat(ctm, fz_translate(0, -page->mediabox.max.y));
	ctm = fz_concat(ctm, fz_scale(zoom, -zoom));
	ctm = fz_concat(ctm, fz_rotate(rotate + page->rotate));
	return ctm;
}

void constrainpan(int *panx, int *pany)
{
	int newx = *panx;
	int newy = *pany;

	if (newx > 0)
		newx = 0;
	if (newx + image->w < winwidth)
		newx = winwidth - image->w;
	if (newy > 0)
		newy = 0;
	if (newy + image->h < winheight)
		newy = winheight - image->h;
	if (winwidth >= image->w)
		newx = (winwidth - image->w) / 2;
	if (winheight >= image->h)
		newy = (winheight - image->h) / 2;

	*panx = newx;
	*pany = newy;
}

void handlecopy()
{
#define BUFLEN 4096
	HGLOBAL handle;
	unsigned short *ucsbuf;
	fz_error *error;
	pdf_textline *line, *ln;
	int x, y, c;
	int i, p;

	int x0 = image->x + copyrect.left - panx;
	int x1 = image->x + copyrect.right - panx;
	int y0 = image->y + copyrect.top - pany;
	int y1 = image->y + copyrect.bottom - pany;

	if (!OpenClipboard(hwnd))
		return;
	EmptyClipboard();

	handle = GlobalAlloc(GMEM_MOVEABLE, BUFLEN * sizeof(unsigned short));
	if (!handle)
	{
		CloseClipboard();
		return;
	}

	ucsbuf = GlobalLock(handle);

	error = pdf_loadtextfromtree(&line, page->tree, makectm());
	if (error)
		fz_abort(error);

	p = 0;
	for (ln = line; ln; ln = ln->next)
	{
		y = y0 - 1;
		for (i = 0; i < ln->len; i++)
		{
			x = ln->text[i].x;
			y = ln->text[i].y;
			c = ln->text[i].c;
			if (c < 32)
				c = '?';
			if (x >= x0 && x <= x1 && y >= y0 && y <= y1)
				if (p < BUFLEN - 1)
					ucsbuf[p++] = c;
		}

		if (y >= y0 && y <= y1)
		{
			if (p < BUFLEN - 1)
				ucsbuf[p++] = '\r';
			if (p < BUFLEN - 1)
				ucsbuf[p++] = '\n';
		}
	}

	ucsbuf[p] = 0;

	pdf_droptextline(line);

	GlobalUnlock(handle);

	SetClipboardData(CF_UNICODETEXT, handle);

	CloseClipboard();
}

void gotouri(fz_obj *uri)
{
	char buf[2048];

	memcpy(buf, fz_tostrbuf(uri), fz_tostrlen(uri));
	buf[fz_tostrlen(uri)] = 0;

	ShellExecute(hwnd, "open", buf, 0, 0, SW_SHOWNORMAL);
}

void gotopage(fz_obj *obj)
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

void handlekey(int c)
{
	int oldpage = pageno;
	float oldzoom = zoom;
	int oldrotate = rotate;
	int panto = 0; /* 0 = top, 1 = bottom, 2 = leave alone */

	/*
	 * Save numbers typed for later
	 */

	if (c >= '0' && c <= '9')
		pagebuf[pagebufidx++] = c;
	else
		if (c != 'g' && c != 'G')
			pagebufidx = 0;

	switch (c)
	{

	/*
	 * Help and quit
	 */

	case VK_F1:
	case 'h':
	case '?':
		help();
		break;

	case VK_ESCAPE:
	case 'q':
		exit(0);
		break;

	/*
	 * Zoom and rotate
	 */

	case '+': case '=':
		zoom += 0.1;
		if (zoom > 3.0)
			zoom = 3.0;
		break;
	case '-':
		zoom -= 0.1;
		if (zoom < 0.1)
			zoom = 0.1;
		break;
	case 'l': case '<':
		rotate -= 90;
		break;
	case 'r': case '>':
		rotate += 90;
		break;

	case 'w':
		shrinkwrap = 1;
		panx = pany = 0;
		winresize(image->w, image->h);
		break;

	/*
	 * Pan view, but dont change page
	 */

	case 'd': case VK_DOWN:
		pany -= image->h / 10;
		constrainpan(&panx, &pany);
		winrepaint();
		break;

	case 'u': case VK_UP:
		pany += image->h / 10;
		constrainpan(&panx, &pany);
		winrepaint();
		break;

	case ',':
		panx += image->w / 10;
		constrainpan(&panx, &pany);
		winrepaint();
		break;

	case '.':
		panx -= image->w / 10;
		constrainpan(&panx, &pany);
		winrepaint();
		break;

	/*
	 * Page navigation
	 */

	case 'g':
	case '\n':
	case '\r':
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
		break;

	case 'G':
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
		if (histlen > 0)
			pageno = hist[--histlen];
		break;

	/*
	 * Back and forth ...
	 */

	case VK_LEFT:
		panto = 2;
		pageno--;
		if (pageno < 1)
			pageno = 1;
		break;

	case VK_PRIOR: case '\b': case 'b':
		panto = 1;
		pageno--;
		if (pageno < 1)
			pageno = 1;
		break;

	case VK_RIGHT:
		panto = 2;
	case VK_NEXT: case ' ': case 'f': case 'n':
		pageno++;
		if (pageno > count)
			pageno = count;
		break;

	case 'B':
		pageno -= 10;
		if (pageno < 1)
			pageno = 1;
		break;

	case 'F': case 'N':
		pageno += 10;
		if (pageno > count)
			pageno = count;
		break;
	}

	if (pageno != oldpage || zoom != oldzoom || rotate != oldrotate)
	{
		switch (panto)
		{
		case 0: pany = 0; break;
		case 1: pany = -2000; break;
		case 2: break;
		}
		showpage();
		constrainpan(&panx, &pany);
	}
}

void handlemouse(int x, int y, int btn, int state)
{
	pdf_link *link;
	fz_matrix ctm;
	fz_point p;

	p.x = x - panx + image->x;
	p.y = y - pany + image->y;

	ctm = makectm();
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
		if (btn == 1 && state == 1)
		{
			if (fz_isstring(link->dest))
				gotouri(link->dest);
			if (fz_isindirect(link->dest))
				gotopage(link->dest);
			return;
		}
	}
	else
	{
		SetCursor(arrowcurs);
	}

	if (state == 1)
	{
		SetCapture(hwnd);
		if (btn == 1 && !iscopying)
			ispanning = 1;
		if (btn == 3 && !ispanning)
		{
			iscopying = 1;
			firstx = x;
			firsty = y;
			copyrect.left = x;
			copyrect.right = x;
			copyrect.top = y;
			copyrect.bottom = y;
		}
	}

	else if (state == -1)
	{
		ReleaseCapture();
		if (iscopying)
		{
			copyrect.left = MIN(firstx, x);
			copyrect.right = MAX(firstx, x);
			copyrect.top = MIN(firsty, y);
			copyrect.bottom = MAX(firsty, y);
			handlecopy();
			winrepaint();
		}
		ispanning = 0;
		iscopying = 0;
	}

	else if (ispanning)
	{
		int newx = panx + x - oldx;
		int newy = pany + y - oldy;

		constrainpan(&newx, &newy);

		if (panx != newx || pany != newy)
		{
			panx = newx;
			pany = newy;
			winrepaint();
		}
	}

	else if (iscopying)
	{
		copyrect.left = MIN(firstx, x);
		copyrect.right = MAX(firstx, x);
		copyrect.top = MIN(firsty, y);
		copyrect.bottom = MAX(firsty, y);
		winrepaint();
	}

	oldx = x;
	oldy = y;
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

	case WM_SIZE:
		if (wParam == SIZE_MINIMIZED)
			return 0;
		if (wParam == SIZE_MAXIMIZED)
			shrinkwrap = 0;
		winwidth = LOWORD(lParam);
		winheight = HIWORD(lParam);
		constrainpan(&panx, &pany);
		winrepaint();
		return 0;

	case WM_SIZING:
		shrinkwrap = 0;
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
		handlemouse(x, y, 1, 1);
		return 0;
	case WM_MBUTTONDOWN:
		//puts("WM_MBUTTONDOWN");
		handlemouse(x, y, 2, 1);
		return 0;
	case WM_RBUTTONDOWN:
		//puts("WM_RBUTTONDOWN");
		handlemouse(x, y, 3, 1);
		return 0;

	case WM_LBUTTONUP:
		//puts("WM_LBUTTONUP");
		handlemouse(x, y, 1, -1);
		return 0;
	case WM_MBUTTONUP:
		//puts("WM_RBUTTONUP");
		handlemouse(x, y, 2, -1);
		return 0;
	case WM_RBUTTONUP:
		//puts("WM_RBUTTONUP");
		handlemouse(x, y, 3, -1);
		return 0;

	case WM_MOUSEMOVE:
		//puts("WM_MOUSEMOVE");
		handlemouse(x, y, 0, 0);
		return 0;

	/* Mouse wheel */
	case WM_MOUSEWHEEL:
		if ((signed short)HIWORD(wParam) > 0)
			handlekey('u');
		else
			handlekey('d');
		return 0;

	/* Keyboard events */

	case WM_KEYDOWN:
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
			handlemouse(oldx, oldy, 0, 0);	/* update cursor */
			return 0;
		}
		return 1;

	/* unicode encoded chars, including escape, backspace etc... */
	case WM_CHAR:
		handlekey(wParam);
		handlemouse(oldx, oldy, 0, 0);	/* update cursor */
		return 0;
	}

	fflush(stdout);

	/* Pass on unhandled events to Windows */
	return DefWindowProc(hwnd, message, wParam, lParam);
}

/*
 * Draw page, init and main stuff
 */

void showpage(void)
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

	winconvertimage();

	SetCursor(arrowcurs);
	{
		char buf[512];
		sprintf(buf, "%s - %d/%d", doctitle, pageno, count);
		SetWindowTextA(hwnd, buf);
	}

	if (shrinkwrap)
	{
		if (winwidth == image->w)
			panx = 0;
		if (winheight == image->h)
			pany = 0;
		winresize(image->w, image->h);
	}
	else
		constrainpan(&panx, &pany);

	winrepaint();
}

void pdfopen(void)
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

int main(int argc, char **argv)
{
	char buf[1024];
	int c;

	int benchmark = 0;

	associateme(argv[0]);

	while ((c = getopt(argc, argv, "bz:r:p:u:")) != -1)
	{
		switch (c)
		{
		case 'b': ++benchmark; break;
		case 'u': password = optarg; break;
		case 'p': pageno = atoi(optarg); break;
		case 'z': zoom = atof(optarg); break;
		case 'r': rotate = atoi(optarg); break;
		default: help(); exit(1); break;
		}
	}

	winopen();

	if (argc - optind == 0)
	{
		if (!getfilename(buf, sizeof buf))
			exit(0);
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

	pdf_dropstore(xref->store);
	xref->store = nil;

	pdf_closexref(xref);

	return 0;
}

