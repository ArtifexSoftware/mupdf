#include <fitz.h>
#include <mupdf.h>
#include "pdfapp.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <commdlg.h>
#include <shellapi.h>

#define ID_ABOUT	0x1000
#define ID_DOCINFO	0x1001

static HWND hwnd = NULL;
static HDC hdc;
static HBRUSH bgbrush;
static HBRUSH shbrush;
static BITMAPINFO *dibinf;
static TCHAR szAppName[] = TEXT("fzview");
static HCURSOR arrowcurs, handcurs, waitcurs;
static LRESULT CALLBACK windproc(HWND, UINT, WPARAM, LPARAM);

static int bmpstride = 0;
static char *bmpdata = NULL;
static int justcopied = 0;

static pdfapp_t gapp;

/*
 * Associate FzView with PDF files.
 */

void associate(char *argv0)
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

	if (RegSetValueEx(key, "", 0, REG_SZ, "FzView", strlen("FzView")+1))
		return;

	RegCloseKey(key);

	/* HKEY_CLASSES_ROOT\FzView */

	if (RegCreateKeyEx(HKEY_CLASSES_ROOT,
				"FzView", 0, NULL, REG_OPTION_NON_VOLATILE,
				KEY_WRITE, NULL, &key, &disp))
		return;

	if (RegSetValueEx(key, "", 0, REG_SZ, name, strlen(name)+1))
		return;

	/* HKEY_CLASSES_ROOT\FzView\DefaultIcon */

	if (RegCreateKeyEx(key,
				"DefaultIcon", 0, NULL, REG_OPTION_NON_VOLATILE,
				KEY_WRITE, NULL, &kicon, &disp))
		return;

	sprintf(tmp, "%s,1", argv0);
	if (RegSetValueEx(kicon, "", 0, REG_SZ, tmp, strlen(tmp)+1))
		return;

	RegCloseKey(kicon);

	/* HKEY_CLASSES_ROOT\FzView\Shell\Open\Command */

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

void winwarn(pdfapp_t *app, char *msg)
{
	MessageBoxA(hwnd, msg, "FzView: Warning", MB_ICONWARNING);
}

void winerror(pdfapp_t *app, char *msg)
{
	MessageBoxA(hwnd, msg, "FzView: Error", MB_ICONERROR);
	exit(1);
}

int winfilename(char *buf, int len)
{
    OPENFILENAME ofn;
	strcpy(buf, "");
    memset(&ofn, 0, sizeof(OPENFILENAME));
    ofn.lStructSize = sizeof(OPENFILENAME);
    ofn.hwndOwner = hwnd;
    ofn.lpstrFile = buf;
    ofn.nMaxFile = len;
    ofn.lpstrInitialDir = NULL;
    ofn.lpstrTitle = "FzView: Open PDF file";
	ofn.lpstrFilter = "PDF Files (*.pdf)\0*.pdf\0All Files\0*\0\0";
    ofn.Flags = OFN_FILEMUSTEXIST|OFN_HIDEREADONLY;
    return GetOpenFileName(&ofn);
}

static char pd_filename[256] = "The file is encrypted.";
static char pd_password[256] = "";
static int pd_okay = 0;

INT CALLBACK
dlogpassproc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam)
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

char *winpassword(pdfapp_t *app, char *filename)
{
	char buf[124], *s;
	strcpy(buf, filename);
	s = buf;
	if (strrchr(s, '\\')) s = strrchr(s, '\\') + 1;
	if (strrchr(s, '/')) s = strrchr(s, '/') + 1;
	if (strlen(s) > 32)
		strcpy(s + 30, "...");
	sprintf(pd_filename, "The file \"%s\" is encrypted.", s);
	DialogBox(NULL, "IDD_DLOGPASS", hwnd, dlogpassproc);
	if (pd_okay)
		return pd_password;
	return NULL;
}

INT CALLBACK
dloginfoproc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam)
{
	char buf[256];
	pdf_xref *xref = gapp.xref;
	fz_obj *obj;

	switch(message)
	{
	case WM_INITDIALOG:
		
		SetDlgItemTextA(hwnd, 0x10, gapp.filename);

		sprintf(buf, "PDF %g", xref->version);
		SetDlgItemTextA(hwnd, 0x11, buf);

		if (xref->crypt)
		{
			sprintf(buf, "Standard %d bit RC4", xref->crypt->n * 8);
			SetDlgItemTextA(hwnd, 0x12, buf);
			strcpy(buf, "");
			if (xref->crypt->p & (1 << 2))
				strcat(buf, "print, ");
			if (xref->crypt->p & (1 << 3))
				strcat(buf, "modify, ");
			if (xref->crypt->p & (1 << 4))
				strcat(buf, "copy, ");
			if (xref->crypt->p & (1 << 5))
				strcat(buf, "annotate, ");
			if (strlen(buf) > 2)
				buf[strlen(buf)-2] = 0;
			else
				strcpy(buf, "none");
			SetDlgItemTextA(hwnd, 0x13, buf);
		}
		else
		{
			SetDlgItemTextA(hwnd, 0x12, "None");
			SetDlgItemTextA(hwnd, 0x13, "n/a");
		}

		if (!xref->info)
			return TRUE;

		#define SETUCS(ID) \
		{ \
			fz_error *error; \
			unsigned short *ucs; \
			error = pdf_toucs2(&ucs, obj); \
			if (!error) \
			{ \
				SetDlgItemTextW(hwnd, ID, ucs); \
				fz_free(ucs); \
			} \
		}

		if ((obj = fz_dictgets(xref->info, "Title")))		SETUCS(0x20)
		if ((obj = fz_dictgets(xref->info, "Author")))		SETUCS(0x21)
		if ((obj = fz_dictgets(xref->info, "Subject")))		SETUCS(0x22)
		if ((obj = fz_dictgets(xref->info, "Keywords")))	SETUCS(0x23)
		if ((obj = fz_dictgets(xref->info, "Creator"))) 	SETUCS(0x24)
		if ((obj = fz_dictgets(xref->info, "Producer")))	SETUCS(0x25)
		if ((obj = fz_dictgets(xref->info, "CreationDate"))) SETUCS(0x26)
		if ((obj = fz_dictgets(xref->info, "ModDate")))		SETUCS(0x27)

		return TRUE;

	case WM_COMMAND:
		EndDialog(hwnd, 0);
		return TRUE;
	}
	return FALSE;
}

void info()
{
	DialogBox(NULL, "IDD_DLOGINFO", hwnd, dloginfoproc);
}

INT CALLBACK
dlogaboutproc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam)
{
	switch(message)
	{
	case WM_INITDIALOG:
		SetDlgItemTextA(hwnd, 0x10, gapp.filename);
		SetDlgItemTextA(hwnd, 2, "FzView is Copyright (C) 2005 artofcode, LLC");
		SetDlgItemTextA(hwnd, 3, pdfapp_usage(&gapp));
		return TRUE;
	case WM_COMMAND:
		EndDialog(hwnd, 0);
		return TRUE;
	}
	return FALSE;
}

void help()
{
	DialogBox(NULL, "IDD_DLOGABOUT", hwnd, dlogaboutproc);
}

/*
 * Main window
 */

void winopen()
{
	WNDCLASS wc;
	HMENU menu;
	RECT r;

	/* Create and register window class */
	wc.style = CS_HREDRAW | CS_VREDRAW | CS_OWNDC;
	wc.lpfnWndProc = windproc;
	wc.cbClsExtra = 0;
	wc.cbWndExtra = 0;
	wc.hInstance = GetModuleHandle(NULL);
	wc.hIcon = LoadIcon(wc.hInstance, "IDI_ICONAPP");
	wc.hCursor = NULL; //LoadCursor(NULL, IDC_ARROW);
	wc.hbrBackground = NULL;//(HBRUSH) GetStockObject(BLACK_BRUSH);
	wc.lpszMenuName = NULL;
	wc.lpszClassName = szAppName;
	assert(RegisterClass(&wc) && "Register window class");

	/* Get screen size */
	SystemParametersInfo(SPI_GETWORKAREA, 0, &r, 0);
	gapp.scrw = r.right - r.left;
	gapp.scrh = r.bottom - r.top;

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

	SetWindowTextA(hwnd, "FzView");

	menu = GetSystemMenu(hwnd, 0);
	AppendMenu(menu, MF_SEPARATOR, 0, NULL);
	AppendMenu(menu, MF_STRING, ID_ABOUT, "About FzView...");
	AppendMenu(menu, MF_STRING, ID_DOCINFO, "Document Properties...");

	SetCursor(arrowcurs);
}

void wincursor(pdfapp_t *app, int curs)
{
	if (curs == ARROW)
		SetCursor(arrowcurs);
	if (curs == HAND)
		SetCursor(handcurs);
	if (curs == WAIT)
		SetCursor(waitcurs);
}

void wintitle(pdfapp_t *app, char *title)
{
	unsigned short wide[256], *dp;
	char *sp;
	int rune;

	dp = wide;
	sp = title;
	while (*sp && dp < wide + 255)
	{
		sp += chartorune(&rune, sp);
		*dp++ = rune;
	}
	*dp = 0;

	SetWindowTextW(hwnd, wide);
}

void winconvert(pdfapp_t *app, fz_pixmap *image)
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

void invertcopyrect(void)
{
	int x0 = gapp.selr.x0 - gapp.panx;
	int x1 = gapp.selr.x1 - gapp.panx;
	int y0 = gapp.selr.y0 - gapp.pany;
	int y1 = gapp.selr.y1 - gapp.pany;
	int x, y;

	x0 = CLAMP(x0, 0, gapp.image->w - 1);
	x1 = CLAMP(x1, 0, gapp.image->w - 1);
	y0 = CLAMP(y0, 0, gapp.image->h - 1);
	y1 = CLAMP(y1, 0, gapp.image->h - 1);

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

	justcopied = 1;
}

void winblit()
{
	int x0 = gapp.panx;
	int y0 = gapp.pany;
	int x1 = gapp.panx + gapp.image->w;
	int y1 = gapp.pany + gapp.image->h;
	RECT r;

	if (bmpdata)
	{
		if (gapp.iscopying || justcopied)
			invertcopyrect();

		dibinf->bmiHeader.biWidth = gapp.image->w;
		dibinf->bmiHeader.biHeight = -gapp.image->h;
		dibinf->bmiHeader.biSizeImage = gapp.image->h * bmpstride;
		SetDIBitsToDevice(hdc,
				gapp.panx, /* destx */
				gapp.pany, /* desty */
				gapp.image->w, /* destw */
				gapp.image->h, /* desth */
				0, /* srcx */
				0, /* srcy */
				0, /* startscan */
				gapp.image->h, /* numscans */
				bmpdata, /* pBits */
				dibinf, /* pInfo */
				DIB_RGB_COLORS /* color use flag */
				);

		if (gapp.iscopying || justcopied)
			invertcopyrect();
	}

	/* Grey background */
	r.top = 0; r.bottom = gapp.winh;
	r.left = 0; r.right = x0;
	FillRect(hdc, &r, bgbrush);
	r.left = x1; r.right = gapp.winw;
	FillRect(hdc, &r, bgbrush);
	r.left = 0; r.right = gapp.winw;
	r.top = 0; r.bottom = y0;
	FillRect(hdc, &r, bgbrush);
	r.top = y1; r.bottom = gapp.winh;
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

void winresize(pdfapp_t *app, int w, int h)
{
	ShowWindow(hwnd, SW_SHOWDEFAULT);
	w += GetSystemMetrics(SM_CXFRAME) * 2;
	h += GetSystemMetrics(SM_CYFRAME) * 2;
	h += GetSystemMetrics(SM_CYCAPTION);
	SetWindowPos(hwnd, 0, 0, 0, w, h, SWP_NOZORDER | SWP_NOMOVE);
}

void winrepaint(pdfapp_t *app)
{
	InvalidateRect(hwnd, NULL, 0);
}

/*
 * Event handling
 */

void windocopy(pdfapp_t *app)
{
	HGLOBAL handle;
	unsigned short *ucsbuf;

	if (!OpenClipboard(hwnd))
		return;
	EmptyClipboard();

	handle = GlobalAlloc(GMEM_MOVEABLE, 4096 * sizeof(unsigned short));
	if (!handle)
	{
		CloseClipboard();
		return;
	}

	ucsbuf = GlobalLock(handle);
	pdfapp_oncopy(&gapp, ucsbuf, 4096);
	GlobalUnlock(handle);

	SetClipboardData(CF_UNICODETEXT, handle);
	CloseClipboard();

	justcopied = 1;	/* keep inversion around for a while... */
}

void winopenuri(pdfapp_t *app, char *buf)
{
	ShellExecute(hwnd, "open", buf, 0, 0, SW_SHOWNORMAL);
}

void handlekey(int c)
{
	if (GetCapture() == hwnd)
		return;

	if (justcopied)
	{
		justcopied = 0;
		winrepaint(&gapp);
	}

	/* translate VK into ascii equivalents */
	switch (c)
	{
	case VK_F1: c = '?'; break;
	case VK_ESCAPE: c = 'q'; break;
	case VK_DOWN: c = 'd'; break;
	case VK_UP: c = 'u'; break;
	case VK_LEFT: c = 'p'; break;
	case VK_RIGHT: c = 'n'; break;
	case VK_PRIOR: c = 'b'; break;
	case VK_NEXT: c = ' '; break;
	}

	if (c == 'q')
		exit(0);
	else if (c == '?' || c == 'h')
		help();
	else 
		pdfapp_onkey(&gapp, c);
}

void handlemouse(int x, int y, int btn, int state)
{
	if (state != 0 && justcopied)
	{
		justcopied = 0;
		winrepaint(&gapp);
	}

	if (state == 1)
		SetCapture(hwnd);
	if (state == -1)
		ReleaseCapture();

	pdfapp_onmouse(&gapp, x, y, btn, 0, state);
}

LRESULT CALLBACK
windproc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam)
{
	static int oldx = 0;
	static int oldy = 0;
	int x = (signed short) LOWORD(lParam);
	int y = (signed short) HIWORD(lParam);

	switch (message)
	{
	case WM_CREATE:
		return 0;

	case WM_DESTROY:
	case WM_CLOSE:
		PostQuitMessage(0);
		return 0;

	case WM_SYSCOMMAND:
		if (wParam == ID_ABOUT)
		{
			help();
			return 0;
		}
		if (wParam == ID_DOCINFO)
		{
			info();
			return 0;
		}
		break;

	case WM_SIZE:
		if (wParam == SIZE_MINIMIZED)
			return 0;
		if (wParam == SIZE_MAXIMIZED)
			gapp.shrinkwrap = 0;
		pdfapp_onresize(&gapp, LOWORD(lParam), HIWORD(lParam));
		return 0;

	case WM_SIZING:
		gapp.shrinkwrap = 0;
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
		SetFocus(hwnd);
		oldx = x; oldy = y;
		handlemouse(x, y, 1, 1);
		return 0;
	case WM_MBUTTONDOWN:
		SetFocus(hwnd);
		oldx = x; oldy = y;
		handlemouse(x, y, 2, 1);
		return 0;
	case WM_RBUTTONDOWN:
		SetFocus(hwnd);
		oldx = x; oldy = y;
		handlemouse(x, y, 3, 1);
		return 0;

	case WM_LBUTTONUP:
		oldx = x; oldy = y;
		handlemouse(x, y, 1, -1);
		return 0;
	case WM_MBUTTONUP:
		oldx = x; oldy = y;
		handlemouse(x, y, 2, -1);
		return 0;
	case WM_RBUTTONUP:
		oldx = x; oldy = y;
		handlemouse(x, y, 3, -1);
		return 0;

	case WM_MOUSEMOVE:
		oldx = x; oldy = y;
		handlemouse(x, y, 0, 0);
		return 0;

	/* Mouse wheel */
	case WM_MOUSEWHEEL:
		if ((signed short)HIWORD(wParam) > 0)
			handlekey(LOWORD(wParam) & MK_SHIFT ? '+' : 'u');
		else
			handlekey(LOWORD(wParam) & MK_SHIFT ? '-' : 'd');
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

int main(int argc, char **argv)
{
	char buf[1024];
	char *filename;

	fz_cpudetect();
	fz_accelerate();

	pdfapp_init(&gapp);

	associate(argv[0]);
	winopen();

	if (argc == 2)
		filename = strdup(argv[1]);
	else
	{
		if (!winfilename(buf, sizeof buf))
			exit(0);
		filename = buf;
	}

	pdfapp_open(&gapp, filename);

	MSG msg;
	while (GetMessage(&msg, NULL, 0, 0))
	{
		TranslateMessage(&msg);
		DispatchMessage(&msg);
	}

	pdfapp_close(&gapp);

	return 0;
}

