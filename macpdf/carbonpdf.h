#include <Carbon/Carbon.h>

#include <fitz.h>
#include <mupdf.h>

typedef struct viewctx
{
    WindowRef window;
    HIViewRef view;
    char *doctitle;
	
    float zoom;
    int rotate;
    int pageno;

    pdf_page *page;
    fz_obj *pageobj;

    pdf_xref *xref;
    pdf_pagetree *pages;
    pdf_outline *outline;
    fz_renderer *rast;
    fz_pixmap *image;
} viewctx;

OSStatus view_register(void);

OSStatus
view_openpdf(HIViewRef view, char *filename);

OSStatus view_showpage(HIViewRef view);
