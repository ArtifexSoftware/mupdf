/*
 * Interactive features
 */

typedef struct pdf_link_s pdf_link;
typedef struct pdf_comment_s pdf_comment;
typedef struct pdf_widget_s pdf_widget;

typedef enum pdf_linkkind_e
{
	PDF_LGOTO,
	PDF_LURI
} pdf_linkkind;

struct pdf_link_s
{
	pdf_linkkind kind;
	fz_rect rect;
	fz_obj *page;
	fz_obj *uri;
	int ismap;
	pdf_link *next;
};

typedef enum pdf_commentkind_e
{
	PDF_CTEXT,
	PDF_CFREETEXT,
	PDF_CLINE,
	PDF_CSQUARE,
	PDF_CCIRCLE,
	PDF_CPOLYGON,
	PDF_CPOLYLINE,
	PDF_CMARKUP,
	PDF_CCARET,
	PDF_CSTAMP,
	PDF_CINK
} pdf_commentkind;

struct pdf_comment_s
{
	pdf_commentkind kind;
	fz_rect rect;
	fz_rect popup;
	fz_obj *contents;
	pdf_comment *next;
};

fz_error * pdf_newlink(pdf_link**, fz_rect rect, int ismap, fz_obj *page, fz_obj *uri);
void pdf_droplink(pdf_link *link);

fz_error *pdf_loadannots(pdf_comment **, pdf_link **, pdf_xref *, fz_obj *annots);

