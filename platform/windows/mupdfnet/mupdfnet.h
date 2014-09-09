
#pragma once

#include <windows.h>
#include<string>
using namespace std;

#ifdef __cplusplus
#define EXTERNC extern "C"
#else
#define EXTERNC
#endif

typedef struct sharp_content_s
{
	int page;
	PCWSTR string_margin;
} sharp_content_t;

#define SYMBOL_DECLSPEC __declspec(dllexport)

EXTERN_C SYMBOL_DECLSPEC void* __stdcall mInitialize();
EXTERN_C SYMBOL_DECLSPEC void __stdcall mCleanUp(void *ctx);
EXTERN_C SYMBOL_DECLSPEC int __stdcall mGetPageCount(void *ctx);
EXTERN_C SYMBOL_DECLSPEC bool __stdcall mRequiresPassword(void *ctx);
EXTERN_C SYMBOL_DECLSPEC bool __stdcall mApplyPassword(void *ctx, PCWSTR password);
EXTERN_C SYMBOL_DECLSPEC int __stdcall mOpenDocument(void *ctx, PCWSTR filename);
EXTERN_C SYMBOL_DECLSPEC int __stdcall mMeasurePage(void *ctx, int page_num, double *width, double *height);
EXTERN_C SYMBOL_DECLSPEC int __stdcall mRenderPage(void *ctx, int page_num,
										byte *bmp_data, int bmp_width,
										int bmp_height, double scale, bool flipy);
EXTERN_C SYMBOL_DECLSPEC int __stdcall mGetContents(void *ctx);
EXTERN_C SYMBOL_DECLSPEC char* __stdcall mGetContentsItem(int k, int *len, int *page);
EXTERN_C SYMBOL_DECLSPEC void __stdcall mReleaseContents();
EXTERN_C SYMBOL_DECLSPEC int __stdcall mTextSearchPage(void *ctx, int page_num, PCWSTR needle);
EXTERN_C SYMBOL_DECLSPEC bool __stdcall mGetTextSearchItem(int k, double *top_x, double
	*top_y, double *height, double *width);
EXTERN_C SYMBOL_DECLSPEC void __stdcall mReleaseTextSearch();
EXTERN_C SYMBOL_DECLSPEC char* __stdcall mGetVers();
EXTERN_C SYMBOL_DECLSPEC char * __stdcall mGetText(void *ctx, int pagenum, int type);

EXTERN_C SYMBOL_DECLSPEC int __stdcall mGetLinksPage(void *ctx, int page_num);
EXTERN_C SYMBOL_DECLSPEC char* __stdcall mGetLinkItem(int k, double *top_x, double
	*top_y, double *height, double *width, int *topage, int *type);
EXTERN_C SYMBOL_DECLSPEC void __stdcall mReleaseLink();

EXTERN_C SYMBOL_DECLSPEC void* __stdcall mCreateDisplayList(void *ctx, int page_num,
	int *page_width, int *page_height);
EXTERN_C SYMBOL_DECLSPEC void* __stdcall mCreateDisplayListText(void *ctx, int page_num,
	int *page_width, int *page_height, void **textptr, int *length);
EXTERN_C SYMBOL_DECLSPEC void* __stdcall mCreateDisplayListAnnot(void *ctx, 
	int page_num);

EXTERN_C SYMBOL_DECLSPEC int __stdcall mRenderPageMT(void *ctx, void *dlist,
	void *annot_dlist, int page_width, int page_height, byte *bmp_data, int bmp_width,
	int bmp_height, double scale, bool flipy);

EXTERN_C SYMBOL_DECLSPEC int __stdcall mGetTextBlock(void *text, int block_num,
	double *top_x, double *top_y, double *height, double *width);

EXTERN_C SYMBOL_DECLSPEC int __stdcall mGetTextLine(void *text, int block_num, 
	int line_num, double *top_x, double *top_y, double *height, double *width);

EXTERN_C SYMBOL_DECLSPEC int __stdcall mGetTextCharacter(void *text, int block_num, 
	int line_num, int item_num, double *top_x, double *top_y, double *height, 
	double *width);

EXTERN_C SYMBOL_DECLSPEC void __stdcall mReleaseText(void *ctx, void *page);

EXTERN_C SYMBOL_DECLSPEC void __stdcall mSetAA(void *ctx, int level);

/* pdfclean methods */
EXTERN_C SYMBOL_DECLSPEC int __stdcall mExtractPages(PCWSTR infile, PCWSTR outfile,
    PCWSTR password, bool has_password, bool linearize, int num_pages, void *pages);
/* output */
EXTERN_C SYMBOL_DECLSPEC int __stdcall mSavePage(void *ctx, PCWSTR outfile, int page_num,
	int resolution, int type, bool append);
