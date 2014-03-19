
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
EXTERN_C SYMBOL_DECLSPEC void* __stdcall mCreateDisplayList(void *ctx, int page_num,
	int *page_width, int *page_height);
EXTERN_C SYMBOL_DECLSPEC int __stdcall mRenderPageMT(void *ctx, void *dlist,
	int page_width, int page_height, byte *bmp_data, int bmp_width,
	int bmp_height, double scale, bool flipy);

