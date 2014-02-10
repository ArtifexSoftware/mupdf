#include "munet.h"
#include <strsafe.h>
#include "muctx.h"

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}

std::shared_ptr<std::vector<sh_content>> gContents;

char* String_to_char(PCWSTR text)
{
	int cb = WideCharToMultiByte(CP_UTF8, 0, text, -1, nullptr, 0, nullptr, nullptr);
	char* charout = new char[cb];
	if (!charout)
	{
		return nullptr;
	}
	WideCharToMultiByte(CP_UTF8, 0, text, -1, charout, cb, nullptr, nullptr);
	return charout;
}

PCWSTR char_to_String(const char *char_in)
{
	size_t size = MultiByteToWideChar(CP_UTF8, 0, char_in, -1, NULL, 0);
	wchar_t *pw;
	pw = new wchar_t[size];
	if (!pw)
	{
		return nullptr;
	}
	MultiByteToWideChar(CP_UTF8, 0, char_in, -1, pw, size);
	return pw;
}

/* We have to have a C-Style API to access the C++ code */
SYMBOL_DECLSPEC void* __stdcall mInitialize()
{
	muctx *mu_ctx = new muctx;
	status_t result = mu_ctx->InitializeContext();

	if (result == S_ISOK)
		return static_cast<void*>(mu_ctx);
	else
		return nullptr;
}

SYMBOL_DECLSPEC int __stdcall mOpenDocument(void *ctx, PCWSTR filename)
{
	muctx *mu_ctx = static_cast<muctx*>(ctx);

	mReleaseContents();
	return mu_ctx->OpenDocument(String_to_char(filename));
}

SYMBOL_DECLSPEC void __stdcall mCleanUp(void *ctx)
{
	muctx *mu_ctx = static_cast<muctx*>(ctx);

	mReleaseContents();
	mu_ctx->CleanUp();
}

SYMBOL_DECLSPEC int __stdcall mGetPageCount(void *ctx)
{
	muctx *mu_ctx = static_cast<muctx*>(ctx);
	return mu_ctx->GetPageCount();
}

SYMBOL_DECLSPEC bool __stdcall mRequiresPassword(void *ctx)
{
	muctx *mu_ctx = static_cast<muctx*>(ctx);
	return mu_ctx->RequiresPassword();
}

SYMBOL_DECLSPEC bool __stdcall mApplyPassword(void *ctx, PCWSTR password)
{
	muctx *mu_ctx = static_cast<muctx*>(ctx);
	return mu_ctx->ApplyPassword(String_to_char(password));
}

SYMBOL_DECLSPEC int __stdcall mRenderPage(void *ctx, int page_num,
	byte* bmp_data, int bmp_width,
	int bmp_height, double scale, bool flipy)
{
	muctx *mu_ctx = static_cast<muctx*>(ctx);
	int code = mu_ctx->RenderPage(page_num, &(bmp_data[0]), bmp_width,
		bmp_height, scale, flipy);

	return code;
}

SYMBOL_DECLSPEC int __stdcall mMeasurePage(void *ctx, int page_num,
	double *width, double *height)
{
	muctx *mu_ctx = static_cast<muctx*>(ctx);
	point_t size;

	int code = mu_ctx->MeasurePage(page_num, &size);
	*width = size.X;
	*height = size.Y;

	return code;
}

SYMBOL_DECLSPEC int __stdcall mGetContents(void *ctx)
{
	muctx *mu_ctx = static_cast<muctx*>(ctx);
	int has_content;
	sh_vector_content content_smart_ptr_vec(new std::vector<sh_content>());
	gContents = content_smart_ptr_vec;
	has_content = mu_ctx->GetContents(gContents);
	if (has_content)
		return gContents->size();
	else
		return 0;
}

SYMBOL_DECLSPEC void __stdcall mReleaseContents()
{
	if (gContents != nullptr)
		gContents.reset();
}

SYMBOL_DECLSPEC char* __stdcall mGetContentsItem(int k, int *len, int *page)
{
	char* retstr = NULL;

	sh_content muctx_content = gContents->at(k);
	const char* str = (muctx_content->string_margin.c_str());
	*len = strlen(str);
	*page = muctx_content->page;

	/* This allocation ensures that Marshal will release in the managed code */
	retstr = (char*)::CoTaskMemAlloc(*len + 1);
	strcpy(retstr, str);
	return retstr;
}

SYMBOL_DECLSPEC void* __stdcall mCreateDisplayList(void *ctx, int page_num,
	int *page_width, int *page_height)
{
	muctx *mu_ctx = static_cast<muctx*>(ctx);
	return (void*)mu_ctx->CreateDisplayList(page_num, page_width, page_height);
}

SYMBOL_DECLSPEC int __stdcall mRenderPageMT(void *ctx, void *dlist,
	int page_width, int page_height, byte *bmp_data, int bmp_width,
	int bmp_height, double scale, bool flipy)
{
	muctx *mu_ctx = static_cast<muctx*>(ctx);

	return (int) mu_ctx->RenderPageMT(dlist, page_width, page_height,
		&(bmp_data[0]), bmp_width, bmp_height,
		scale, flipy, false, { 0, 0 }, { 0, 0 });
}
