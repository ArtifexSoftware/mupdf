#include "mupdfnet.h"
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
std::shared_ptr<std::vector<sh_text>> gTextResults;
std::shared_ptr<std::vector<sh_link>> gLinkResults;

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

SYMBOL_DECLSPEC char * __stdcall mGetText(void *ctx, int pagenum, int type)
{
	char* retstr = NULL;
	muctx *mu_ctx = static_cast<muctx*>(ctx);
	std::string text_cstr;
	int len;

	text_cstr = mu_ctx->GetText(pagenum, type);
	if (text_cstr.size() > 0)
	{
		auto text = text_cstr.c_str();
		len = strlen(text);
		retstr = (char*)::CoTaskMemAlloc(len + 1);
		strcpy(retstr, text);
	}
	return retstr;
}

SYMBOL_DECLSPEC int __stdcall mTextSearchPage(void *ctx, int page_num, PCWSTR needle)
{
	muctx *mu_ctx = static_cast<muctx*>(ctx);

	sh_vector_text text_smart_ptr_vec(new std::vector<sh_text>());
	gTextResults = text_smart_ptr_vec;
	
	return mu_ctx->GetTextSearch(page_num, String_to_char(needle), gTextResults);
}

SYMBOL_DECLSPEC bool __stdcall mGetTextSearchItem(int k, double *top_x, double
	*top_y, double *height, double *width)
{
	char* retstr = NULL;

	if (k < 0 || k > gTextResults->size())
		return false;
	sh_text muctx_search = gTextResults->at(k);
	*top_x = muctx_search->upper_left.X;
	*top_y = muctx_search->upper_left.Y;
	*width = muctx_search->lower_right.X - muctx_search->upper_left.X;
	*height = muctx_search->lower_right.Y - muctx_search->upper_left.Y;
	return true;
}

SYMBOL_DECLSPEC void __stdcall mReleaseTextSearch()
{
	if (gTextResults != nullptr)
		gTextResults.reset();
}

SYMBOL_DECLSPEC int __stdcall mGetLinksPage(void *ctx, int page_num)
{
	muctx *mu_ctx = static_cast<muctx*>(ctx);

	sh_vector_link link_smart_ptr_vec(new std::vector<sh_link>());
	gLinkResults = link_smart_ptr_vec;

	return mu_ctx->GetLinks(page_num, gLinkResults);
}

SYMBOL_DECLSPEC void __stdcall mSetAA(void *ctx, int level)
{
	muctx *mu_ctx = static_cast<muctx*>(ctx);
	mu_ctx->SetAA(level);
}

SYMBOL_DECLSPEC char* __stdcall mGetVers()
{
	int len = strlen(FZ_VERSION);
	char* retstr = NULL;

	if (len > 0)
	{
		/* This allocation ensures that Marshal will release in the managed code */
		retstr = (char*)::CoTaskMemAlloc(len + 1);
		strcpy(retstr, FZ_VERSION);
	}
	return retstr;
}

SYMBOL_DECLSPEC char* __stdcall mGetLinkItem(int k, double *top_x, double
	*top_y, double *height, double *width, int *topage, int *type)
{
	char* retstr = NULL;

	if (k < 0 || k > gLinkResults->size())
		return false;
	sh_link muctx_link = gLinkResults->at(k);
	*top_x = muctx_link->upper_left.X;
	*top_y = muctx_link->upper_left.Y;
	*width = muctx_link->lower_right.X - muctx_link->upper_left.X;
	*height = muctx_link->lower_right.Y - muctx_link->upper_left.Y;
	*topage = muctx_link->page_num;
	*type = (int) muctx_link->type;

	if (muctx_link->type == LINK_URI)
	{
		const char* str = muctx_link->uri.get();
		int len = strlen(str);
		if (len > 0)
		{
			/* This allocation ensures that Marshal will release in the managed code */
			retstr = (char*)::CoTaskMemAlloc(len + 1);
			strcpy(retstr, str);
		}
		muctx_link->uri.release();
	}
	return retstr;
}

SYMBOL_DECLSPEC void __stdcall mReleaseLink()
{
	if (gTextResults != nullptr)
		gTextResults.reset();
}

SYMBOL_DECLSPEC void* __stdcall mCreateDisplayList(void *ctx, int page_num,
	int *page_width, int *page_height)
{
	muctx *mu_ctx = static_cast<muctx*>(ctx);
	return (void*)mu_ctx->CreateDisplayList(page_num, page_width, page_height);
}

SYMBOL_DECLSPEC void* __stdcall mCreateDisplayListAnnot(void *ctx, int page_num)
{
	muctx *mu_ctx = static_cast<muctx*>(ctx);
	return (void*)mu_ctx->CreateAnnotationList(page_num);
}

SYMBOL_DECLSPEC void* __stdcall mCreateDisplayListText(void *ctx, int page_num,
	int *page_width, int *page_height, void **text_out, int *length)
{
	muctx *mu_ctx = static_cast<muctx*>(ctx);
	fz_text_page *text;
	void *text_ptr = (void*)mu_ctx->CreateDisplayListText(page_num, page_width, page_height,
		&text, length);
	*text_out = (void*) text;
	return text_ptr;
}

SYMBOL_DECLSPEC int __stdcall mRenderPageMT(void *ctx, void *dlist,
	void *annot_dlist, int page_width, int page_height, byte *bmp_data, int bmp_width,
	int bmp_height, double scale, bool flipy)
{
	muctx *mu_ctx = static_cast<muctx*>(ctx);

	return (int) mu_ctx->RenderPageMT(dlist, annot_dlist, page_width, page_height,
		&(bmp_data[0]), bmp_width, bmp_height,
		scale, flipy, false, { 0, 0 }, { 0, 0 });
}

SYMBOL_DECLSPEC void __stdcall mReleaseText(void *ctx, void *page)
{
	muctx *mu_ctx = static_cast<muctx*>(ctx);
	mu_ctx->ReleaseText(page);
}

/* Information about a block of text */
SYMBOL_DECLSPEC int __stdcall mGetTextBlock(void *page, int block_num,
	double *top_x, double *top_y, double *height, double *width)
{
	fz_text_page *text = (fz_text_page*) page;
	fz_text_block *block;

	if (text->blocks[block_num].type != FZ_PAGE_BLOCK_TEXT)
		return 0;
	block = text->blocks[block_num].u.text;

	*top_x = block->bbox.x0;
	*top_y = block->bbox.y0;
	*height = block->bbox.y1 - *top_y;
	*width = block->bbox.x1 - *top_x;
	return block->len;
}

/* Information about a line of text */
SYMBOL_DECLSPEC int __stdcall mGetTextLine(void *page, int block_num, int line_num,
	double *top_x, double *top_y, double *height, double *width)
{
	int len = 0;
	fz_text_block *block;
	fz_text_line line;
	fz_text_span *span;
	fz_text_page *text = (fz_text_page*)page;

	block = text->blocks[block_num].u.text;
	line = block->lines[line_num];
	
	*top_x = line.bbox.x0;
	*top_y = line.bbox.y0;
	*height = line.bbox.y1 - *top_y;
	*width = line.bbox.x1 - *top_x;

	for (span = line.first_span; span; span = span->next)
	{
		len += span->len;
	}
	return len;
}

/* Information down to the character level */
SYMBOL_DECLSPEC int __stdcall mGetTextCharacter(void *page, int block_num, int line_num,
	int item_num, double *top_x, double *top_y, double *height, double *width)
{
	fz_text_block *block;
	fz_text_line line;
	fz_text_span *span;
	fz_text_page *text = (fz_text_page*)page;
	fz_char_and_box cab;
	int index = item_num;

	block = text->blocks[block_num].u.text;
	line = block->lines[line_num];

	span = line.first_span;
	while (index >= span->len)
	{
		index = index - span->len;  /* Reset to start of next span */
		span = span->next;  /* Get next span */
	}

	cab.c = span->text[index].c;
	fz_text_char_bbox(&(cab.bbox), span, index);
	*top_x = cab.bbox.x0;
	*top_y = cab.bbox.y0;
	*height = cab.bbox.y1 - *top_y;
	*width = cab.bbox.x1 - *top_x;

	return cab.c;
}

/* pdf clean methods */
SYMBOL_DECLSPEC int __stdcall mExtractPages(PCWSTR infile, PCWSTR outfile,
	PCWSTR password, bool has_password, bool linearize, int num_pages, void *pages)
{
	int argc = 3 + ((has_password) ? (2) : (0)) + ((linearize) ? (1) : (0)) + ((num_pages > 0) ? (1) : (0));
	char **argv;
	int size_pages;
	char *infilechar = String_to_char(infile);
	char *outfilechar = String_to_char(outfile);
	char *passchar;
	int *pagenum = (int*) pages;
	char *pagenums;
	char* num;
	int num_size;
	int result;
	int pos = 1;

	argv = new char*[argc];

	if (has_password)
	{
		passchar = String_to_char(password);
		argv[pos++] = "-p";
		argv[pos++] = passchar;
	}
	if (linearize)
	{
		argv[pos++] = "-l";
	}

	argv[pos++] = infilechar;
	argv[pos++] = outfilechar;

	if (num_pages > 0)
	{
		/* Get last page, for number length and number of pages */
		int last = pagenum[num_pages - 1];
		if (last == 0)
		{
			num_size = 1;
			size_pages = num_size;
		}
		else
		{
			num_size = floor(log10(last)) + 1;
			size_pages = (num_size + 1) * num_pages;
		}

		/* Create the list of page numbers */
		pagenums = new char[size_pages + 1];
		pagenums[0] = '\0';
		num = new char[num_size + 2];
		for (int kk = 0; kk < num_pages; kk++)
		{
			if (kk < num_pages - 1)
				sprintf(num, "%d,", pagenum[kk]);
			else
				sprintf(num, "%d", pagenum[kk]);
			strcat(pagenums, num);
		}
		argv[pos++] = pagenums;
	}

	fz_optind = 1;
	result = pdfclean_main(argc, argv);
	
	delete(num);
	delete(infilechar);
	delete(outfilechar);
	if (has_password)
		delete(passchar);
	if (num_pages > 0)
		delete(pagenums);
	delete(argv);
	return result;
}

/* output methods */
SYMBOL_DECLSPEC int __stdcall mSavePage(void *ctx, PCWSTR outfile, int page_num,
	int resolution, int type, bool append)
{
	muctx *mu_ctx = static_cast<muctx*>(ctx);
	char *outfilechar = String_to_char(outfile);
	status_t result = mu_ctx->SavePage(outfilechar, page_num, resolution, type,
		append);
	delete(outfilechar);
	if (result == S_ISOK)
		return 0;
	else
		return -1;
}
