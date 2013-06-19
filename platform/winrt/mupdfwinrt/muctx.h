#pragma once

#include <memory>
#include <functional>
#include <vector>
#include <windows.h>
#include <mutex>
#include "utils.h"
#include "Cache.h"
#include "status.h"

extern "C" {
	#include "mupdf/fitz.h"
}

#define MAX_SEARCH 500

using namespace Platform;  /* For String */
using namespace Windows::Foundation;  /* For Point */

/* These are the std objects used to interface to muctx.  We do use windows
   String and Point types however */

/* Links */
typedef struct document_link_s
{
	link_t type;
	Point upper_left;
	Point lower_right;
	std::unique_ptr<char[]> uri;
	int page_num;
} document_link_t;
#define sh_link std::shared_ptr<document_link_t>
#define sh_vector_link std::shared_ptr<std::vector<sh_link>>

/* Text Search */
typedef struct text_search_s
{
	Point upper_left;
	Point lower_right;
} text_search_t;
#define sh_text std::shared_ptr<text_search_t>
#define sh_vector_text std::shared_ptr<std::vector<sh_text>>

/* Content Results */
typedef struct content_s
{
	int  page;
	String^ string_orig;
	String^ string_margin;
} content_t;
#define sh_content std::shared_ptr<content_t>
#define sh_vector_content std::shared_ptr<std::vector<sh_content>>

/* Used for HTML return */
#define sh_vector_char std::shared_ptr<std::vector<char>>

/* Needed for file handling */
using namespace Windows::Storage::Streams;
using namespace Windows::Foundation;

typedef struct win_stream_struct_s
{
	IRandomAccessStream^ stream;
} win_stream_struct;

class muctx
{
private:
	CRITICAL_SECTION mu_criticalsec[FZ_LOCK_MAX];
	win_stream_struct win_stream;
	fz_locks_context mu_locks;
	fz_context *mu_ctx;
	fz_document *mu_doc;
	fz_outline *mu_outline;
	fz_rect mu_hit_bbox[MAX_SEARCH];
	void FlattenOutline(fz_outline *outline, int level,
						sh_vector_content contents_vec);
	Cache *display_list_cache;
	fz_display_list* CreateDisplayList(int page_num);

public:
	muctx(void);
	~muctx(void);
	void CleanUp(void);
	status_t InitializeStream(IRandomAccessStream^ readStream, char *ext);
	int GetPageCount();
	status_t InitializeContext();
	status_t RenderPage(int page_num, int width, int height, unsigned char *bmp_data,
						bool use_dlist);
	Point MeasurePage(int page_num);
	Point MeasurePage(fz_page *page);
	int GetLinks(int page_num, sh_vector_link links_vec);
	int GetTextSearch(int page_num, char* needle, sh_vector_text texts_vec);
	int GetContents(sh_vector_content contents_vec);
	String^ GetHTML(int page_num);
	bool RequiresPassword(void);
	bool ApplyPassword(char* password);
};
