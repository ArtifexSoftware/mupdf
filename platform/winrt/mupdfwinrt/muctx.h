#pragma once

#include <memory>
#include <functional>
#include <vector>
#include <windows.h>
#include <mutex>
#include "Cache.h"
#include "status.h"

extern "C" {
	#include "mupdf/fitz.h"
}

#define MAX_SEARCH 500

typedef struct point_s
{
	double X;
	double Y;
} point_t;

/* Links */
typedef struct document_link_s
{
	link_t type;
	point_t upper_left;
	point_t lower_right;
	std::unique_ptr<char[]> uri;
	int page_num;
} document_link_t;
#define sh_link std::shared_ptr<document_link_t>
#define sh_vector_link std::shared_ptr<std::vector<sh_link>>

/* Text Search */
typedef struct text_search_s
{
	point_t upper_left;
	point_t lower_right;
} text_search_t;
#define sh_text std::shared_ptr<text_search_t>
#define sh_vector_text std::shared_ptr<std::vector<sh_text>>

/* Content Results */
typedef struct content_s
{
	int  page;
	std::string string_orig;
	std::string string_margin;
} content_t;
#define sh_content std::shared_ptr<content_t>
#define sh_vector_content std::shared_ptr<std::vector<sh_content>>

#ifdef _WINRT_DLL
using namespace Windows::Storage::Streams;
using namespace Windows::Foundation;

typedef struct win_stream_struct_s
{
	IRandomAccessStream^ stream;
	unsigned char public_buffer[4096];
} win_stream_struct;
#endif

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
	Cache *page_cache;

public:
	muctx(void);
	~muctx(void);
	void CleanUp(void);
	int GetPageCount();
	status_t InitializeContext();
	status_t RenderPage(int page_num, unsigned char *bmp_data, int bmp_width, 
						int bmp_height, float scale, bool flipy);
	status_t RenderPageMT(void *dlist, int page_width, int page_height,
							unsigned char *bmp_data, int bmp_width, int bmp_height,
							float scale, bool flipy, bool tile, point_t top_left,
							point_t bottom_right);
	fz_display_list* CreateDisplayList(int page_num, int *width, int *height);
	int MeasurePage(int page_num, point_t *size);
	point_t MeasurePage(fz_page *page);
	unsigned int GetLinks(int page_num, sh_vector_link links_vec);
	int GetTextSearch(int page_num, char* needle, sh_vector_text texts_vec);
	int GetContents(sh_vector_content contents_vec);
	std::string GetHTML(int page_num);
	bool RequiresPassword(void);
	bool ApplyPassword(char* password);
#ifdef _WINRT_DLL
	status_t InitializeStream(IRandomAccessStream^ readStream, char *ext);
#endif

};
