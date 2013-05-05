#pragma once

#include <memory>
#include <functional>
#include <vector>
#include "utils.h"

#include <windows.h>
#include <Winerror.h>
#include <mutex>

extern "C" {
    #include "fitz.h"
    #include "fitz-internal.h"
    #include "muxps.h"
    #include "mupdf.h"
}

#define MAX_SEARCH 500

using namespace Windows::Foundation;  /* For Point */

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

typedef struct text_search_s
{
    Point upper_left;
    Point lower_right;
} text_search_t;

#define sh_text std::shared_ptr<text_search_t>
#define sh_vector_text std::shared_ptr<std::vector<sh_text>> 

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
	CRITICAL_SECTION mu_criticalsec;
    win_stream_struct win_stream;
    fz_locks_context mu_locks;
	fz_context *mu_ctx;
	fz_document *mu_doc;
	fz_outline *mu_outline;
    fz_rect mu_hit_bbox[MAX_SEARCH];
	fz_cookie *mu_cookie;
    fz_stream *mu_stream;

public:
    muctx(void);
    ~muctx(void);
    HRESULT InitializeStream(IRandomAccessStream^ readStream, char *ext);
    int GetPageCount();   
    HRESULT InitializeContext();
    HRESULT RenderPage(int page_num, int width, int height, unsigned char *bmp_data);
    Point MeasurePage(int page_num);
    Point MeasurePage(fz_page *page);
    int GetLinks(int page_num, sh_vector_link links_vec);
    int GetTextSearch(int page_num, char* needle, sh_vector_text texts_vec);
};




