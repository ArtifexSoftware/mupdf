#pragma once

#include "pch.h"
#include "muctx.h"
#include "Links.h"

/* This class interfaces to mupdf API with minimal windows objects
 * (other than the file streaming stuff) */

/* File streaming set up for mupdf */

/* win_read_file etc.  Reading of windows managed stream.  This is
 * not ideal as I have to read into a managed buffer and then transfer
 * to the actual buffer I want.  I would like a more direct approach.
 * Alternate approach is to push this off outside the winrt and read
 * from a memory buffer. */
static int win_read_file(fz_stream *stm, unsigned char *buf, int len)
{
	void *temp = stm->state;
	win_stream_struct *stream = reinterpret_cast <win_stream_struct*> (temp);
	IRandomAccessStream^ Stream = stream->stream;
	unsigned long long curr_pos = Stream->Position;
	unsigned long long length = Stream->Size;
	DataReader^ local_reader = ref new DataReader(Stream);
	DataReaderLoadOperation^ result = local_reader->LoadAsync(len);

	/* Block on the Async call */
	while(result->Status != AsyncStatus::Completed) {

	}

	result->GetResults();
	int curr_len2 = local_reader->UnconsumedBufferLength;
	if (curr_len2 < len)
		len = curr_len2;

	Platform::Array<unsigned char>^ arrByte = ref new Platform::Array<unsigned char>(len);
	local_reader->ReadBytes(arrByte);

	memcpy(buf, arrByte->Data, len);
	local_reader->DetachStream();

	return len;
}

static void win_seek_file(fz_stream *stm, int offset, int whence)
{
	void *temp = stm->state;
	win_stream_struct *stream = reinterpret_cast <win_stream_struct*> (temp);
	IRandomAccessStream^ Stream = stream->stream;
	unsigned long long curr_pos = Stream->Position;
	unsigned long long length = Stream->Size;
	unsigned long long n;

	if (whence == SEEK_END)
	{
		n = length + offset;
	}
	else if (whence == SEEK_CUR)
	{
		n = curr_pos + offset;
	}
	else if (whence == SEEK_SET)
	{
		n = offset;
	}
	Stream->Seek(n);
	curr_pos = Stream->Position;
	stm->pos = n;
	stm->rp = stm->bp;
	stm->wp = stm->bp;
}

static void win_close_file(fz_context *ctx, void *state)
{
	DataReader^ dataReader = reinterpret_cast <DataReader^> (state);

	delete dataReader;
}

/* mutext functions see mupdf readme for details */
static void lock_mutex(void *user, int lock)
{
	LPCRITICAL_SECTION locks = (LPCRITICAL_SECTION)user;
	EnterCriticalSection(&locks[lock]);
}

static void unlock_mutex(void *user, int lock)
{
	LPCRITICAL_SECTION locks = (LPCRITICAL_SECTION)user;
	LeaveCriticalSection(&locks[lock]);
}

void muctx::CleanUp(void)
{
	free(this->mu_cookie);
	if (mu_outline != NULL)
		fz_free_outline(mu_ctx, mu_outline);
	if (mu_doc != NULL)
		fz_close_document(mu_doc);
	if (mu_ctx != NULL)
		fz_free_context(mu_ctx);

	this->mu_cookie = NULL;
	this->mu_ctx = NULL;
	this->mu_doc = NULL;
	this->mu_outline = NULL;
	this->mu_stream = NULL;
}

/* Set up the context, mutex and cookie */
HRESULT muctx::InitializeContext()
{
	int i;

	/* Get the mutexes set up */
	for (i = 0; i < FZ_LOCK_MAX; i++)
		InitializeCriticalSectionEx(&mu_criticalsec[i], 0, 0);
	mu_locks.user = &mu_criticalsec[0];
	mu_locks.lock = lock_mutex;
	mu_locks.unlock = unlock_mutex;

	/* Allocate the context */
	this->mu_ctx = fz_new_context(NULL, &mu_locks, FZ_STORE_DEFAULT);
	if (this->mu_ctx == NULL)
	{
		return E_OUTOFMEMORY;
	}
	else
	{
		/* If we are fine, allocate the cookie for progress etc. */
		this->mu_cookie = (fz_cookie*)malloc(sizeof(fz_cookie));
		if (this->mu_cookie == NULL) {
			fz_free_context(this->mu_ctx);
			return E_OUTOFMEMORY;
		}
		else
			return S_OK;
	}
}

/* Initializer */
muctx::muctx(void)
{
	this->mu_cookie = NULL;
	this->mu_ctx = NULL;
	this->mu_doc = NULL;
	this->mu_outline = NULL;
	this->mu_stream = NULL;
}

/* Destructor */
muctx::~muctx(void)
{
	free(this->mu_cookie);
	if (mu_outline != NULL)
		fz_free_outline(mu_ctx, mu_outline);
	if (mu_doc != NULL)
		fz_close_document(mu_doc);
	if (mu_ctx != NULL)
		fz_free_context(mu_ctx);

	this->mu_cookie = NULL;
	this->mu_ctx = NULL;
	this->mu_doc = NULL;
	this->mu_outline = NULL;
	this->mu_stream = NULL;
}

/* Set up the stream access */
HRESULT muctx::InitializeStream(IRandomAccessStream^ readStream, char *ext)
{
	win_stream.stream = readStream;
	this->mu_stream = fz_new_stream(mu_ctx, 0, win_read_file, win_close_file);
	this->mu_stream->seek = win_seek_file;
	this->mu_stream->state =  reinterpret_cast <void*> (&win_stream);

	/* Now lets see if we can open the file */
	mu_doc = fz_open_document_with_stream(mu_ctx, ext, this->mu_stream);

	if (mu_doc == NULL)
		return E_FAIL;
	else
		return S_OK;
}

/* Return the documents page count */
int muctx::GetPageCount()
{
	if (this->mu_doc == NULL)
		return -1;
	else
		return this->mu_doc->count_pages(this->mu_doc);
}

/* Get page size */
Point muctx::MeasurePage(int page_num)
{
	Point pageSize;
	fz_rect rect;
	fz_page *page;
	fz_rect *bounds;

	page = fz_load_page(mu_doc, page_num);
	bounds = fz_bound_page(mu_doc, page, &rect);
	pageSize.X = bounds->x1 - bounds->x0;
	pageSize.Y = bounds->y1 - bounds->y0;

	return pageSize;
}

/* Get page size */
Point muctx::MeasurePage(fz_page *page)
{
	Point pageSize;
	fz_rect rect;
	fz_rect *bounds;

	bounds = fz_bound_page(mu_doc, page, &rect);
	pageSize.X = bounds->x1 - bounds->x0;
	pageSize.Y = bounds->y1 - bounds->y0;

	return pageSize;
}

void muctx::FlattenOutline(fz_outline *outline, int level,
			  sh_vector_content contents_vec)
{
	char indent[8*4+1];
	if (level > 8)
		level = 8;
	memset(indent, ' ', level * 4);
	indent[level * 4] = 0;

	String^ indent_str = char_to_String(indent);
	String^ str_indent;

	while (outline)
	{
		if (outline->dest.kind == FZ_LINK_GOTO)
		{
			int page = outline->dest.ld.gotor.page;
			if (page >= 0 && outline->title)
			{
				/* Add to the contents std:vec */
				sh_content content_item(new content_t());
				content_item->page = page;
				content_item->string_orig = char_to_String(outline->title);
				content_item->string_margin =
					str_indent->Concat(indent_str, content_item->string_orig);
				contents_vec->push_back(content_item);
			}
		}
		FlattenOutline(outline->down, level + 1, contents_vec);
		outline = outline->next;
	}
}

int muctx::GetContents(sh_vector_content contents_vec)
{
	fz_outline *root = NULL;
	fz_context *ctx_clone = NULL;
	int has_content = 0;

	if (mu_cookie->abort == 1)
		return has_content;

	ctx_clone = fz_clone_context(mu_ctx);

	fz_var(root);
	fz_try(ctx_clone)
	{
		root = fz_load_outline(mu_doc);
		if (root != NULL)
		{
			has_content = 1;
			FlattenOutline(root, 0, contents_vec);
		}
	}
	fz_always(ctx_clone)
	{
		if (root != NULL)
		{
			fz_free_outline(ctx_clone, root);
		}
	}
	fz_catch(ctx_clone)
	{
		fz_free_context(ctx_clone);
		return E_FAIL;
	}
	fz_free_context(ctx_clone);
	return has_content;
}

int muctx::GetTextSearch(int page_num, char* needle, sh_vector_text texts_vec)
{
	fz_page *page = NULL;
	fz_text_sheet *sheet = NULL;
	fz_device *dev = NULL;
	fz_context *ctx_clone = NULL;
	fz_text_page *text = NULL;
	int hit_count = 0;
	int k;

	if (mu_cookie->abort == 1)
		return hit_count;

	ctx_clone = fz_clone_context(mu_ctx);

	fz_var(page);
	fz_var(sheet);
	fz_var(dev);
	fz_try(ctx_clone)
	{
		page = fz_load_page(mu_doc, page_num);
		sheet = fz_new_text_sheet(ctx_clone);
		text = fz_new_text_page(ctx_clone, &fz_empty_rect);  // Free?
		dev = fz_new_text_device(ctx_clone, sheet, text);
		fz_run_page(mu_doc, page, dev, &fz_identity, NULL);
		fz_free_device(dev);  /* Why does this need to be done here?  Seems odd */
		dev = NULL;
		hit_count = fz_search_text_page(ctx_clone, text, needle, mu_hit_bbox, nelem(mu_hit_bbox));

		for (k = 0; k < hit_count; k++)
		{
			sh_text text_search(new text_search_t());
			text_search->upper_left.X = mu_hit_bbox[k].x0;
			text_search->upper_left.Y = mu_hit_bbox[k].y0;
			text_search->lower_right.X = mu_hit_bbox[k].x1;
			text_search->lower_right.Y = mu_hit_bbox[k].y1;
			texts_vec->push_back(text_search);
		}
	}
	fz_always(ctx_clone)
	{
		if (page != NULL)
		{
			fz_free_page(mu_doc, page);
		}
		if (dev != NULL)
		{
			fz_free_device(dev);
		}
		if (sheet != NULL)
		{
			fz_free_text_sheet(ctx_clone, sheet);
		}
		if (text != NULL)
		{
			fz_free_text_page(ctx_clone, text);
		}
	}
	fz_catch(ctx_clone)
	{
		fz_free_context(ctx_clone);
		return E_FAIL;
	}
	fz_free_context(ctx_clone);
	return hit_count;
}

/* Get the links and pack into a smart pointer structure */
int muctx::GetLinks(int page_num, sh_vector_link links_vec)
{
	fz_page *page = NULL;
	fz_link *links = NULL;
	fz_context *ctx_clone = NULL;
	int k = 0;
	int num_links = 0;

	if (mu_cookie->abort == 1)
		return num_links;

	ctx_clone = fz_clone_context(mu_ctx);

	fz_var(page);
	fz_var(links);
	fz_try(ctx_clone)
	{
		page = fz_load_page(mu_doc, page_num);
		links = fz_load_links(mu_doc, page);

		fz_link *curr_link = links;
		if (curr_link != NULL)
		{
			/* Get our smart pointer structure filled */
			while (curr_link != NULL)
			{
				fz_rect curr_rect = curr_link->rect;
				sh_link link(new document_link_t());

				link->upper_left.X = curr_rect.x0;
				link->upper_left.Y = curr_rect.y0;
				link->lower_right.X = curr_rect.x1;
				link->lower_right.Y = curr_rect.y1;

				switch (curr_link->dest.kind)
				{
				case FZ_LINK_GOTO:

					link->type = LINK_GOTO;
					link->page_num = curr_link->dest.ld.gotor.page;
					break;

				case FZ_LINK_URI:
				{
					int lenstr = strlen(curr_link->dest.ld.uri.uri);
					std::unique_ptr<char[]> uri(new char[lenstr + 1]);
					strcpy_s(uri.get(), lenstr + 1, curr_link->dest.ld.uri.uri);
					link->uri.swap(uri);
					link->type = LINK_URI;
					break;
				}

				default:
					link->type = NOT_SET;

				}
				links_vec->push_back(link);
				curr_link = curr_link->next;
				num_links += 1;
			}
		}
	}
	fz_always(ctx_clone)
	{
		if (page != NULL)
		{
			fz_free_page(mu_doc, page);
		}
		if (links != NULL)
		{
			fz_drop_link(ctx_clone, links);
		}
	}
	fz_catch(ctx_clone)
	{
		fz_free_context(ctx_clone);
		return E_FAIL;
	}
	fz_free_context(ctx_clone);
	return num_links;
}

/* Render page_num to size width by height into bmp_data buffer */
HRESULT muctx::RenderPage(int page_num, int width, int height,
			  unsigned char *bmp_data)
{
	fz_device *dev = NULL;
	fz_pixmap *pix = NULL;
	fz_page *page = NULL;
	fz_matrix ctm, *pctm = &ctm;
	Point page_size;
	fz_context *ctx_clone = NULL;

	if (mu_cookie->abort == 1)
		return S_OK;

	ctx_clone = fz_clone_context(mu_ctx);

	fz_var(dev);
	fz_var(pix);
	fz_var(page);
	fz_try(ctx_clone)
	{
		page = fz_load_page(mu_doc, page_num);
		page_size = MeasurePage(page);

		/* Figure out scale factors so that we get the desired size */
		pctm = fz_scale(pctm, (float) width / page_size.X, (float) height / page_size.Y);
		/* Flip on Y */
		ctm.f = height;
		ctm.d = -ctm.d;
		pix = fz_new_pixmap_with_data(ctx_clone, fz_device_bgr, width, height, bmp_data);
		fz_clear_pixmap_with_value(ctx_clone, pix, 255);
		dev = fz_new_draw_device(ctx_clone, pix);
		fz_run_page(mu_doc, page, dev, pctm, NULL);
	}
	fz_always(ctx_clone)
	{
		if (dev != NULL)
		{
			fz_free_device(dev);
		}
		if (pix != NULL)
		{
			fz_drop_pixmap(ctx_clone, pix);
		}
		if (page != NULL)
		{
			fz_free_page(mu_doc, page);
		}
	}
	fz_catch(ctx_clone)
	{
		fz_free_context(ctx_clone);
		return E_FAIL;
	}

	fz_free_context(ctx_clone);
	return S_OK;
}

bool muctx::RequiresPassword(void)
{
	return fz_needs_password(mu_doc);
}

bool muctx::ApplyPassword(char* password)
{
	return fz_authenticate_password(mu_doc, password);
}

String^ muctx::GetHTML(int page_num)
{
	fz_output *out = NULL;
	fz_device *dev = NULL;
	fz_page *page = NULL;
	fz_text_sheet *sheet = NULL;
	fz_text_page *text = NULL;
	fz_context *ctx_clone = NULL;
	fz_buffer *buf = NULL;
	String^ html;

	if (mu_cookie->abort == 1)
		return nullptr;

	ctx_clone = fz_clone_context(mu_ctx);

	fz_var(dev);
	fz_var(page);
	fz_var(sheet);
	fz_var(text);  // Free?
	fz_var(buf);   // Free?
	fz_try(ctx_clone)
	{
		page = fz_load_page(mu_doc, page_num);
		sheet = fz_new_text_sheet(ctx_clone);
		text = fz_new_text_page(ctx_clone, &fz_empty_rect);
		dev = fz_new_text_device(ctx_clone, sheet, text);
		fz_run_page(mu_doc, page, dev, &fz_identity, NULL);
		fz_free_device(dev);
		dev = NULL;
		fz_analyze_text(ctx_clone, sheet, text);
		buf = fz_new_buffer(ctx_clone, 256);
		out = fz_new_output_with_buffer(ctx_clone, buf);
		fz_print_text_page_html(ctx_clone, out, text);
		html = char_to_String((char*) buf->data);
	}
	fz_always(ctx_clone)
	{
		if (dev != NULL)
		{
			fz_free_device(dev);
		}
		if (page != NULL)
		{
			fz_free_page(mu_doc, page);
		}
		if (sheet != NULL)
		{
			fz_free_text_sheet(ctx_clone, sheet);
		}
	}
	fz_catch(ctx_clone)
	{
		fz_free_context(ctx_clone);
		return nullptr;
	}

	fz_free_context(ctx_clone);
	return html;
}
