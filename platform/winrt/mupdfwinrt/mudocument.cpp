// mudocument.cpp

/* This file contains the interface between the muctx class, which
	implements the mupdf calls and the WinRT objects enabling calling from
	C#, C++, Visual Basic, JavaScript applications */

#include "pch.h"
#include "mudocument.h"
#include "status.h"
#include "utils.h"

using namespace mupdfwinrt;
using namespace concurrency;
using namespace Platform::Collections;

mudocument::mudocument()
{
	this->mu_object.InitializeContext();
	this->links = nullptr;
}

bool mudocument::RequiresPassword()
{
	return mu_object.RequiresPassword();
}

bool mudocument::ApplyPassword(String^ password)
{
	char* pass_char = String_to_char(password);
	bool ok = mu_object.ApplyPassword(pass_char);
	delete []pass_char;
	return ok;
}

void mudocument::CleanUp()
{
	this->mu_object.CleanUp();
}

int mudocument::GetNumPages()
{
	return this->mu_object.GetPageCount();
}

Point mudocument::GetPageSize(int page_num)
{
	Point size_out;
	point_t size;

	mutex_lock.lock();
	int code = this->mu_object.MeasurePage(page_num, &size);
	mutex_lock.unlock();
	if (code < 0)
        throw ref new Exception(code, ref new String(L"Get Page Size Failed"));

	size_out.X = size.X;
	size_out.Y = size.Y;
	return size_out;
}

Windows::Foundation::IAsyncOperation<int>^ mudocument::OpenFileAsync(StorageFile^ file)
{
	return create_async([this, file]()
	{
		String^ filetype = file->FileType;
		const wchar_t *w = filetype->Data();
		int cb = WideCharToMultiByte(CP_UTF8, 0, w, -1, nullptr, 0, nullptr, nullptr);
		char* name = new char[cb];

		WideCharToMultiByte(CP_UTF8, 0, w ,-1 ,name ,cb ,nullptr, nullptr);
		char *ext = strrchr(name, '.');

		auto t = create_task(file->OpenAsync(FileAccessMode::Read));

		return t.then([this, file, ext](task<IRandomAccessStream^> task)
		{
			try
			{
				IRandomAccessStream^ readStream = task.get();
				UINT64 const size = readStream->Size;

				if (size <= MAXUINT32)
				{
					status_t code = this->mu_object.InitializeStream(readStream, ext);
					if (code != S_ISOK)
						delete readStream;
					return (int) code;
				}
				else
				{
					delete readStream;
					return (int) E_FAILURE;
				}
			}
			catch(COMException^ ex) {
				throw ref new FailureException("Open File Failed");
			}
		});
	});
}

/* Header info for bmp stream so that we can use the image brush */
static void Prepare_bmp(int width, int height, DataWriter ^dw)
{
	int row_size = width * 4;
	int bmp_size = row_size * height + 54;

	dw->WriteString("BM");
	dw->ByteOrder = ByteOrder::LittleEndian;
	dw->WriteInt32(bmp_size);
	dw->WriteInt16(0);
	dw->WriteInt16(0);
	dw->WriteInt32(54);
	dw->WriteInt32(40);
	dw->WriteInt32(width);
	dw->WriteInt32(height);
	dw->WriteInt16(1);
	dw->WriteInt16(32);
	dw->WriteInt32(0);
	dw->WriteInt32(row_size * height);
	dw->WriteInt32(2835);
	dw->WriteInt32(2835);
	dw->WriteInt32(0);
	dw->WriteInt32(0);
}

/* Do the search through the pages with an async task with progress callback */
Windows::Foundation::IAsyncOperationWithProgress<int, double>^
	mudocument::SearchDocumentWithProgressAsync(String^ textToFind, int dir, 
												int start_page, int num_pages)
{
	return create_async([this, textToFind, dir, start_page, num_pages]
						(progress_reporter<double> reporter) -> int
	{
		double progress;
		int box_count, result;

		for (int i = start_page; i >= 0 && i < num_pages; i += dir)
		{
			box_count = this->ComputeTextSearch(textToFind, i);
			result = i;
			if (dir == SEARCH_FORWARD)
			{
				progress = 100.0 * (double) (i + 1) / (double) num_pages;
			}
			else
			{
				progress = 100.0 * (double) (num_pages - i) / (double) num_pages;
			}
			/* We could have it only update with certain percentage changes but
			   we are just looping over the pages here so it is not too bad */
			reporter.report(progress);

			if (is_task_cancellation_requested())
			{
				// Cancel the current task.
				cancel_current_task();
			}

			if (box_count > 0)
			{
				return result;
			}
			if (is_task_cancellation_requested())
			{
			}
		}
		reporter.report(100.0);
		if (box_count == 0)
			return TEXT_NOT_FOUND;
		else
			return result;
	});
}

/* Pack the page into a bitmap.  This is used in the DirectX code for printing
	not in the xaml related code.  It is also used by the thumbnail creation
	thread to ensure that the thumbs are created in order and we don't create
	thousands of threads */
int mudocument::RenderPageBitmapSync(int page_num, int bmp_width, int bmp_height, 
								float scale, bool use_dlist, bool flipy, bool tile,
								Point top_left, Point bottom_right, 
								Array<unsigned char>^* bit_map)
{
	status_t code;
	/* Allocate space for bmp */
	Array<unsigned char>^ bmp_data = 
				ref new Array<unsigned char>(bmp_height * 4 * bmp_width);

	if (bmp_data == nullptr)
	{
		*bit_map = nullptr;
		return E_OUTOFMEM;
	}

	if (use_dlist) 
	{
		void *dlist;
		int page_height;
		int page_width;

		mutex_lock.lock();
		/* This lock will keep out issues in mupdf as well as race conditions
			in the page cache */
		dlist = (void*) mu_object.CreateDisplayList(page_num, &page_width, 
													&page_height);
		/* Rendering of display list can occur with other threads so unlock */
		mutex_lock.unlock();
		if (dlist == NULL)
		{
			*bit_map = nullptr;
			return E_FAILURE;
		}
		code = mu_object.RenderPageMT(dlist, page_width, page_height, 
										&(bmp_data[0]), bmp_width, bmp_height,
										scale, flipy, tile, { top_left.X, top_left.Y }, 
										{ bottom_right.X, bottom_right.Y });
	} 
	else 
	{
		/* Not dealing with the case of tiling and no display list at this time. */
		if (tile)
		{
			*bit_map = nullptr;
			return E_FAILURE;
		}
		/* Rendering in immediate mode.  Keep lock in place */
		mutex_lock.lock();
		code = mu_object.RenderPage(page_num, &(bmp_data[0]), bmp_width, 
									bmp_height, scale, flipy);
		mutex_lock.unlock();
	}
	if (code != S_ISOK)
	{
		*bit_map = nullptr;
		return E_FAILURE;
	}

	*bit_map = bmp_data;
	return (int) code;
}

/* Pack the page into a bmp stream */
Windows::Foundation::IAsyncOperation<InMemoryRandomAccessStream^>^
	mudocument::RenderPageAsync(int page_num, int bmp_width, int bmp_height, 
								bool use_dlist, float scale)
{
	return create_async([this, bmp_width, bmp_height, page_num, use_dlist, scale]
						(cancellation_token ct) -> InMemoryRandomAccessStream^
	{
		/* Allocate space for bmp */
		Array<unsigned char>^ bmp_data = 
						ref new Array<unsigned char>(bmp_height * 4 * bmp_width);
		if (bmp_data == nullptr)
			return nullptr;

		/* Set up the memory stream */
		InMemoryRandomAccessStream ^ras = ref new InMemoryRandomAccessStream();
		if (ras == nullptr)
			return nullptr;
		DataWriter ^dw = ref new DataWriter(ras->GetOutputStreamAt(0));
		if (dw == nullptr)
			return nullptr;

		status_t code;

		/* Go ahead and write our header data into the memory stream */
		Prepare_bmp(bmp_width, bmp_height, dw);

		if (use_dlist) 
		{
			void *dlist;
			int page_height;
			int page_width;

			mutex_lock.lock();
			/* This lock will keep out issues in mupdf as well as race conditions
			   in the page cache */
			dlist = (void*) mu_object.CreateDisplayList(page_num, &page_width, 
														&page_height);
			mutex_lock.unlock();
			if (dlist == NULL)
				return nullptr;
			/* Rendering of display list can occur with other threads so unlock */
			code = mu_object.RenderPageMT(dlist, page_width, page_height, 
										  &(bmp_data[0]), bmp_width, bmp_height,
										  scale, true, false, { 0.0, 0.0 }, 
										  { (float) bmp_width, (float) bmp_height });
		} 
		else 
		{ 
			/* Rendering in immediate mode.  Keep lock in place */
			mutex_lock.lock();
			code = mu_object.RenderPage(page_num, &(bmp_data[0]), bmp_width, 
										bmp_height, scale, true);
			mutex_lock.unlock();
		}
		if (code != S_ISOK)
			return nullptr;
		/* Now the data into the memory stream */
		dw->WriteBytes(bmp_data);
		auto t = create_task(dw->StoreAsync());
		t.wait();
		/* Return raster stream */
		return ras;
	});
}

unsigned int mudocument::ComputeLinks(int page_num)
{
	/* We get back a standard smart pointer from muctx interface and go to WinRT
	   type here */
	sh_vector_link link_smart_ptr_vec(new std::vector<sh_link>());
	mutex_lock.lock();
	unsigned int num_items = mu_object.GetLinks(page_num, link_smart_ptr_vec);
	mutex_lock.unlock();
	if (num_items == 0 || num_items == E_FAIL)
		return 0;
	/* Pack into winRT type*/
	this->links = ref new Platform::Collections::Vector<Links^>();
	if (this->links == nullptr)
		return 0;
	for (unsigned int k = 0; k < num_items; k++)
	{
		auto new_link = ref new Links();
		if (new_link == nullptr)
		{
			this->links = nullptr;
			return 0;
		}
		sh_link muctx_link = link_smart_ptr_vec->at(k);
		new_link->LowerRight = { (float) muctx_link->lower_right.X, (float) muctx_link->lower_right.Y };
		new_link->UpperLeft = { (float) muctx_link->upper_left.X, (float) muctx_link->upper_left.Y };
		new_link->PageNum = muctx_link->page_num;
		new_link->Type = muctx_link->type;
		if (new_link->Type == LINK_URI)
		{
			String^ str = char_to_String(muctx_link->uri.get());
			// The URI to launch
			new_link->Uri = ref new Windows::Foundation::Uri(str);
			if (new_link->Uri == nullptr)
			{
				this->links = nullptr;
				return 0;
			}
		}
		this->links->Append(new_link);
	}
	return num_items;
}

Links^ mudocument::GetLink(unsigned int k)
{
	if (k >= this->links->Size)
		return nullptr;
	return this->links->GetAt(k);
}

int mudocument::ComputeTextSearch(String^ text, int page_num)
{
	/* We get back a standard smart pointer from muctx interface and go to
	 * WinRT type here */
	char* text_char = String_to_char(text);
	sh_vector_text text_smart_ptr_vec(new std::vector<sh_text>());
	int num_items;

	mutex_lock.lock();
	num_items = mu_object.GetTextSearch(page_num, text_char, text_smart_ptr_vec);
	mutex_lock.unlock();

	if (num_items == 0)
		return 0;
	/* Pack into winRT type*/
	this->textsearch = ref new Platform::Collections::Vector<Links^>();
	if (this->textsearch == nullptr)
		return 0;
	for (int k = 0; k < num_items; k++)
	{
		auto new_link = ref new Links();
		if (new_link == nullptr)
		{
			this->textsearch = nullptr;
			return 0;
		}
		sh_text muctx_text = text_smart_ptr_vec->at(k);
		new_link->LowerRight = { (float) muctx_text->lower_right.X, (float) muctx_text->lower_right.Y };
		new_link->UpperLeft = { (float) muctx_text->upper_left.X, (float) muctx_text->upper_left.Y };
		new_link->Type = TEXTBOX;
		this->textsearch->Append(new_link);
	}
	delete []text_char;
	return num_items;
}

/* Return number of hits found on most recent page */
int mudocument::TextSearchCount(void)
{
	if (this->textsearch != nullptr)
		return this->textsearch->Size;
	else
		return 0;
}

/* Returns the kth item for a page after a text search query */
Links^ mudocument::GetTextSearch(unsigned int k)
{
	if (k >= this->textsearch->Size)
		return nullptr;
	return this->textsearch->GetAt(k);
}

unsigned int mudocument::ComputeContents()
{
	/* We get back a standard smart pointer from muctx interface and go to
	 * WinRT type here */
	sh_vector_content content_smart_ptr_vec(new std::vector<sh_content>());
	int has_content;

	mutex_lock.lock();
	has_content = mu_object.GetContents(content_smart_ptr_vec);
	mutex_lock.unlock();

	if (!has_content)
		return 0;
	/* Pack into winRT type */
	this->contents = ref new Platform::Collections::Vector<ContentItem^>();
	if (this->contents == nullptr)
		return 0;
	unsigned int num_items = content_smart_ptr_vec->size();

	for (unsigned int k = 0; k < num_items; k++)
	{
		auto new_content = ref new ContentItem();
		if (new_content == nullptr)
		{
			this->contents = nullptr;
			return 0;
		}
		sh_content muctx_content = content_smart_ptr_vec->at(k);
		new_content->Page = muctx_content->page;
		new_content->StringMargin = char_to_String(muctx_content->string_margin.c_str());
		new_content->StringOrig = char_to_String(muctx_content->string_orig.c_str());
		this->contents->Append(new_content);
	}
	return num_items;
}

ContentItem^ mudocument::GetContent(unsigned int k)
{
	if (k >= this->contents->Size)
		return nullptr;
	return this->contents->GetAt(k);
}

String^ mudocument::ComputeHTML(int page_num)
{
	String^ html = nullptr;
	std::string html_cstr;

	mutex_lock.lock();
	html_cstr = mu_object.GetHTML(page_num);
	mutex_lock.unlock();

	html = char_to_String(html_cstr.c_str());
	return html;
}
