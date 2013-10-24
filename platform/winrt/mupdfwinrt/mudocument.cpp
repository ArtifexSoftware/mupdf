// mudocument.cpp

/* This file contains the interface between the muctx class, which
   implements the mupdf calls and the WinRT objects enabling calling from
   C#, C++, Visual Basic, JavaScript applications */

#include "pch.h"
#include "mudocument.h"
#include "status.h"

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
	Point size;

	mutex_lock.lock();
	size = this->mu_object.MeasurePage(page_num);
	mutex_lock.unlock();
	return size;
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
				/* Need to do something useful here */
				throw ex;
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

/* Pack the page into a bmp stream */
Windows::Foundation::IAsyncOperation<InMemoryRandomAccessStream^>^
	mudocument::RenderPageAsync(int page_num, int bmp_width, int bmp_height, 
								bool use_dlist)
{
	return create_async([this, bmp_width, bmp_height, page_num, use_dlist]
						(cancellation_token ct) -> InMemoryRandomAccessStream^
	{
		/* Allocate space for bmp */
		Array<unsigned char>^ bmp_data = 
						ref new Array<unsigned char>(bmp_height * 4 * bmp_width);
		/* Set up the memory stream */
		InMemoryRandomAccessStream ^ras = ref new InMemoryRandomAccessStream();
		DataWriter ^dw = ref new DataWriter(ras->GetOutputStreamAt(0));
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
			/* Rendering of display list can occur with other threads so unlock */
			mutex_lock.unlock();
			code = mu_object.RenderPageMT(dlist, page_width, page_height, 
										  &(bmp_data[0]), bmp_width, bmp_height);
		} 
		else 
		{
			/* Rendering in immediate mode.  Keep lock in place */
			mutex_lock.lock();
			code = mu_object.RenderPage(page_num, &(bmp_data[0]), bmp_width, 
										bmp_height);
			mutex_lock.unlock();
		}
		if (code != S_ISOK)
		{
			throw ref new FailureException("Page Rendering Failed");
		}
		/* Now the data into the memory stream */
		dw->WriteBytes(bmp_data);
		DataWriterStoreOperation^ result = dw->StoreAsync();
		/* Block on this Async call? */
		while(result->Status != AsyncStatus::Completed) {
		}
		/* Return raster stream */
		return ras;
	});
}

int mudocument::ComputeLinks(int page_num)
{
	/* We get back a standard smart pointer from muctx interface and go to WinRT
	   type here */
	sh_vector_link link_smart_ptr_vec(new std::vector<sh_link>());
	mutex_lock.lock();
	int num_items = mu_object.GetLinks(page_num, link_smart_ptr_vec);
	mutex_lock.unlock();
	if (num_items == 0)
		return 0;
	/* Pack into winRT type*/
	this->links = ref new Platform::Collections::Vector<Links^>();
	for (int k = 0; k < num_items; k++)
	{
		auto new_link = ref new Links();
		sh_link muctx_link = link_smart_ptr_vec->at(k);
		new_link->LowerRight = muctx_link->lower_right;
		new_link->UpperLeft = muctx_link->upper_left;
		new_link->PageNum = muctx_link->page_num;
		new_link->Type = muctx_link->type;
		if (new_link->Type == LINK_URI)
		{
			String^ str = char_to_String(muctx_link->uri.get());
			// The URI to launch
			new_link->Uri = ref new Windows::Foundation::Uri(str);
		}
		this->links->Append(new_link);
	}
	return num_items;
}

Links^ mudocument::GetLink(int k)
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
	for (int k = 0; k < num_items; k++)
	{
		auto new_link = ref new Links();
		sh_text muctx_text = text_smart_ptr_vec->at(k);
		new_link->LowerRight = muctx_text->lower_right;
		new_link->UpperLeft = muctx_text->upper_left;
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
Links^ mudocument::GetTextSearch(int k)
{
	if (k >= this->textsearch->Size)
		return nullptr;
	return this->textsearch->GetAt(k);
}

int mudocument::ComputeContents()
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
	/* Pack into winRT type*/
	this->contents = ref new Platform::Collections::Vector<ContentItem^>();
	int num_items = content_smart_ptr_vec->size();

	for (int k = 0; k < num_items; k++)
	{
		auto new_content = ref new ContentItem();
		sh_content muctx_content = content_smart_ptr_vec->at(k);
		new_content->Page = muctx_content->page;
		new_content->StringMargin = muctx_content->string_margin;
		new_content->StringOrig = muctx_content->string_orig;
		this->contents->Append(new_content);
	}
	return num_items;
}

ContentItem^ mudocument::GetContent(int k)
{
	if (k >= this->contents->Size)
		return nullptr;
	return this->contents->GetAt(k);
}

String^ mudocument::ComputeHTML(int page_num)
{
	String^ html;

	mutex_lock.lock();
	html = mu_object.GetHTML(page_num);
	mutex_lock.unlock();
	return html;
}
