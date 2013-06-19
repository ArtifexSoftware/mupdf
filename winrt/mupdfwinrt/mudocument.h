#pragma once

/* This file contains the interface between the muctx class, which
   implements the mupdf calls and the WinRT objects enabling calling from
   C#, C++, and JavaScript applications */

#include "muctx.h"
#include "Links.h"
#include "ppltasks.h"
#include "ContentItem.h"
#include <winnt.h>
#include <collection.h>

using namespace Windows::Storage;
using namespace Platform;
using namespace Concurrency;
using namespace Platform::Collections;

namespace mupdfwinrt
{
	public ref class mudocument sealed
	{
		private:
			muctx mu_object;
			std::mutex mutex_lock;
			Platform::Collections::Vector<Links^>^ links;
			Platform::Collections::Vector<Links^>^ textsearch;
			Platform::Collections::Vector<ContentItem^>^ contents;
		public:
			mudocument();
			void CleanUp();
			Windows::Foundation::IAsyncOperation<int>^ OpenFileAsync(StorageFile^ file);
			int GetNumPages(void);
			Point GetPageSize(int page_num);
			Windows::Foundation::IAsyncOperation<InMemoryRandomAccessStream^>^
				RenderPageAsync(int page_num, int width, int height, bool use_dlist);
			Windows::Foundation::IAsyncOperationWithProgress<int, double>^
				SearchDocumentWithProgressAsync(String^ textToFind, int dir, int start_page);
			String^ ComputeHTML(int page_num);
			int ComputeTextSearch(String^ text, int page_num);
			Links^ GetTextSearch(int k);
			int TextSearchCount(void);
			int ComputeContents(void);
			ContentItem^ GetContent(int k);
			int ComputeLinks(int page_num);
			Links^ GetLink(int k);
			bool RequiresPassword();
			bool ApplyPassword(String^ password);
	};
}
