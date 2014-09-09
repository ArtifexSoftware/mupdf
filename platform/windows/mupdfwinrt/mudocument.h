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
				RenderPageAsync(int page_num, int width, int height, 
								bool use_dlist, float scale);
			int RenderPageBitmapSync(int page_num, int bmp_width, int bmp_height,
				float scale, bool use_dlist, bool flipy, bool tiling, Point top_left,
				Point bottom_right, Array<unsigned char>^* bit_map);
			Windows::Foundation::IAsyncOperationWithProgress<int, double>^
				SearchDocumentWithProgressAsync(String^ textToFind, int dir, 
												int start_page, int num_pages);
			String^ ComputeHTML(int page_num);
			int ComputeTextSearch(String^ text, int page_num);
			Links^ GetTextSearch(unsigned int k);
			int TextSearchCount(void);
			unsigned int ComputeContents(void);
			ContentItem^ GetContent(unsigned int k);
			unsigned int ComputeLinks(int page_num);
			Links^ GetLink(unsigned int k);
			bool RequiresPassword();
			bool ApplyPassword(String^ password);
	};
}
