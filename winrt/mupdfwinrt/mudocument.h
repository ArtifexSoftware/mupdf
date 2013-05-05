#pragma once

/* This file contains the WinRT API interface between the muctx class which 
   implements the mupdf calls and the WinRT objects enabling calling from 
   C#, C++, Visual Basic, JavaScript applications */

#include "muctx.h"
#include "Links.h"
#include "ppltasks.h"
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
    public:
        mudocument();
        Windows::Foundation::IAsyncAction^ OpenFile(StorageFile^ file);
        int GetNumPages();
        Point GetPageSize(int page_num);
        Windows::Foundation::IAsyncOperation<InMemoryRandomAccessStream^>^  
            RenderPage(int page_num, int width, int height);
        int ComputeLinks(int page_num);
        Links^ GetLink(int k);
        int ComputeTextSearch(String^ text, int page_num);
        
    };
}