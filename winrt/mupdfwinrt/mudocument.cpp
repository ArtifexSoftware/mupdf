// mudocument.cpp

/* This file contains the interface between the muctx class, which 
   implements the mupdf calls and the WinRT objects enabling calling from 
   C#, C++, Visual Basic, JavaScript applications */

#include "pch.h"
#include "mudocument.h"

using namespace mupdfwinrt;
using namespace concurrency;
using namespace Platform::Collections;

mudocument::mudocument()
{
    this->mu_object.InitializeContext();
    this->links = nullptr;
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
    std::lock_guard<std::mutex> lock(mutex_lock);
    return this->mu_object.MeasurePage(page_num);
}

Windows::Foundation::IAsyncAction^ mudocument::OpenFile(StorageFile^ file)
{
    return create_async([this, file]()
    {
        String^ path = file->Path;
        const wchar_t *w = path->Data();
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
                    HRESULT code = this->mu_object.InitializeStream(readStream, ext);
                    return;
                }
                else
                {
                    delete readStream; 
                    return;
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

/* Pack the page into a bmp stream so that we can use it with an image brush */
Windows::Foundation::IAsyncOperation<InMemoryRandomAccessStream^>^ 
    mudocument::RenderPage(int page_num, int width, int height)
{
    return create_async([this, width, height, page_num](cancellation_token ct) -> InMemoryRandomAccessStream^
    {
        /* Allocate space for bmp */
        Array<unsigned char>^ bmp_data = ref new Array<unsigned char>(height * 4 * width);
        /* Set up the memory stream */
        InMemoryRandomAccessStream ^ras = ref new InMemoryRandomAccessStream();
        DataWriter ^dw = ref new DataWriter(ras->GetOutputStreamAt(0));

        /* Go ahead and write our header data into the memory stream */
        Prepare_bmp(width, height, dw);
    
        std::lock_guard<std::mutex> lock(mutex_lock);

        /* Get raster bitmap stream */
        HRESULT code = mu_object.RenderPage(page_num, width, height, &(bmp_data[0])); 
        if (code != S_OK) 
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
    std::lock_guard<std::mutex> lock(mutex_lock);
    /* We get back a standard smart pointer from muctx interface and go to WinRT
       type here */
    sh_vector_link link_smart_ptr_vec(new std::vector<sh_link>());
    int num_items = mu_object.GetLinks(page_num, link_smart_ptr_vec);
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
    std::lock_guard<std::mutex> lock(mutex_lock);
    /* We get back a standard smart pointer from muctx interface and go to WinRT
       type here */
    char* text_char = String_to_char(text);
    sh_vector_text text_smart_ptr_vec(new std::vector<sh_text>());

    int num_items = mu_object.GetTextSearch(page_num, text_char, text_smart_ptr_vec);
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
    return num_items;
}

Links^ mudocument::GetTextSearch(int k)
{
   if (k >= this->textsearch->Size)
       return nullptr;
   return this->textsearch->GetAt(k);
}

int mudocument::ComputeContents()
{
    std::lock_guard<std::mutex> lock(mutex_lock);
    /* We get back a standard smart pointer from muctx interface and go to WinRT
       type here */

    sh_vector_content content_smart_ptr_vec(new std::vector<sh_content>());

    int has_content = mu_object.GetContents(content_smart_ptr_vec);

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
    std::lock_guard<std::mutex> lock(mutex_lock);
    return mu_object.GetHTML(page_num);
}
