//
// MainPage.xaml.cpp
// Implementation of the MainPage class.
//

#include "pch.h"
#include "MainPage.xaml.h"

#define LOOK_AHEAD 1 /* A +/- count on the pages to pre-render */
#define MIN_SCALE 0.5
#define MAX_SCALE 4
#define MARGIN_BUFF 400
#define MAX_SEARCH 500
#define SCALE_THUMB 0.1 

#define BLANK_WIDTH 17
#define BLANK_HEIGHT 22

static float screenScale = 1;

int linkPage[MAX_SEARCH];
char *linkUrl[MAX_SEARCH];

using namespace mupdf_cpp;

using namespace Windows::Foundation;
using namespace Windows::UI::Xaml;
using namespace Windows::UI::Xaml::Controls;
using namespace Windows::UI::Xaml::Controls::Primitives;
using namespace Windows::UI::Xaml::Data;
using namespace Windows::UI::Xaml::Media;
using namespace Windows::UI::Xaml::Navigation;
using namespace Windows::Graphics::Display;

//****************** Added *****************
using namespace Windows::Storage::Pickers;
using namespace Windows::Devices::Enumeration;
using namespace concurrency;
using namespace Windows::Graphics::Imaging;
//****************** End Add ****************

#ifndef NDEBUG
unsigned int _mainThreadId = 0U;

#ifdef  __cplusplus
extern "C" {
#endif

    // The IsMainThread function returns true if the current thread is the app's main thread and false otherwise.
    bool IsMainThread()
    {
        return (_mainThreadId == GetCurrentThreadId());
    }

    // The IsBackgroundThread function returns false if the current thread is the app's main thread and true otherwise.
    bool IsBackgroundThread()
    {
        return (_mainThreadId != GetCurrentThreadId());
    }

    // The RecordMainThread function registers the main thread ID for use by the IsMainThread and IsBackgroundThread functions.
    void RecordMainThread()
    {
        _mainThreadId = GetCurrentThreadId();
    }

#ifdef  __cplusplus
}
#endif

#endif /* not NDEBUG */

MainPage::MainPage()
{
	InitializeComponent();

    Windows::UI::Color color;
    color.R = 0x00;
    color.G = 0x00;
    color.B = 0xFF;
    color.A = 0x40;
    m_textcolor_brush = ref new SolidColorBrush(color);

    color.R = 0xAC;
    color.G = 0x72;
    color.B = 0x25;
    color.A = 0x40;
    m_linkcolor_brush = ref new SolidColorBrush(color);

    // Create the image brush
    m_renderedImage = ref new ImageBrush();
    mu_doc = nullptr;
    m_docPages = ref new Platform::Collections::Vector<DocumentPage^>();
    CleanUp();
    RecordMainThread();
    mu_doc = ref new mudocument(); 
    if (mu_doc == nullptr)
        throw ref new FailureException("Document allocation failed!");
}

/// <summary>
/// Invoked when this page is about to be displayed in a Frame.
/// </summary>
/// <param name="e">Event data that describes how this page was reached.  The Parameter
/// property is typically used to configure the page.</param>
void MainPage::OnNavigatedTo(NavigationEventArgs^ e)
{
	(void) e;	// Unused parameter
}

void mupdf_cpp::MainPage::ExitInvokedHandler(Windows::UI::Popups::IUICommand^ command)
{

}

void mupdf_cpp::MainPage::OKInvokedHandler(Windows::UI::Popups::IUICommand^ command)
{

}

void mupdf_cpp::MainPage::NotifyUser(String^ strMessage, NotifyType_t type)
{
    MessageDialog^ msg = ref new MessageDialog(strMessage);
    UICommand^ ExitCommand = nullptr;
    UICommand^  OKCommand = nullptr;

    switch (type)
    {
    case StatusMessage:
        OKCommand = ref new UICommand("OK", 
            ref new UICommandInvokedHandler(this, &mupdf_cpp::MainPage::OKInvokedHandler));        
         msg->Commands->Append(OKCommand);
        /// Set the command that will be invoked by default
        msg->DefaultCommandIndex = 0;
        // Set the command to be invoked when escape is pressed
        msg->CancelCommandIndex = 1;
        break;
    case ErrorMessage:
        ExitCommand = ref new UICommand("Exit", 
            ref new UICommandInvokedHandler(this, &mupdf_cpp::MainPage::ExitInvokedHandler));
        msg->Commands->Append(ExitCommand);
        /// Set the command that will be invoked by default
        msg->DefaultCommandIndex = 0;
        // Set the command to be invoked when escape is pressed
        msg->CancelCommandIndex = 1;
        break;
    default:
        break;
    }
    // Show the message dialog
    msg->ShowAsync();
}

bool mupdf_cpp::MainPage::EnsureUnsnapped()
{
    // FilePicker APIs will not work if the application is in a snapped state.
    // If an app wants to show a FilePicker while snapped, it must attempt to unsnap first

    bool unsnapped = (ApplicationView::Value != ApplicationViewState::Snapped  || 
        ApplicationView::TryUnsnap());
    if (!unsnapped)
    {
        NotifyUser("Cannot unsnap the application", StatusMessage);
    }
    return unsnapped;
}

void mupdf_cpp::MainPage::Picker(Platform::Object^ sender, Windows::UI::Xaml::RoutedEventArgs^ e)
{
    if (!EnsureUnsnapped())
        return;

    FileOpenPicker^ openPicker = ref new FileOpenPicker();
	openPicker->ViewMode = PickerViewMode::List;
	openPicker->SuggestedStartLocation = PickerLocationId::PicturesLibrary;
    openPicker->FileTypeFilter->Append(".pdf");
    openPicker->FileTypeFilter->Append(".xps");
    openPicker->FileTypeFilter->Append(".oxps");

	create_task(openPicker->PickSingleFileAsync()).then([this](StorageFile^ file) 
	{ 
		if (file) 
		{ 		
            this->OpenDocumentPrep(file);
		} 
		else 
		{ 
			/* Nothing selected */
		} 
	});
}

/* Set the page with the new raster information */
void MainPage::UpdatePage(int page_num, InMemoryRandomAccessStream^ ras, 
                          Point ras_size, Page_Content_t content_type)
{
    assert(IsMainThread());

    WriteableBitmap ^bmp = ref new WriteableBitmap(ras_size.X, ras_size.Y);
    bmp->SetSource(ras);

    DocumentPage^ doc_page = ref new DocumentPage();
    doc_page->Image = bmp;

    if (content_type == THUMBNAIL)
    {
        doc_page->Height = ras_size.Y / SCALE_THUMB;
        doc_page->Width = ras_size.X / SCALE_THUMB;
    }
    else
    {
        doc_page->Height = ras_size.Y;
        doc_page->Width = ras_size.X;
    }
    doc_page->Content = content_type;

    /* We do not want flipview change notification to occur for ourselves */
    m_page_update = true;
    this->m_docPages->SetAt(page_num, doc_page);
    m_page_update = false;

}

Point MainPage::ComputePageSize(spatial_info_t spatial_info, int page_num)
{
    Point screenSize;
    Point pageSize;
    Point size = mu_doc->GetPageSize(page_num);

    screenSize = spatial_info.size;
	screenSize.Y *= screenScale;
	screenSize.X *= screenScale;

	float hscale = screenSize.X / size.X;
	float vscale = screenSize.Y / size.Y;
	float scale = min(hscale, vscale);
    pageSize.X = size.X * scale * spatial_info.scale_factor;
    pageSize.Y = size.Y * scale * spatial_info.scale_factor;

    return pageSize;
}

Point MainPage::currPageSize(int page)
{
	Point Size;

    FlipViewItem ^flipview_temp = (FlipViewItem^) m_curr_flipView->Items->GetAt(page);

    Size.Y = flipview_temp->ActualHeight;
    Size.X = flipview_temp->ActualWidth;
    return Size;
}

static Point fitPageToScreen(Point page, Point screen)
{
    Point pageSize;

	float hscale = screen.X / page.X;
	float vscale = screen.Y / page.Y;
	float scale = fz_min(hscale, vscale);
    pageSize.X = floorf(page.X * scale) / page.X;
	pageSize.Y = floorf(page.Y * scale) / page.Y;
	return pageSize;
}

spatial_info_t MainPage::InitSpatial(double scale)
{
    spatial_info_t value;

    value.size.Y = this->ActualHeight;
    value.size.X = this->ActualWidth;
    value.scale_factor = scale;
    return value;
}

void Prepare_bmp(int width, int height, DataWriter ^dw)
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

void MainPage::ReleasePages(int old_page, int new_page)
{
    if (old_page == new_page) return;
    /* To keep from having memory issue reset the page back to 
        the thumb if we are done rendering the thumbnails */
    for (int k = old_page - LOOK_AHEAD; k <= old_page + LOOK_AHEAD; k++) 
    {
        if (k < new_page - LOOK_AHEAD || k > new_page + LOOK_AHEAD) 
        {
            if (k >= 0 && k < this->m_num_pages)
            {
                SetThumb(k, true);
            }
        }
    }
}

void MainPage::InitThumbnails()
{
    this->m_thumbnails.raster = ref new Array<InMemoryRandomAccessStream^>(m_num_pages);
    this->m_thumbnails.scale = ref new Array<double>(m_num_pages);
    this->m_thumbnails.size = ref new Array<Point>(m_num_pages);
}

/* Return this page from a full res image to the thumb image or only set to thumb
   if it has not already been set */
void MainPage::SetThumb(int page_num, bool replace)
{
    /* See what is there now */
    auto doc = this->m_docPages->GetAt(page_num);
    if (doc->Content == THUMBNAIL) return;

    if ((replace || doc->Content == DUMMY) && this->m_thumbnails.raster[page_num] != nullptr) 
        UpdatePage(page_num, this->m_thumbnails.raster[page_num], 
                   this->m_thumbnails.size[page_num], THUMBNAIL);
}

/* Create white image for us to use as place holder in large document for flip
   view filling instead of the thumbnail image  */
void MainPage::CreateBlank(int width, int height)
{
    Array<unsigned char>^ bmp_data = ref new Array<unsigned char>(height * 4 * width);
    /* Set up the memory stream */
    WriteableBitmap ^bmp = ref new WriteableBitmap(width, height);
    InMemoryRandomAccessStream ^ras = ref new InMemoryRandomAccessStream();
    DataWriter ^dw = ref new DataWriter(ras->GetOutputStreamAt(0));
    /* Go ahead and write our header data into the memory stream */
    Prepare_bmp(width, height, dw);

    /* Set the data to all white */
    memset(bmp_data->Data, 255, height * 4 * width);

    /* Write the data */
    dw->WriteBytes(bmp_data);

    DataWriterStoreOperation^ result = dw->StoreAsync();
    /* Block on the Async call */
    while(result->Status != AsyncStatus::Completed) {
    }
    /* And store in a the image brush */
    bmp->SetSource(ras);
    m_BlankBmp = bmp;
}

void mupdf_cpp::MainPage::SetFlipView()
{
    int height = this->ActualHeight;
    int width = this->ActualWidth;

    CreateBlank(BLANK_WIDTH, BLANK_HEIGHT);
    /* Set the current flip view mode */
    if (height > width)
        this->m_curr_flipView = xaml_vert_flipView;
    else
        this->m_curr_flipView = xaml_horiz_flipView;
}

/* Clean up everything as we are opening a new document after having another
   one open */
void mupdf_cpp::MainPage::CleanUp()
{
    /* Remove current pages in the flipviews */
    if (xaml_vert_flipView->Items->Size) 
        xaml_vert_flipView->Items->Clear();

    if (xaml_horiz_flipView->Items->Size) 
        xaml_horiz_flipView->Items->Clear();

    this->m_curr_flipView = nullptr;
    m_currpage = -1;
    m_file_open = false;
    m_slider_min = 0;
    m_slider_max = 0;
    m_init_done = false;
    m_memory_use = 0;
    m_from_doubleflip = false;
    m_first_time = false;
    m_insearch = false;
    m_search_active = false;
    m_sliderchange = false;
    m_flip_from_searchlink = false;
    m_num_pages = -1;
    m_search_rect_count = 0;
    ResetSearch();
    m_ren_status = REN_AVAILABLE;
    m_thumb_page_start = 0;
    m_thumb_page_stop = 0;
    m_links_on = false;
    m_curr_zoom = 1.0;
    m_canvas_translate.X = 0;
    m_canvas_translate.Y = 0;

    this->xaml_PageSlider->Minimum = m_slider_min;
    this->xaml_PageSlider->Maximum = m_slider_max;
    this->xaml_PageSlider->IsEnabled = false;  
}

/* Create the thumbnail images */
void mupdf_cpp::MainPage::RenderThumbs()
{
    spatial_info_t spatial_info = this->InitSpatial(1);
    int num_pages = this->m_num_pages;
    int thumb_pages = this->m_thumb_page_start;
    cancellation_token_source cts;
    auto token = cts.get_token();
    m_ThumbCancel = cts;

    this->m_ren_status = REN_THUMBS;
    thumbs_t thumbnails = m_thumbnails;
    DWORD thread0_id = GetCurrentThreadId();

    create_task([spatial_info, num_pages, thumb_pages, thumbnails, this, thread0_id]()-> int
    {
        spatial_info_t spatial_info_local = spatial_info;
        spatial_info_local.scale_factor = SCALE_THUMB;

        InMemoryRandomAccessStream ^ras = ref new InMemoryRandomAccessStream();

        for (int k = thumb_pages; k < num_pages; k++)
        {
            Point ras_size = ComputePageSize(spatial_info_local, k);
            bool done = false;
            DWORD thread1_id = GetCurrentThreadId();
            auto task = create_task(mu_doc->RenderPage(k, ras_size.X, ras_size.Y)).then([this, k, ras_size, thumbnails, &done, thread1_id, thread0_id] (InMemoryRandomAccessStream^ ras)
            {
                DWORD thread2_id = GetCurrentThreadId();
                thumbnails.raster[k] = ras;
                thumbnails.scale[k] = SCALE_THUMB;
                thumbnails.size[k] = ras_size;
                done = true;
            }, task_continuation_context::use_current());  


            try
            {
                task.get();  // get exception
            }
            catch (Exception^ exception)
            {
            }

             /* Don't start new thumb until this one is finished, lest we launch a
               thousand thumbnail renderings */
            while (!done) 
            {
            }

            /* If cancelled then save the last one as the continuation will not
               have occured.  */
            if (is_task_cancellation_requested()) 
            {
                thumbnails.raster[k] = ras;
                thumbnails.scale[k] = SCALE_THUMB;
                thumbnails.size[k] = ras_size;
                this->m_thumb_page_stop = k + 1;
                
                cancel_current_task();
            }
        }
        return num_pages; /* all done with thumbnails! */
    }, token).then([this](task<int> the_task) 
    {
        int new_end;
        try
        {
           new_end = the_task.get();
        } 
        catch (const task_canceled& e)
        {
            new_end = this->m_thumb_page_stop;
        }

        int old_end = this->m_thumb_page_start;

        /* Now go ahead and create the proper stuctures */
        this->m_ren_status = REN_UPDATE_THUMB_CANVAS;
        this->m_thumb_page_start = new_end;

        for (int k = old_end; k < new_end; k++)
        {
            assert(IsMainThread());
            SetThumb(k, false);
        }
        this->m_ren_status = REN_AVAILABLE;
    }, task_continuation_context::use_current());
}

void mupdf_cpp::MainPage::OpenDocumentPrep(StorageFile^ file)
{
    if (this->m_num_pages != -1) 
    {
        m_init_done = false;
        /* If the thumbnail thread is running then we need to end that first */
        RenderingStatus_t *ren_status = &m_ren_status;
        cancellation_token_source *ThumbCancel = &m_ThumbCancel;

        /* Create a task to wait until the renderer is available, then clean up then open */
        auto t = create_task([ren_status, ThumbCancel]()->int
        {
            if (*ren_status == REN_THUMBS)
                ThumbCancel->cancel();
            while (*ren_status != REN_AVAILABLE) {
            }
            return 0;
        }).then([this](task<int> the_task)
        {
            CleanUp();
            return 0;
        }, task_continuation_context::use_current()).then([this, file](task<int> the_task)
        {
            OpenDocument(file);    
        }, task_continuation_context::use_current());
    }
    else
    {
        OpenDocument(file);    
    }
}

void mupdf_cpp::MainPage::OpenDocument(StorageFile^ file)
{
    String^ path = file->Path;
    const wchar_t *w = path->Data();
    int cb = WideCharToMultiByte(CP_UTF8, 0, w, -1, nullptr, 0, nullptr, nullptr);
	char* name = new char[cb];

    WideCharToMultiByte(CP_UTF8, 0, w ,-1 ,name ,cb ,nullptr, nullptr);
    char *ext = strrchr(name, '.');
        
    this->SetFlipView();

    /* Open document and when open, push on */
    auto open_task = create_task(mu_doc->OpenFile(file));

    open_task.then([this]
    {
        assert(IsMainThread());

        m_num_pages = mu_doc->GetNumPages();
        if ((m_currpage) >= m_num_pages) 
        {
            m_currpage = m_num_pages - 1;
        } 
        else if (m_currpage < 0) 
        {
            m_currpage = 0;
        }

         /* Initialize all the flipvew items with blanks */
        for (int k = 0; k < m_num_pages; k++) 
        {
            DocumentPage^ doc_page = ref new DocumentPage();
            doc_page->Image = this->m_BlankBmp;
            doc_page->Height = BLANK_HEIGHT;
            doc_page->Width = BLANK_WIDTH;
            doc_page->Content = DUMMY;
            this->m_docPages->Append(doc_page);
        }

        this->xaml_horiz_flipView->ItemsSource = m_docPages; 
        this->xaml_vert_flipView->ItemsSource = m_docPages;

        /* Do the first few pages, then start the thumbs */
        spatial_info_t spatial_info = InitSpatial(1);

        for (int k = 0; k < LOOK_AHEAD + 2; k++) 
        {
            if (m_num_pages > k ) 
            {
                Point ras_size = ComputePageSize(spatial_info, k);

                auto render_task = 
                    create_task(mu_doc->RenderPage(k, ras_size.X, ras_size.Y));

                render_task.then([this, k, ras_size] (InMemoryRandomAccessStream^ ras)
                {
                    /* Set up the image brush when rendering is completed, must be on
                       UI thread */
                    UpdatePage(k, ras, ras_size, FULL_RESOLUTION);
                }, task_continuation_context::use_current());
            }
        }

        /* Update the slider settings, if more than one page */
        if (m_num_pages > 1) 
        {
            this->xaml_PageSlider->Maximum = m_num_pages;
            this->xaml_PageSlider->Minimum = 1;
            this->xaml_PageSlider->IsEnabled = true;
        } 
        else
        {
            this->xaml_PageSlider->Maximum = 0;
            this->xaml_PageSlider->Minimum = 0;
            this->xaml_PageSlider->IsEnabled = false;
        }
        /* All done with initial pages */
        this->m_init_done = true;
    }).then([this]
    {
        InitThumbnails();
        this->RenderThumbs();
    }, task_continuation_context::use_current());
}

task<int> mupdf_cpp::MainPage::RenderRange(int curr_page)
{
    /* Render +/- the look ahead from where we are if blank page is present */
    spatial_info_t spatial_info = InitSpatial(1);

    RenderingStatus_t *ren_status = &m_ren_status;
    cancellation_token_source *ThumbCancel = &m_ThumbCancel;

    /* Create a task to wait until the renderer is available */
    auto t = create_task([ren_status, ThumbCancel]()
    {
        if (*ren_status == REN_THUMBS)
            ThumbCancel->cancel();
        while (*ren_status != REN_AVAILABLE) {
        }
    });
        
    return t.then([this, curr_page, spatial_info]()
    {
        assert(IsMainThread());
        int val = 0;
        /* This runs on the main ui thread */
        for (int k = curr_page - LOOK_AHEAD; k <= curr_page + LOOK_AHEAD; k++) 
        {
            if (k >= 0 && k < m_num_pages) 
            {
                /* Check if page is already rendered */
                auto doc = this->m_docPages->GetAt(k);
                if (doc->Content != FULL_RESOLUTION) 
                {
                    Point ras_size = ComputePageSize(spatial_info, k);
                    auto render_task = 
                        create_task(mu_doc->RenderPage(k, ras_size.X, ras_size.Y));

                    render_task.then([this, k, ras_size] (InMemoryRandomAccessStream^ ras)
                    {
                        /* Set up the image brush when rendering is completed, must be on
                           UI thread */
                        UpdatePage(k, ras, ras_size, FULL_RESOLUTION);
                        this->m_ren_status = REN_AVAILABLE;                    
                    }, task_continuation_context::use_current());
                }
            }
        } 
        Canvas^ link_canvas = (Canvas^) (this->FindName("linkCanvas"));
        if (link_canvas != nullptr)
        {
            Canvas^ Parent_Canvas = (Canvas^) link_canvas->Parent;
            if (Parent_Canvas != nullptr)
            {
                Parent_Canvas->Children->RemoveAtEnd();
                delete link_canvas;
            }
        }
        m_currpage = curr_page;
        if (this->m_links_on) 
        {
            AddLinkCanvas();
        }
        /* Check if thumb rendering is done.  If not then restart */
        if (this->m_num_pages != this->m_thumb_page_start)
            this->RenderThumbs();
        return val;
    }, task_continuation_context::use_current());
}

void mupdf_cpp::MainPage::Slider_Released(Platform::Object^ sender, Windows::UI::Xaml::Controls::Primitives::RangeBaseValueChangedEventArgs^ e)
{
    /* Check if thumb rendering is done.  If not then restart */
    if (this->m_num_pages != this->m_thumb_page_start)
        this->RenderThumbs();
}

void mupdf_cpp::MainPage::Slider_ValueChanged(Platform::Object^ sender, Windows::UI::Xaml::Controls::Primitives::RangeBaseValueChangedEventArgs^ e)
{
    int newValue = (int) this->xaml_PageSlider->Value - 1;  /* zero based */
    RenderingStatus_t *ren_status = &m_ren_status;
    cancellation_token_source *ThumbCancel = &m_ThumbCancel;

    if (m_update_flip)
    {
        m_update_flip = false;
        return;
    }
    if (m_init_done && this->xaml_PageSlider->IsEnabled) 
    {
        auto doc = this->m_docPages->GetAt(newValue);
        if (doc->Content != FULL_RESOLUTION) 
        {
            create_task([ren_status, ThumbCancel]()
            {
                if (*ren_status == REN_THUMBS)
                    ThumbCancel->cancel();
                while (*ren_status != REN_AVAILABLE) {
                }
            }).then([this, newValue]() 
            {
                spatial_info_t spatial_info = InitSpatial(1);
                Point ras_size = ComputePageSize(spatial_info, newValue);
                auto render_task = 
                    create_task(mu_doc->RenderPage(newValue, ras_size.X, ras_size.Y));

                render_task.then([this, newValue, ras_size] (InMemoryRandomAccessStream^ ras)
                {
                    UpdatePage(newValue, ras, ras_size, FULL_RESOLUTION);
                    this->m_ren_status = REN_AVAILABLE;  
                    this->m_currpage = newValue;
                    m_sliderchange = true;
                    this->m_curr_flipView->SelectedIndex = newValue;
                    ResetSearch(); 
                }, task_continuation_context::use_current());
            }, task_continuation_context::use_current());
        }
    }
}

void mupdf_cpp::MainPage::FlipView_SelectionChanged(Object^ sender, SelectionChangedEventArgs^ e)
{
    if (m_init_done && !m_page_update)
    {
        int pos = this->m_curr_flipView->SelectedIndex;

        m_update_flip = true;
        if (xaml_PageSlider->IsEnabled)
        {
            xaml_PageSlider->Value = pos;
        }
        if (pos >= 0) 
        {
            if (m_flip_from_searchlink)
            {
                m_flip_from_searchlink = false;
                return;
            } 
            else if (m_sliderchange)
            {
                m_sliderchange = false;
                return;
            }
            else
            {
                ResetSearch();
            }
            /* Get the current page */
            int curr_page = this->m_currpage;
            task<int> task = this->RenderRange(pos);
            task.then([this, curr_page, pos](int val)
            {
                this->ReleasePages(curr_page, pos);
            }, task_continuation_context::use_current());
        }
    }
}

/* Search Related Code */

void mupdf_cpp::MainPage::Searcher(Platform::Object^ sender, Windows::UI::Xaml::RoutedEventArgs^ e)
{
    /* Update the app bar so that we can do the search */
    StackPanel^ leftPanel = (StackPanel^) this->TopAppBar->FindName("LeftPanel");

	if (leftPanel != nullptr && m_insearch)
    {
        m_insearch = false;
        leftPanel->Children->RemoveAtEnd();
        leftPanel->Children->RemoveAtEnd();
        leftPanel->Children->RemoveAtEnd();
    }
    else if (leftPanel != nullptr && !m_insearch)
	{
        /* Search is not going to work in snapped view for now to simplify UI 
           in this cramped case.  So see if we can get out of snapped mode. */

        if (!EnsureUnsnapped())
            return;

        m_insearch = true;
	    Windows::UI::Xaml::Controls::Button^ PrevButton = ref new Button();
        PrevButton->Style = safe_cast<Windows::UI::Xaml::Style^>(App::Current->Resources->Lookup("PreviousAppBarButtonStyle"));
	    PrevButton->Click += ref new RoutedEventHandler(this, &mupdf_cpp::MainPage::SearchPrev);
        
	    Windows::UI::Xaml::Controls::Button^ NextButton = ref new Button();
        NextButton->Style = safe_cast<Windows::UI::Xaml::Style^>(App::Current->Resources->Lookup("NextAppBarButtonStyle"));
	    NextButton->Click += ref new RoutedEventHandler(this, &mupdf_cpp::MainPage::SearchNext);

        Windows::UI::Xaml::Controls::TextBox^ SearchBox = ref new TextBox();
        SearchBox->Name = "findBox";
        SearchBox->Width = 200;
        SearchBox->Height = 20;
        
        leftPanel->Children->Append(SearchBox);
        leftPanel->Children->Append(PrevButton);
        leftPanel->Children->Append(NextButton);
	}
}

void mupdf_cpp::MainPage::ShowSearchResults(SearchResult_t result)
{
    int height, width;
    int old_page = this->m_currpage;
    int new_page = result.page_num;
    spatial_info_t spatial_info = InitSpatial(1);
    return;

    /* This will be fixed and turned on when I determine how best to show the
       canvas and bind to the xmal content */
#if 0
    this->m_ren_status = REN_PAGE;
    task<Canvas^> the_task = RenderPage_Task(m_doc, new_page, &width, &height, 
                                         spatial_info, &m_renderedImage);
    the_task.then([this, old_page, new_page](task<Canvas^> the_task)
    {
        assert(IsMainThread());

        try
        {
           this->m_renderedCanvas = the_task.get();
        } 
        catch (const task_canceled& e)
        {
            this->m_renderedCanvas = nullptr;
        }
        ReplacePage(new_page);
        this->m_ren_status = REN_AVAILABLE;
        this->ReleasePages(old_page, new_page);
    }, task_continuation_context::use_current()).then([this, result]() 
    
    {
        /* Once the rendering is done launch this task to show the result */
        Point screenSize;
        Point pageSize;
        Point scale;

        if (this->m_links_on) 
        {
            fz_drop_link(ctx, this->m_links);
            AddLinkCanvas();
        }
	    fz_page *page = fz_load_page(m_doc, result.page_num);
        FlipViewItem ^flipview_temp = (FlipViewItem^) m_curr_flipView->Items->GetAt(result.page_num);
        Canvas^ results_Canvas = (Canvas^) (flipview_temp->Content);

        m_searchpage = result.page_num;

        screenSize.Y = this->ActualHeight;
        screenSize.X = this->ActualWidth;

	    screenSize.X *= screenScale;
	    screenSize.Y *= screenScale;
    
        pageSize = measurePage(m_doc, page);
	    scale = fitPageToScreen(pageSize, screenSize);

        /* Now add the rects */
        for (int k = 0; k < result.box_count && k < MAX_SEARCH; k++) 
        {
            /* Create a new ref counted Rectangle */
            Rectangle^ a_rectangle = ref new Rectangle();
            TranslateTransform ^trans_transform = ref new TranslateTransform();
            a_rectangle->Width = hit_bbox[k].x1 - hit_bbox[k].x0;
            a_rectangle->Height = hit_bbox[k].y1 - hit_bbox[k].y0;
            trans_transform->X = hit_bbox[k].x0 * scale.X;
            trans_transform->Y = hit_bbox[k].y0 *  scale.Y;
		    a_rectangle->Width *= scale.X;
		    a_rectangle->Height *= scale.Y;
            a_rectangle->RenderTransform = trans_transform;
            a_rectangle->Fill = m_textcolor_brush;
            results_Canvas->Children->Append(a_rectangle);
            m_search_rect_count += 1;
        }
        if (result.box_count > 0)
        {
            m_flip_from_searchlink = true;
            this->m_curr_flipView->SelectedIndex = result.page_num;
            m_currpage = result.page_num;
        }
    }, task_continuation_context::use_current());
#endif
}

void mupdf_cpp::MainPage::SearchNext(Platform::Object^ sender, Windows::UI::Xaml::RoutedEventArgs^ e)
{
    StackPanel^ leftPanel = (StackPanel^) this->TopAppBar->FindName("LeftPanel");
    TextBox^ findBox = (TextBox^) leftPanel->FindName("findBox");
    String^ textToFind = findBox->Text;
    RenderingStatus_t *ren_status = &m_ren_status;
    cancellation_token_source *ThumbCancel = &m_ThumbCancel;

    /* Create a task to wait until the renderer is available */
    create_task([ren_status, ThumbCancel]()
    {
        if (*ren_status == REN_THUMBS)
            ThumbCancel->cancel();
        while (*ren_status != REN_AVAILABLE) {
            }
    }).then([this, textToFind]() 
    {
        if (this->m_search_active == false)
            SearchInDirection(1, textToFind);
    }, task_continuation_context::use_current());
}

void mupdf_cpp::MainPage::SearchPrev(Platform::Object^ sender, Windows::UI::Xaml::RoutedEventArgs^ e)
{
    StackPanel^ leftPanel = (StackPanel^) this->TopAppBar->FindName("LeftPanel");
    TextBox^ findBox = (TextBox^) leftPanel->FindName("findBox");
    String^ textToFind = findBox->Text;
    RenderingStatus_t *ren_status = &m_ren_status;
    cancellation_token_source *ThumbCancel = &m_ThumbCancel;

    /* Create a task to wait until the renderer is available */
    create_task([ren_status, ThumbCancel]()
    {
        if (*ren_status == REN_THUMBS)
            ThumbCancel->cancel();
        while (*ren_status != REN_AVAILABLE) {
        }
    }).then([this, textToFind]() 
    {
        if (this->m_search_active == false)
            SearchInDirection(-1, textToFind);
    }, task_continuation_context::use_current());
}

void mupdf_cpp::MainPage::CancelSearch(Platform::Object^ sender, Windows::UI::Xaml::RoutedEventArgs^ e)
{
   m_searchcts.cancel();
}

void mupdf_cpp::MainPage::ResetSearch(void)
{
	m_searchpage = -1;
#if 0
    wchar_t buf[20];
    String^ TempString = ref new String(buf);

    /*  Remove all the rects */
    for (int k = 0; k < this->m_search_rect_count; k++)
    {
        unsigned int index;
        int len = swprintf_s(buf, 20, L"%s_%d", L"Rect",k);
        Rectangle^ curr_rect = (Rectangle^) (m_curr_flipView->FindName(TempString));
        if (curr_rect != nullptr)
        {
            Canvas^ results_Canvas = (Canvas^) curr_rect->Parent;
            results_Canvas->Children->IndexOf(curr_rect, &index);
            results_Canvas->Children->RemoveAt(index);
        }
    }
#endif
}

void mupdf_cpp::MainPage::SearchInDirection(int dir, String^ textToFind)
{
    cancellation_token_source cts;
    auto token = cts.get_token();
    m_searchcts = cts;
    int pos = m_currpage;
    int start;
    SearchResult_t result;

    result.box_count = 0;
    result.page_num = -1;

	if (m_searchpage == pos)
		start = pos + dir;
	else
		start = pos;

 /*   ProgressBar^ my_xaml_Progress = (ProgressBar^) (this->FindName("xaml_Progress"));
    my_xaml_Progress->Value = start;
    my_xaml_Progress->IsEnabled = true;
    my_xaml_Progress->Opacity = 1.0; */

 /*   ProgressBar^ my_bar = (ProgressBar^) (xaml_MainGrid->FindName("search_progress"));

    if (my_bar == nullptr)
    {
        my_bar = ref new ProgressBar();
        my_bar->Name = "search_progress";
        my_bar->Maximum = this->m_num_pages;
        my_bar->Value = start;
        my_bar->IsIndeterminate = false;
        my_bar->Height = 10; 
        my_bar->Width = 400;
        xaml_MainGrid->Children->Append(my_bar);
    }
    else
    {
        my_bar->Value = start;
    }  */
    this->m_search_active = true;

    /* Do task lambdas here to avoid UI blocking issues */
    auto search_task = create_task([this, textToFind, dir, start, &result]()->SearchResult_t
    {
		for (int i = start; i >= 0 && i < this->m_num_pages; i += dir) 
        {
            result.box_count = this->mu_doc->ComputeTextSearch(textToFind, i);
            result.page_num = i;

            //my_xaml_Progress->Value = i;
			if (result.box_count > 0) 
            {
                return result;
			}
            if (is_task_cancellation_requested()) 
            {
            }
        }
        /* Todo no matches found alert */
        return result;
    }, token);
    /* Do the continuation on the ui thread */
    search_task.then([this](task<SearchResult_t> the_task)
    {
        SearchResult_t the_result = the_task.get();
        if (the_result.box_count > 0) 
        {
          //  ProgressBar^ xaml_Progress = (ProgressBar^) (this->FindName("xaml_Progress"));
         //   xaml_Progress->IsEnabled = false;
          //  xaml_Progress->Opacity = 0.0;
            this->ShowSearchResults(the_result);
        }
        this->m_search_active = false;
    }, task_continuation_context::use_current());
}

/* This is here to handle when we rotate or go into the snapview mode 
   ToDo  add in data binding to change the scroll direction */
void mupdf_cpp::MainPage::GridSizeChanged()
{
    int height = this->ActualHeight;
    int width = this->ActualWidth;
    FlipView^ old_flip = m_curr_flipView;


    if (TopAppBar1->IsOpen)
    {
        UpdateAppBarButtonViewState();
    }

    if (height > width)
    {
        m_curr_flipView = this->xaml_vert_flipView;
        if (!m_zoom_mode)
        {
            this->xaml_zoomCanvas->Height = height;
            this->xaml_zoomCanvas->Width = width;
            this->m_curr_flipView->Height = height;
            this->m_curr_flipView->Width = width;
        }
        xaml_vert_flipView->IsEnabled = true;
        xaml_vert_flipView->Opacity = 1;
        xaml_horiz_flipView->IsEnabled = false;
        xaml_horiz_flipView->Opacity = 0;    }
    else
    {
        m_curr_flipView = this->xaml_horiz_flipView;
        if (!m_zoom_mode)
        {
            this->xaml_zoomCanvas->Height = height;
            this->xaml_zoomCanvas->Width = width;
            this->m_curr_flipView->Height = height;
            this->m_curr_flipView->Width = width;
        }
        xaml_horiz_flipView->IsEnabled = true;
        xaml_horiz_flipView->Opacity = 1;
        xaml_vert_flipView->IsEnabled = false;
        xaml_vert_flipView->Opacity = 0;
    }

    if (xaml_RichText->Visibility == Windows::UI::Xaml::Visibility::Visible)
    {
        int height = xaml_OutsideGrid->ActualHeight;
        int height_app = TopAppBar1->ActualHeight;
  
        xaml_RichText->Height = height - height_app;
    }

    UpDatePageSizes();

    if (m_num_pages > 0 && old_flip != m_curr_flipView && old_flip != nullptr)
    {
        if ((this->m_curr_flipView->SelectedIndex == this->m_currpage) && this->m_links_on)
            FlipView_SelectionChanged(nullptr, nullptr);
        else
            this->m_curr_flipView->SelectedIndex = this->m_currpage;
    }
}

void mupdf_cpp::MainPage::UpDatePageSizes()
{
    /* Render our current pages at the new resolution and rescale the thumbnail 
       canvas if needed */
    if (m_num_pages > 0)
    {
        for (int i = 0; i < m_num_pages; i++)
        {
            FlipViewItem ^flipview_temp = (FlipViewItem^) m_curr_flipView->Items->GetAt(i);
            if (flipview_temp != nullptr && flipview_temp->Content != nullptr)
            {
                Canvas^ curr_canvas = (Canvas^) flipview_temp->Content;
                int curr_canvas_height = curr_canvas->Height;
                int curr_canvas_width = curr_canvas->Width;

                double scale_x = (double) curr_canvas_height / (double) this->xaml_zoomCanvas->Height;
                double scale_y = (double) curr_canvas_width / (double) this->xaml_zoomCanvas->Width;

                double min_scale = max(scale_x, scale_y);
                curr_canvas->Height = curr_canvas_height / min_scale;
                curr_canvas->Width = curr_canvas_width / min_scale;
            }
        }  
    }
};

void mupdf_cpp::MainPage::ClearLinksCanvas()
{
    Canvas^ link_canvas = (Canvas^) (this->FindName("linkCanvas"));
    if (link_canvas != nullptr) 
    {
        Canvas^ Parent_Canvas = (Canvas^) link_canvas->Parent;
        if (Parent_Canvas != nullptr)
        {
            Parent_Canvas->Children->RemoveAtEnd();
            delete link_canvas;
        }
    }
}

/* Link related code */
void mupdf_cpp::MainPage::Linker(Platform::Object^ sender, Windows::UI::Xaml::RoutedEventArgs^ e)
{
    m_links_on = !m_links_on;
    RenderingStatus_t *ren_status = &m_ren_status;
    cancellation_token_source *ThumbCancel = &m_ThumbCancel;
        
    if (m_links_on)
    {
       auto t = create_task([ren_status, ThumbCancel]()
        {
            if (*ren_status == REN_THUMBS)
                ThumbCancel->cancel();
            while (*ren_status != REN_AVAILABLE) {
            }
        });
        
        t.then([this]()
        {
            AddLinkCanvas();
        }, task_continuation_context::use_current());
    }
    else
        ClearLinksCanvas();
}

void mupdf_cpp::MainPage::AddLinkCanvas()
{
    return;
    /* This is disabled for now until I figure out how to add the canvas 
       with rects into the data template for the scroll view object */
    if (m_links_on)
    {
        ClearLinksCanvas();

        int num_links = mu_doc->ComputeLinks(m_currpage);
        if (num_links == 0) return;

        Point screenSize;
        Point pageSize;
        Point scale;

        screenSize.Y = this->ActualHeight;
        screenSize.X = this->ActualWidth;
        screenSize.X *= screenScale;
        screenSize.Y *= screenScale;
        pageSize = mu_doc->GetPageSize(m_currpage);
        scale = fitPageToScreen(pageSize, screenSize);

        /* A new canvas */
        Canvas^ link_canvas = ref new Canvas(); 
        link_canvas->Name = "linkCanvas";

        /* Get current scrollview item */
        auto currItem = m_curr_flipView->ItemContainerGenerator->ContainerFromItem(m_curr_flipView->SelectedItem);
        if (currItem == nullptr)
        {
            return;
        }

        FlipViewItem ^flipview_temp = (FlipViewItem^) m_curr_flipView->Items->GetAt(m_currpage);
        Canvas^ curr_canvas = (Canvas^) flipview_temp->Content;

        link_canvas->Height = curr_canvas->Height;
        link_canvas->Width = curr_canvas->Width;
        curr_canvas->Children->Append(link_canvas);

        /* Now add the rects */
        for (int k = 0; k < num_links; k++)
        {
            auto curr_link = mu_doc->GetLink(k);
            if (curr_link->Type != NOT_SET)
            {
                Rectangle^ a_rectangle = ref new Rectangle();
                TranslateTransform ^trans_transform = ref new TranslateTransform();

                a_rectangle->IsTapEnabled = true;
                a_rectangle->Width = curr_link->LowerRight.X - curr_link->UpperLeft.X;
                a_rectangle->Height = curr_link->UpperLeft.Y - curr_link->LowerRight.Y;
                trans_transform->X = curr_link->UpperLeft.X * scale.X;
                trans_transform->Y = curr_link->UpperLeft.Y *  scale.Y;
		        a_rectangle->Width *= scale.X;
		        a_rectangle->Height *= scale.Y;
                a_rectangle->RenderTransform = trans_transform;
                a_rectangle->Fill = m_linkcolor_brush;
                link_canvas->Children->Append(a_rectangle);
            }
        }
    }
}

bool mupdf_cpp::MainPage::CheckRect(Rectangle^ curr_rect, Point pt)
{
    TranslateTransform ^trans_transform = (TranslateTransform^) curr_rect->RenderTransform;
    Point rect_start;
    Point rect_end;

    rect_start.X = trans_transform->X;
    rect_start.Y = trans_transform->Y;
    rect_end.X = rect_start.X + curr_rect->Width;
    rect_end.Y = rect_start.Y + curr_rect->Height;
    if ((rect_start.X < pt.X) && (pt.X < rect_end.X) && (rect_start.Y < pt.Y) && (pt.Y < rect_end.Y)) 
        return true;
    return false;
}

void mupdf_cpp::MainPage::Canvas_Single_Tap(Platform::Object^ sender, Windows::UI::Xaml::Input::TappedRoutedEventArgs^ e)
{
    /* See if we are currently viewing any links */
    if (m_links_on)
    {
        Point pt;
        Canvas^ link_canvas = (Canvas^) (m_curr_flipView->FindName("linkCanvas"));
        if (link_canvas != nullptr)
        {
            pt = e->GetPosition(link_canvas);
            IIterator<UIElement^> ^it = link_canvas->Children->First();
            int count = 0;
            while (it->HasCurrent)
            {
                Rectangle^ curr_rect = (Rectangle^) (it->Current);
                if (CheckRect(curr_rect, pt))
                {
                    int page = JumpToLink(count);
                    if (page >= 0)
                        this->m_curr_flipView->SelectedIndex = page;
                    return;
                }
                it->MoveNext();
                count += 1;
            }
        }
    }
}

/* Window string hurdles.... */
static String^ char_to_String(char *char_in)
{
        size_t size = MultiByteToWideChar(CP_UTF8, 0, char_in, -1, NULL, 0);
        wchar_t *pw;
        pw = new wchar_t[size];
        if (!pw)
        {
            delete []pw;
            return nullptr;
        }
        MultiByteToWideChar (CP_UTF8, 0, char_in, -1, pw, size );
        String^ str_out = ref new String(pw);
        delete []pw;
        return str_out;
}

int mupdf_cpp::MainPage::JumpToLink(int index)
{    
    auto link = mu_doc->GetLink(index);

    if (link->Type == LINK_GOTO)
    {
        return link->PageNum;
    } 
    else if (link->Type == LINK_URI)
    {
        // Set the option to show a warning
        auto launchOptions = ref new Windows::System::LauncherOptions();
        launchOptions->TreatAsUntrusted = true;

        // Launch the URI with a warning prompt
        concurrency::task<bool> launchUriOperation(Windows::System::Launcher::LaunchUriAsync(link->Uri, launchOptions));
        launchUriOperation.then([](bool success)
       {
          if (success)
          {
             // URI launched
          }
          else
          {
             // URI launch failed
          }
       });
       return -1;
    }
    return 0;
}

/* Bring up the contents */
void mupdf_cpp::MainPage::ContentDisplay(Platform::Object^ sender, Windows::UI::Xaml::RoutedEventArgs^ e)
{
    if (this->m_num_pages < 0) 
        return;

    if (this->xaml_ListView->IsEnabled) 
    {
        this->xaml_ListView->Opacity = 0.0;
        this->xaml_ListView->IsEnabled = false;
        this->m_curr_flipView->Opacity = 1.0;
        this->m_curr_flipView->IsEnabled = true;
    } 
    else
    {
        if (xaml_ListView->Items->Size == 0)
        {
            /* Make sure we are good to go */
            RenderingStatus_t *ren_status = &m_ren_status;
            cancellation_token_source *ThumbCancel = &m_ThumbCancel;

            /* Create a task to wait until the renderer is available */
            auto t = create_task([ren_status, ThumbCancel]()
            {
                if (*ren_status == REN_THUMBS)
                    ThumbCancel->cancel();
                while (*ren_status != REN_AVAILABLE) {
                }
            }).then([this]()
            {
                int size_content = mu_doc->ComputeContents();
                /* Bring up the content now */
                for (int k = 0; k < size_content; k++)
                {
                    ContentItem^ item = mu_doc->GetContent(k);
                    this->xaml_ListView->Items->Append(item);
                }
                if (size_content > 0)
                {
                    this->xaml_ListView->Opacity = 1.0;
                    this->xaml_ListView->IsEnabled = true;
                    this->m_curr_flipView->Opacity = 0.0;
                    this->m_curr_flipView->IsEnabled = false;
                }
                /* Check if thumb rendering is done.  If not then restart */
                if (this->m_num_pages != this->m_thumb_page_start)
                    this->RenderThumbs();
            }, task_continuation_context::use_current());
        }  
        else 
        {
            this->xaml_ListView->Opacity = 1.0;
            this->xaml_ListView->IsEnabled = true;
            this->m_curr_flipView->Opacity = 0.0;
            this->m_curr_flipView->IsEnabled = false;
        }
    }  
}

void mupdf_cpp::MainPage::ContentSelected(Platform::Object^ sender, Windows::UI::Xaml::Controls::ItemClickEventArgs^ e)
{
    ContentItem^ b = safe_cast<ContentItem^>(e->ClickedItem);
    int newpage = b->Page;

    if (newpage > -1 && newpage < this->m_num_pages)
    {
        this->xaml_ListView->Opacity = 0.0;
        this->xaml_ListView->IsEnabled = false;
        this->m_curr_flipView->Opacity = 1.0;
        this->m_curr_flipView->IsEnabled = true;

        int old_page = this->m_currpage;
        this->m_curr_flipView->SelectedIndex = newpage;
        this->m_currpage = newpage;
    }
}

void mupdf_cpp::MainPage::Reflower(Platform::Object^ sender, Windows::UI::Xaml::RoutedEventArgs^ e)
{
#if 0
    if (this->m_num_pages < 0) return;

    if (xaml_RichText->Visibility == Windows::UI::Xaml::Visibility::Visible)
    {
        /* Go back to flip view */
        xaml_RichText->Visibility = Windows::UI::Xaml::Visibility::Collapsed;
        this->xaml_MainGrid->Opacity = 1.0;
        this->m_curr_flipView->IsEnabled = true;
            xaml_RichGrid->Visibility = Windows::UI::Xaml::Visibility::Collapsed;
            xaml_RichGrid->Opacity = 0.0;

    } 
    else if (this->m_curr_flipView->IsEnabled)
    {
        /* Only go from flip view to reflow */
        RenderingStatus_t *ren_status = &m_ren_status;
        cancellation_token_source *ThumbCancel = &m_ThumbCancel;
        /* Create a task to wait until the renderer is available */
        auto t = create_task([ren_status, ThumbCancel]()
        {
            if (*ren_status == REN_THUMBS)
                ThumbCancel->cancel();
            while (*ren_status != REN_AVAILABLE) {
            }
        }).then([this]()
        {
			fz_rect bounds;
            fz_output *out;
	        fz_page *page = fz_load_page(m_doc, this->m_currpage);
	        fz_text_sheet *sheet = fz_new_text_sheet(ctx);
	        fz_text_page *text = fz_new_text_page(ctx, &fz_empty_rect);
	        fz_device *dev = fz_new_text_device(ctx, sheet, text);

	        fz_run_page(m_doc, page, dev, &fz_identity, NULL);
	        fz_free_device(dev);
            dev = NULL;
			fz_text_analysis(ctx, sheet, text);
            fz_buffer *buf = fz_new_buffer(ctx, 256);
            out = fz_new_output_buffer(ctx, buf);
			fz_print_text_page(ctx, out, text);
            xaml_RichText->Visibility = Windows::UI::Xaml::Visibility::Visible;
            this->xaml_MainGrid->Opacity = 0.0;
            this->m_curr_flipView->IsEnabled = false;
            String^ html_string = char_to_String((char*) buf->data);

            xaml_RichGrid->Visibility = Windows::UI::Xaml::Visibility::Visible;
            xaml_RichGrid->Opacity = 1.0;
            int height = xaml_OutsideGrid->ActualHeight;
            int height_app = TopAppBar1->ActualHeight;
  
            xaml_RichText->Height = height - height_app;
            this->xaml_RichText->Document->SetText(Windows::UI::Text::TextSetOptions::FormatRtf, html_string);

            /* Check if thumb rendering is done.  If not then restart */
            if (this->m_num_pages != this->m_thumb_page_start)
                this->RenderThumbs();
        }, task_continuation_context::use_current());
    }
#endif
}

/* Need to handle resizing of app bar to make sure everything fits */

void mupdf_cpp::MainPage::topAppBar_Loaded(Platform::Object^ sender, Windows::UI::Xaml::RoutedEventArgs^ e)
{
    UpdateAppBarButtonViewState();
}

void mupdf_cpp::MainPage::UpdateAppBarButtonViewState()
{
    String ^viewState = Windows::UI::ViewManagement::ApplicationView::Value.ToString();
    VisualStateManager::GoToState(Search, viewState, true);
    VisualStateManager::GoToState(Contents, viewState, true);
    VisualStateManager::GoToState(Links, viewState, true);
    VisualStateManager::GoToState(Reflow, viewState, true);
    VisualStateManager::GoToState(Help, viewState, true); 
}

void mupdf_cpp::MainPage::ScrollChanged(Platform::Object^ sender, Windows::UI::Xaml::Controls::ScrollViewerViewChangedEventArgs^ e)
{

 int zz = 1;
}
