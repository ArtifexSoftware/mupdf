//
// MainPage.xaml.cpp
// Implementation of the MainPage class.
//

#include "pch.h"
#include "MainPage.xaml.h"

#define LOOK_AHEAD 10 /* A +/- count on the pages to pre-render */
#define MIN_SCALE 0.5
#define MAX_SCALE 4
#define MARGIN_BUFF 400
#define MAX_SEARCH 500

static float screenScale = 1;
static fz_context *ctx = NULL;

using namespace winapp;

using namespace Windows::Foundation;
using namespace Windows::Foundation::Collections;
using namespace Windows::UI::Xaml;
using namespace Windows::UI::Xaml::Controls;
using namespace Windows::UI::Xaml::Controls::Primitives;
using namespace Windows::UI::Xaml::Data;
using namespace Windows::UI::Xaml::Media;
using namespace Windows::UI::Xaml::Navigation;
using namespace Windows::UI::Xaml::Shapes;
using namespace Windows::Graphics::Display;

//****************** Added *****************
using namespace Windows::Storage::Pickers;
using namespace Windows::Devices::Enumeration;
using namespace concurrency;
using namespace Windows::Graphics::Imaging;
//****************** End Add ****************

typedef struct win_stream_struct_s
{
    IRandomAccessStream^ stream;
} win_stream_struct;
static win_stream_struct win_stream;

MainPage::MainPage()
{
	InitializeComponent();
    //Text Search Box
    Windows::UI::Color color;
    color.R = 0x25;
    color.G = 0x72;
    color.B = 0xAC;
    color.A = 0x40;

    m_color_brush = ref new SolidColorBrush(color);
    // Create the image brush
    m_renderedImage = ref new ImageBrush();
    m_doc = NULL;
    CleanUp();

	// use at most 128M for resource cache
	ctx = fz_new_context(NULL, NULL, 128<<20);
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

void winapp::MainPage::Picker(Platform::Object^ sender, Windows::UI::Xaml::RoutedEventArgs^ e)
{
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
            this->OpenDocument(file);
            /* File selected.  Start rendering and switch view. */
			//txtBlockOutput->Text = "Picked photo: " + file->Name;
		} 
		else 
		{ 
			/* Nothing selected */
		} 
	});
}

void MainPage::NotifyUserFileNotExist()
{
    //NotifyUser("The file '" + Filename + "' does not exist. Use scenario one to create this file.", NotifyType::ErrorMessage);
}

void MainPage::HandleFileNotFoundException(Platform::COMException^ e)
{
    if (e->HResult == 0x80070002) // Catch FileNotExistException
    {
        NotifyUserFileNotExist();
    }
    else
    {
        throw e;
    }
}

RectSize MainPage::currPageSize(int page)
{
	RectSize Size;

    FlipViewItem ^flipview_temp = (FlipViewItem^) xaml_flipView->Items->GetAt(page);

    Size.height = flipview_temp->ActualHeight;
    Size.width = flipview_temp->ActualWidth;
    return Size;
}

static RectSize measurePage(fz_document *doc, fz_page *page)
{
	RectSize pageSize;
    fz_rect rect;
	fz_rect *bounds = fz_bound_page(doc, page, &rect);

	pageSize.width = bounds->x1 - bounds->x0;
	pageSize.height = bounds->y1 - bounds->y0;
	return pageSize;
}

static RectSize fitPageToScreen(RectSize page, RectSize screen)
{
    RectSize pageSize;

	float hscale = screen.width / page.width;
	float vscale = screen.height / page.height;
	float scale = fz_min(hscale, vscale);
    pageSize.width = floorf(page.width * scale) / page.width;
	pageSize.height = floorf(page.height * scale) / page.height;
	return pageSize;
}

void MainPage::Prepare_bmp(int width, int height, DataWriter ^dw)
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

/* Add rendered page into flipview structure at location page_num */
void MainPage::AddPage(int page_num) 
{
    FlipViewItem ^flipview_temp = ref new FlipViewItem();
    flipview_temp->Content = this->m_renderedCanvas;
    xaml_flipView->Items->Append(flipview_temp);
}

/* Replace rendered page into flipview structure at location page_num */
void MainPage::ReplacePage(int page_num) 
{
    FlipViewItem ^flipview_temp = (FlipViewItem^) xaml_flipView->Items->GetAt(page_num);
    flipview_temp->Content = this->m_renderedCanvas;    
    flipview_temp->Background = nullptr;
}

/* Add rendered page into flipview structure at location page_num */
void MainPage::AddBlankPage(int page_num) 
{
    FlipViewItem ^flipview_temp = ref new FlipViewItem();
    flipview_temp->Background = this->m_blankPage;
    xaml_flipView->Items->Append(flipview_temp);
}

/* Create white image for us to use as place holder in large document for flip
   view filling instead of the thumbnail image  */
void MainPage::CreateBlank(int width, int height)
{
    Platform::Array<unsigned char>^ bmp_data = 
            ref new Platform::Array<unsigned char>(height * 4 * width);
    /* Set up the memory stream */
    WriteableBitmap ^bmp = ref new WriteableBitmap(width, height);
    InMemoryRandomAccessStream ^ras = ref new InMemoryRandomAccessStream();
    DataWriter ^dw = ref new DataWriter(ras->GetOutputStreamAt(0));
    /* Go ahead and write our header data into the memory stream */
    this->Prepare_bmp(width, height, dw);

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
    m_blankPage = ref new ImageBrush();
    m_blankPage->Stretch = Windows::UI::Xaml::Media::Stretch::None;
    m_blankPage->ImageSource = bmp;
}

/* win_read_file.  Reading of windows managed stream.  This is not ideal as I have 
   to read into a managed buffer and then transfer to the actual buffer I want.  I
   would like a more direct approach */
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

void winapp::MainPage::PixToMemStream(fz_pixmap *pix, DataWriter ^dw, Platform::Array<unsigned char> ^arr)
{
	unsigned char *samples = fz_pixmap_samples(ctx, pix);
	int w = fz_pixmap_width(ctx, pix);
	int h = fz_pixmap_height(ctx, pix);

    /* Write the data */
    dw->WriteBytes(arr);

    DataWriterStoreOperation^ result = dw->StoreAsync();
    /* Block on the Async call */
    while(result->Status != AsyncStatus::Completed) {
    }
}

void winapp::MainPage::RenderPage(fz_document *doc, fz_page *page, int *width, int *height, double scale_factor)
{
	fz_matrix ctm, *pctm = &ctm;
	fz_device *dev;
	fz_pixmap *pix;
    RectSize pageSize;
    RectSize scale;
    RectSize screenSize;
    int bmp_width, bmp_height;
    Canvas^ my_Canvas = ref new Canvas();

    screenSize.height = this->ActualHeight;
    screenSize.width = this->ActualWidth;

	screenSize.width *= screenScale;
	screenSize.height *= screenScale;
    
    pageSize = measurePage(doc, page);
	scale = fitPageToScreen(pageSize, screenSize);
	pctm = fz_scale(pctm, scale.width * scale_factor, scale.height * scale_factor);
    bmp_width = pageSize.width * scale.width * scale_factor;
    bmp_height = pageSize.height * scale.height * scale_factor;

    /* Y is flipped for some reason */
    ctm.f = bmp_height;
    ctm.d = -ctm.d;

    /* Allocate space for bmp */
    Platform::Array<unsigned char>^ bmp_data = 
            ref new Platform::Array<unsigned char>(bmp_height * 4 * bmp_width);
    m_memory_use += bmp_height * 4 * bmp_width;
    /* Set up the memory stream */
    WriteableBitmap ^bmp = ref new WriteableBitmap(bmp_width, bmp_height);
    InMemoryRandomAccessStream ^ras = ref new InMemoryRandomAccessStream();
    DataWriter ^dw = ref new DataWriter(ras->GetOutputStreamAt(0));
    /* Go ahead and write our header data into the memory stream */
    this->Prepare_bmp(bmp_width, bmp_height, dw);
    /* Now get a pointer to our samples and pass it to fitz to use */
    pix = fz_new_pixmap_with_data(ctx, fz_device_bgr, bmp_width, bmp_height, &(bmp_data[0]));
	fz_clear_pixmap_with_value(ctx, pix, 255);
	dev = fz_new_draw_device(ctx, pix);
	fz_run_page(doc, page, dev, pctm, NULL);
	fz_free_device(dev);
    /* Now the data into the memory stream */
	PixToMemStream(pix, dw, bmp_data);
    /* And store in a new image brush */
    bmp->SetSource(ras);
    m_renderedImage = ref new ImageBrush();
    m_renderedImage->Stretch = Windows::UI::Xaml::Media::Stretch::None;
    m_renderedImage->ImageSource = bmp;
    *width = bmp_width;
    *height = bmp_height;
    m_renderedCanvas = ref new Canvas();
    m_renderedCanvas->Height = bmp_height;
    m_renderedCanvas->Width = bmp_width;
    m_renderedCanvas->Background = this->m_renderedImage;
}

void winapp::MainPage::SetupZoomCanvas()
{
    int height = this->ActualHeight;
    int width = this->ActualWidth;

    CreateBlank(width, height);
    xaml_zoomCanvas->Background = this->m_blankPage;
    xaml_zoomCanvas->Background->Opacity = 0;
}

/* Clean up everything as we are opening a new document after having another
   one open */
void winapp::MainPage::CleanUp()
{
    /* Remove current pages in the flipview */
    if (xaml_flipView->Items->Size) 
        xaml_flipView->Items->Clear();

    /* Clean up mupdf */
    if (this->m_doc != NULL) 
        fz_close_document(m_doc);

    m_currpage = 0;
    m_file_open = false;
    m_doc = NULL;
    m_slider_min = 0;
    m_slider_max = 0;
    m_init_done = false;
    m_memory_use = 0;
    m_zoom_mode = false;
    m_zoom_handled = false;
    m_first_time = false;
    m_insearch = false;
    m_sliderchange = false;
    m_flip_from_search = false;
    m_num_pages = -1;
    m_search_rect_count = 0;
    ResetSearch();

    m_curr_zoom = 1.0;
    m_canvas_translate.X = 0;
    m_canvas_translate.Y = 0;

    this->xaml_PageSlider->Minimum = m_slider_min;
    this->xaml_PageSlider->Maximum = m_slider_max;
    this->xaml_PageSlider->IsEnabled = false;   
    
}

void winapp::MainPage::OpenDocument(StorageFile^ file)
{
    String^ path = file->Path;
    const wchar_t *w = path->Data();
    int cb = WideCharToMultiByte(CP_UTF8, 0, w, -1, nullptr, 0, nullptr, nullptr);
	char* name = new char[cb];

    WideCharToMultiByte(CP_UTF8, 0, w ,-1 ,name ,cb ,nullptr, nullptr);
    char *ext = strrchr(name, '.');

    if (this->m_num_pages != -1)
        CleanUp();
        
    this->SetupZoomCanvas();

    create_task(file->OpenAsync(FileAccessMode::Read)).then([this, file, ext](task<IRandomAccessStream^> task)
    {
        try
        {
            IRandomAccessStream^ readStream = task.get();
            UINT64 const size = readStream->Size;
            win_stream.stream = readStream;
            
            if (size <= MAXUINT32)
            {
                /* assign data reader to stream object */
                fz_stream *str;

                str =  fz_new_stream(ctx, 0, win_read_file, win_close_file);
                str->seek = win_seek_file;
                str->state =  reinterpret_cast <void*> (&win_stream);
                    
                /* Now lets see if we can render the file */
                
                m_doc = fz_open_document_with_stream(ctx, ext, str);
                m_num_pages = m_doc->count_pages(m_doc);

                /* Set up the search progress bar */
                ProgressBar^ xaml_Progress = (ProgressBar^) (this->FindName("xaml_Progress"));
                xaml_Progress->Maximum = m_num_pages;

                if ((m_currpage) >= m_num_pages) 
                {
                    m_currpage = m_num_pages - 1;
                } 
                else if (m_currpage < 0) 
                {
                    m_currpage = 0;
                }
                /* Do a few pages */
                int height, width;
                for (int k = 0; k < LOOK_AHEAD + 2; k++) 
                {
                    if (m_num_pages > k ) 
                    {
                        fz_page *page = fz_load_page(m_doc, k);
			            this->RenderPage(m_doc, page, &width, &height, 1);
                        AddPage(k);
                        fz_free_page(m_doc, page);
                    }
                }
                /* If we still have more pages, then set the rest to a blank white
                   page which will get bumped as we move through the doc. */
                if (m_num_pages > LOOK_AHEAD + 2)
                {
                    for (int k = LOOK_AHEAD + 2; k < m_num_pages; k++) 
                    {
                        AddBlankPage(k);
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
                this->m_init_done = true;
            }
            else
            {
                delete readStream; 
            }
        }
        catch(COMException^ ex) {
            this->HandleFileNotFoundException(ex);
        }
    });
}

void winapp::MainPage::RenderRange(int curr_page, int *height, int *width)
{
    /* Render +/- the look ahead from where we are if blank page is present */
    for (int k = curr_page - LOOK_AHEAD; k <= curr_page + LOOK_AHEAD; k++) 
    {
        if (k >= 0 && k < m_num_pages) 
        {
            FlipViewItem ^flipview_temp = (FlipViewItem^) xaml_flipView->Items->GetAt(k);
            if (flipview_temp->Background == this->m_blankPage) 
            {
                fz_page *page = fz_load_page(m_doc, k);
			    this->RenderPage(m_doc, page, width, height, 1);
                ReplacePage(k);
                fz_free_page(m_doc, page);
            } 
        }
    }
    RectSize rectsize = this->currPageSize(curr_page);
    *height = rectsize.height;
    *width = rectsize.width;
    m_currpage = curr_page;
}

void winapp::MainPage::Slider_Released(Platform::Object^ sender, Windows::UI::Xaml::Controls::Primitives::RangeBaseValueChangedEventArgs^ e)
{
    int height, width;
    int newValue = (int) this->xaml_PageSlider->Value - 1;  /* zero based */

    this->RenderRange(newValue, &height, &width);
    this->m_currpage = newValue;
}

void winapp::MainPage::Slider_ValueChanged(Platform::Object^ sender, Windows::UI::Xaml::Controls::Primitives::RangeBaseValueChangedEventArgs^ e)
{
    int newValue = (int) this->xaml_PageSlider->Value - 1;  /* zero based */

    if (m_update_flip)
    {
        m_update_flip = false;
        return;
    }
    if (m_init_done && this->xaml_PageSlider->IsEnabled) 
    {
        FlipViewItem ^flipview_temp = (FlipViewItem^) xaml_flipView->Items->GetAt(newValue);
        if (flipview_temp->Background == this->m_blankPage) 
        {
            int width, height;
            fz_page *page = fz_load_page(m_doc, newValue);
            this->RenderPage(m_doc, page, &width, &height, 1);
            ReplacePage(newValue);
            this->m_currpage = newValue;
            fz_free_page(m_doc, page);
        } 
        m_sliderchange = true;
        this->xaml_flipView->SelectedIndex = newValue;
        ResetSearch();
    }
}

void winapp::MainPage::FlipView_SelectionChanged(Object^ sender, SelectionChangedEventArgs^ e)
{
    int pos = this->xaml_flipView->SelectedIndex;
    int height, width;

    m_update_flip = true;
    if (xaml_PageSlider->IsEnabled)
    {
        xaml_PageSlider->Value = pos;
    }
    if (pos >= 0) 
    {
        if (m_flip_from_search)
        {
            m_flip_from_search = false;
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
        if (m_init_done)
            this->RenderRange(pos, &height, &width);
    }
}

void winapp::MainPage::Canvas_ManipulationStarting(Object^ sender, ManipulationStartingRoutedEventArgs^ e)
{
    bool handled;

    e->GetType();
    handled = e->Handled;
}

void winapp::MainPage::Canvas_ManipulationStarted(Object^ sender, ManipulationStartedRoutedEventArgs^ e)
{
    this->m_touchpoint = e->Position;
}

void winapp::MainPage::Canvas_ManipulationDelta(Object^ sender, ManipulationDeltaRoutedEventArgs^ e)
{
    int width, height;

    m_changes = e->Cumulative;
    if (e->Delta.Scale != 1 || m_first_time) 
    {
        /* Render at scaled resolution */
        int pos = this->xaml_flipView->SelectedIndex;
        fz_page *page = fz_load_page(m_doc, pos);
        m_curr_zoom = m_curr_zoom * e->Delta.Scale;
        if (m_curr_zoom < MIN_SCALE) m_curr_zoom = MIN_SCALE;
        if (m_curr_zoom > MAX_SCALE) m_curr_zoom = MAX_SCALE;
        this->RenderPage(m_doc, page, &width, &height, m_curr_zoom);
        this->xaml_zoomCanvas->Background = this->m_renderedImage;
        this->xaml_zoomCanvas->Width = width;
        this->xaml_zoomCanvas->Height = height;
        m_zoom_size.X = width;
        m_zoom_size.Y = height;
        m_first_time = false;
    }

    TranslateTransform ^trans_transform = ref new TranslateTransform();
    m_canvas_translate.X += e->Delta.Translation.X;
    m_canvas_translate.Y += e->Delta.Translation.Y;
    
    if (m_canvas_translate.Y > ((this->ActualHeight + m_zoom_size.Y) / 2 - MARGIN_BUFF) ) 
    {
        m_canvas_translate.Y = (this->ActualHeight + m_zoom_size.Y) / 2 - MARGIN_BUFF;
    }
    if (m_canvas_translate.Y < (MARGIN_BUFF - (this->ActualHeight + m_zoom_size.Y) / 2) ) 
    {
        m_canvas_translate.Y = MARGIN_BUFF - (this->ActualHeight + m_zoom_size.Y) / 2;
    }
    if (m_canvas_translate.X > ((this->ActualWidth + m_zoom_size.X) / 2 - MARGIN_BUFF)) 
    {
        m_canvas_translate.X = (this->ActualWidth + m_zoom_size.X) / 2 - MARGIN_BUFF;
    }

    if (m_canvas_translate.X < (MARGIN_BUFF - (this->ActualWidth + m_zoom_size.X) / 2)) 
    {
        m_canvas_translate.X = (MARGIN_BUFF - (this->ActualWidth + m_zoom_size.X) / 2);
    } 

    trans_transform->X = m_canvas_translate.X;
    trans_transform->Y = m_canvas_translate.Y;
    this->xaml_zoomCanvas->RenderTransform = trans_transform;
}

void winapp::MainPage::FlipView_Double(Object^ sender, DoubleTappedRoutedEventArgs^ e)
{
    if (!m_zoom_mode)
    {
        m_zoom_mode = true;
        int pos = this->xaml_flipView->SelectedIndex;
        FlipViewItem ^flipview_temp = (FlipViewItem^) xaml_flipView->Items->GetAt(pos);
        Canvas^ Curr_Canvas = (Canvas^) (flipview_temp->Content);
        xaml_flipView->IsEnabled = false;
        this->xaml_zoomCanvas->Background = Curr_Canvas->Background;
        this->xaml_zoomCanvas->Background->Opacity = 1;
        this->xaml_flipView->Opacity = 0.0;
        m_zoom_handled = true;
        m_first_time = true;
    }
}

void winapp::MainPage::Canvas_Double(Object^ sender, DoubleTappedRoutedEventArgs^ e)
{
    TranslateTransform ^trans_transform = ref new TranslateTransform();

    if (m_zoom_mode && !m_zoom_handled)
    {
        m_zoom_mode = false;
        int pos = this->xaml_flipView->SelectedIndex;

        FlipViewItem ^flipview_temp = (FlipViewItem^) xaml_flipView->Items->GetAt(pos);
        Canvas^ Curr_Canvas = (Canvas^) (flipview_temp->Content);

       if (this->xaml_zoomCanvas->Background != Curr_Canvas->Background)
            this->xaml_zoomCanvas->Background->Opacity = 0;
        else 
            this->xaml_zoomCanvas->Background = nullptr;
        this->xaml_flipView->Opacity = 1;
        xaml_flipView->IsEnabled = true;
        m_first_time = true;
    }
    m_zoom_handled = false;
    m_curr_zoom = 1.0;
    this->xaml_zoomCanvas->Height = this->ActualHeight;
    this->xaml_zoomCanvas->Width = this->ActualWidth;
    trans_transform->X = 0;
    trans_transform->Y = 0;
    m_canvas_translate.X = 0;
    m_canvas_translate.Y = 0;
    this->xaml_zoomCanvas->RenderTransform = trans_transform;
}

/* Search Related Code */

static int hit_count = 0;
static fz_rect hit_bbox[MAX_SEARCH];

static int
search_page(fz_document *doc, int number, char *needle, fz_cookie *cookie)
{
	fz_page *page = fz_load_page(doc, number);

	fz_text_sheet *sheet = fz_new_text_sheet(ctx);
	fz_text_page *text = fz_new_text_page(ctx, &fz_empty_rect);
	fz_device *dev = fz_new_text_device(ctx, sheet, text);
	fz_run_page(doc, page, dev, &fz_identity, cookie);
	fz_free_device(dev);

	hit_count = fz_search_text_page(ctx, text, needle, hit_bbox, nelem(hit_bbox));;

	fz_free_text_page(ctx, text);
	fz_free_text_sheet(ctx, sheet);
	fz_free_page(doc, page);

	return hit_count;
}

void winapp::MainPage::Searcher(Platform::Object^ sender, Windows::UI::Xaml::RoutedEventArgs^ e)
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
        m_insearch = true;
	    Windows::UI::Xaml::Controls::Button^ PrevButton = ref new Button();
        PrevButton->Style = safe_cast<Windows::UI::Xaml::Style^>(App::Current->Resources->Lookup("PreviousAppBarButtonStyle"));
	    PrevButton->Click += ref new RoutedEventHandler(this, &winapp::MainPage::SearchPrev);
        
	    Windows::UI::Xaml::Controls::Button^ NextButton = ref new Button();
        NextButton->Style = safe_cast<Windows::UI::Xaml::Style^>(App::Current->Resources->Lookup("NextAppBarButtonStyle"));
	    NextButton->Click += ref new RoutedEventHandler(this, &winapp::MainPage::SearchNext);

        Windows::UI::Xaml::Controls::TextBox^ SearchBox = ref new TextBox();
        SearchBox->Name = "findBox";
        SearchBox->Width = 200;
        SearchBox->Height = 20;
        
        leftPanel->Children->Append(SearchBox);
        leftPanel->Children->Append(PrevButton);
        leftPanel->Children->Append(NextButton);
	}
}

void winapp::MainPage::ShowSearchResults(SearchResult_t result)
{
    int height, width;
    this->RenderRange(result.page_num, &height, &width);
    RectSize screenSize;
    RectSize pageSize;
    RectSize scale;
	fz_page *page = fz_load_page(m_doc, result.page_num);
    FlipViewItem ^flipview_temp = (FlipViewItem^) xaml_flipView->Items->GetAt(result.page_num);
    Canvas^ results_Canvas = (Canvas^) (flipview_temp->Content);
   // wchar_t buf[20];

    m_searchpage = result.page_num;

    screenSize.height = this->ActualHeight;
    screenSize.width = this->ActualWidth;

	screenSize.width *= screenScale;
	screenSize.height *= screenScale;
    
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
        trans_transform->X = hit_bbox[k].x0 * scale.width;
        trans_transform->Y = hit_bbox[k].y0 *  scale.height;
		a_rectangle->Width *= scale.width;
		a_rectangle->Height *= scale.height;
        /* Give it a unique name */
#if 0
        int len = swprintf_s(buf, 20, L"%s_%d", L"Rect",k );
        a_rectangle->Name = ref new String(buf);
#endif
        a_rectangle->RenderTransform = trans_transform;
        a_rectangle->Fill = m_color_brush;
        results_Canvas->Children->Append(a_rectangle);
        m_search_rect_count += 1;
    }
    if (result.box_count > 0)
    {
        m_flip_from_search = true;
        this->xaml_flipView->SelectedIndex = result.page_num;
    }
}

void winapp::MainPage::SearchNext(Platform::Object^ sender, Windows::UI::Xaml::RoutedEventArgs^ e)
{
    StackPanel^ leftPanel = (StackPanel^) this->TopAppBar->FindName("LeftPanel");
    TextBox^ findBox = (TextBox^) leftPanel->FindName("findBox");
    String^ textToFind = findBox->Text;

    SearchInDirection(1, textToFind);
}

void winapp::MainPage::SearchPrev(Platform::Object^ sender, Windows::UI::Xaml::RoutedEventArgs^ e)
{
    StackPanel^ leftPanel = (StackPanel^) this->TopAppBar->FindName("LeftPanel");
    TextBox^ findBox = (TextBox^) leftPanel->FindName("findBox");
    String^ textToFind = findBox->Text;

    SearchInDirection(-1, textToFind);
}

void winapp::MainPage::CancelSearch(Platform::Object^ sender, Windows::UI::Xaml::RoutedEventArgs^ e)
{
   m_searchcts.cancel();
}

void winapp::MainPage::ResetSearch(void)
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
        Rectangle^ curr_rect = (Rectangle^) (xaml_flipView->FindName(TempString));
        if (curr_rect != nullptr)
        {
            Canvas^ results_Canvas = (Canvas^) curr_rect->Parent;
            results_Canvas->Children->IndexOf(curr_rect, &index);
            results_Canvas->Children->RemoveAt(index);
        }
    }
#endif
}

void winapp::MainPage::SearchInDirection(int dir, String^ textToFind)
{
	int start;
    const wchar_t *w = textToFind->Data();
    int cb = WideCharToMultiByte(CP_UTF8, 0, textToFind->Data(), -1, nullptr, 0, nullptr, nullptr);
	char* needle = new char[cb];
    fz_document *local_doc = m_doc;
    auto cancel_token = m_searchcts.get_token();  /* Cancelation token */
    SearchResult_t result;
    int pos = m_currpage;

    result.box_count = 0;
    result.page_num = -1;

    WideCharToMultiByte(CP_UTF8, 0, textToFind->Data() ,-1 ,needle ,cb ,nullptr, nullptr);

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


    /* Get the ui thread */
    auto ui = task_continuation_context::use_current();

    /* Do task lambdas here to avoid UI blocking issues */
    auto search_task = create_task([this, needle, dir, start, local_doc, &result]()->SearchResult_t
    {
		for (int i = start; i >= 0 && i < fz_count_pages(local_doc); i += dir) 
        {
			result.box_count = search_page(local_doc, i, needle, NULL);
            result.page_num = i;
            
            //my_xaml_Progress->Value = i;
			if (result.box_count) 
            {
                free(needle);
                return result;
			}
            if (is_task_cancellation_requested()) 
            {
                free(needle);
            }
        }
        /* Todo no matches found alert */
        free(needle);
        return result;
    }, cancel_token);

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
    }, ui);
}

/* This is here to handle when we rotate or go into the snapview mode 
   ToDo  add in data binding to change the scroll direction */
void winapp::MainPage::GridSizeChanged()
{

    int height = this->ActualHeight;
    int width = this->ActualWidth;

    if (DisplayProperties::CurrentOrientation == DisplayOrientations::Portrait ||
        DisplayProperties::CurrentOrientation == DisplayOrientations::PortraitFlipped)
    {
        if (!m_zoom_mode)
        {
            this->xaml_zoomCanvas->Height = height;
            this->xaml_zoomCanvas->Width = width;
            this->xaml_flipView->Height = height;
            this->xaml_flipView->Width = width;
        }
    }
    else
    {
        if (!m_zoom_mode)
        {
            this->xaml_zoomCanvas->Height = height;
            this->xaml_zoomCanvas->Width = width;
            this->xaml_flipView->Height = height;
            this->xaml_flipView->Width = width;
        }
    }
    UpDatePageSizes();
}

void winapp::MainPage::UpDatePageSizes()
{
    int width, height;

    /* Render our current pages at the new resolution and mark the rest with the blank */
    if (m_num_pages > 0)
    {
        for (int i = 0; i < m_num_pages; i++)
        {
            FlipViewItem ^flipview_temp = (FlipViewItem^) xaml_flipView->Items->GetAt(i);
            flipview_temp->Content = nullptr;    
            flipview_temp->Background = this->m_blankPage;
        }
        this->RenderRange(this->m_currpage, &height, &width);
    }
};
