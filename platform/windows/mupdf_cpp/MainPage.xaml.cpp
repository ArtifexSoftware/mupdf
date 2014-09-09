//
// MainPage.xaml.cpp
// Implementation of the MainPage class.
//

#include "pch.h"
#include "MainPage.xaml.h"
#include <regex>
#include <sstream>
#include "DXGI1_3.h"

#define LOOK_AHEAD 1 /* A +/- count on the pages to pre-render */
#define THUMB_PREADD 10
#define MIN_SCALE 0.5

#define SCALE_THUMB 0.1
#define PRINT_PREVIEW_SCALE 0.5

#define BLANK_WIDTH 17
#define BLANK_HEIGHT 22

#define KEYBOARD_ZOOM_STEP 0.25
#define ZOOM_MAX 4
#define ZOOM_MIN 0.25

#define KEY_PLUS 0xbb
#define KEY_MINUS 0xbd
#define ZOOM_IN 0
#define ZOOM_OUT 1

#define SEARCH_FIT 672
#define VS_LARGE 1366
#define VS_SMALL 500

static float screenScale = 1;

using namespace mupdf_cpp;
using namespace Windows::Foundation;
using namespace Windows::UI::Xaml;
using namespace Windows::UI::Xaml::Controls;
using namespace Windows::UI::Xaml::Controls::Primitives;
using namespace Windows::UI::Xaml::Data;
using namespace Windows::UI::Xaml::Media;
using namespace Windows::UI::Xaml::Navigation;
using namespace Windows::Graphics::Display;
using namespace Windows::Graphics::Printing;
using namespace Windows::UI::Core;

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
	Application::Current->Suspending += 
		ref new SuspendingEventHandler(this, &MainPage::App_Suspending);
	Application::Current->UnhandledException +=
		ref new UnhandledExceptionEventHandler(this, &MainPage::ExceptionHandler);
	m_textcolor="#402572AC";
	m_linkcolor="#40AC7225";
	mu_doc = nullptr;
	m_docPages = ref new Platform::Collections::Vector<DocumentPage^>();
	m_thumbnails = ref new Platform::Collections::Vector<DocumentPage^>();
	m_page_link_list = ref new Platform::Collections::Vector<IVector<RectList^>^>();
	m_text_list = ref new Platform::Collections::Vector<RectList^>();
	m_linkset = ref new Platform::Collections::Vector<int>();
	if (m_docPages == nullptr || m_thumbnails == nullptr || 
		m_page_link_list == nullptr || m_text_list == nullptr ||
		m_linkset == nullptr)
		throw ref new FailureException("Document allocation failed!");

	SetUpDirectX();
	RegisterForPrinting();
	CleanUp();
#ifndef NDEBUG
	RecordMainThread();
#endif
	/* So that we can catch special loading events (e.g. open with) */
	_pageLoadedHandlerToken = Loaded += ref new RoutedEventHandler(this, &MainPage::Page_Loaded);
}

/* You need a Direct3D device to create a Direct2D device.   This gets stuff
	set up for Direct2D printing support */
void MainPage::SetUpDirectX()
{
	UINT creation_flags = D3D11_CREATE_DEVICE_BGRA_SUPPORT;
	ComPtr<IDXGIDevice> dxgi_device;
	D2D1_FACTORY_OPTIONS options;
	ZeroMemory(&options, sizeof(D2D1_FACTORY_OPTIONS));
	D3D_FEATURE_LEVEL feature_levels[] =
	{
		D3D_FEATURE_LEVEL_11_1,
		D3D_FEATURE_LEVEL_11_0,
		D3D_FEATURE_LEVEL_10_1,
		D3D_FEATURE_LEVEL_10_0,
		D3D_FEATURE_LEVEL_9_3,
		D3D_FEATURE_LEVEL_9_2,
		D3D_FEATURE_LEVEL_9_1
	};
	ComPtr<ID3D11Device> device;
	ComPtr<ID3D11DeviceContext> context;

#if defined(_DEBUG)
	options.debugLevel = D2D1_DEBUG_LEVEL_INFORMATION;
#endif	

	ThrowIfFailed(D3D11CreateDevice(nullptr, D3D_DRIVER_TYPE_HARDWARE, 0, 
				creation_flags, feature_levels, ARRAYSIZE(feature_levels),
				D3D11_SDK_VERSION, &device, &m_featureLevel, &context));
	ThrowIfFailed(device.As(&m_d3d_device));
	ThrowIfFailed(context.As(&m_d3d_context));
	ThrowIfFailed(m_d3d_device.As(&dxgi_device));
	ThrowIfFailed(D2D1CreateFactory(D2D1_FACTORY_TYPE_MULTI_THREADED,
					__uuidof(ID2D1Factory1), &options, &m_d2d_factory));
	ThrowIfFailed(CoCreateInstance(CLSID_WICImagingFactory, nullptr,
						CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&m_wic_factory)));
	m_d2d_factory->CreateDevice(dxgi_device.Get(), &m_d2d_device);
}

/* Used during launch of application from file when application was not 
   already running */
void MainPage::Page_Loaded(Object^ sender, RoutedEventArgs^ e)
{
	MainPage^ rootPage = dynamic_cast<MainPage^>(sender);
	if (rootPage->FileEvent != nullptr)
	{
		/* Launched with an "open with", or as default app */
		if (rootPage->FileEvent->Files->Size > 0)
		{
			IStorageItem ^file = rootPage->FileEvent->Files->GetAt(0);
			StorageFile ^sfile = safe_cast<StorageFile^>(file);

			OpenDocumentPrep(sfile);
		}
	}
}

/* Used during launch of application from file when application was already 
   running */
void MainPage::FromFile()
{
	if (this->FileEvent != nullptr)
	{
		/* Launched with an "open with", or as default app */
		if (this->FileEvent->Files->Size > 0)
		{
			IStorageItem ^file = this->FileEvent->Files->GetAt(0);
			StorageFile ^sfile = safe_cast<StorageFile^>(file);

			OpenDocumentPrep(sfile);
		}
	}
}

/// <summary>
/// Invoked when this page is about to be displayed in a Frame.
/// </summary>
/// <param name="e">Event data that describes how this page was reached.  The Parameter
/// property is typically used to configure the page.</param>
void MainPage::OnNavigatedTo(NavigationEventArgs^ e)
{

}

void MainPage::ExceptionHandler(Object^ sender, UnhandledExceptionEventArgs^ e)
{
	if (!this->m_init_done)
	{
		/* Windows 8.1 has some weird issues that occur before we have even tried
			to open a document.  For example rolling the mouse wheel throws an
			exception in 8.1 but not 8.0.  This is clearly a windows issue.  For 
			now mark as handled and move on which seems to be fine */
		e->Handled = true;
	}
	else
	{
		e->Handled = true;
		NotifyUser("An error was encountered", ErrorMessage);
	}
}

/* We need to clean up (Trim) the directX memory on suspension */
void MainPage::App_Suspending(Object^ sender, SuspendingEventArgs^ e)
{
	ComPtr<IDXGIDevice3> pDXGIDevice;
	ThrowIfFailed(m_d3d_device.As(&pDXGIDevice));
	pDXGIDevice->Trim();
}

void MainPage::ExitInvokedHandler(Windows::UI::Popups::IUICommand^ command)
{

}

void MainPage::OKInvokedHandler(Windows::UI::Popups::IUICommand^ command)
{

}

void MainPage::NotifyUser(String^ strMessage, int type)
{
	MessageDialog^ msg = ref new MessageDialog(strMessage);
	UICommand^ ExitCommand = nullptr;
	UICommand^  OKCommand = nullptr;

	switch (type)
	{
	case StatusMessage:
		OKCommand = ref new UICommand("OK",
			ref new UICommandInvokedHandler(this, &MainPage::OKInvokedHandler));
		msg->Commands->Append(OKCommand);
		/// Set the command that will be invoked by default
		msg->DefaultCommandIndex = 0;
		// Set the command to be invoked when escape is pressed
		msg->CancelCommandIndex = 1;
		break;
	case ErrorMessage:
		ExitCommand = ref new UICommand("Exit",
			ref new UICommandInvokedHandler(this, &MainPage::ExitInvokedHandler));
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

void MainPage::Picker(Platform::Object^ sender, Windows::UI::Xaml::RoutedEventArgs^ e)
{
	/* If we are actively rendering a document to the print thread then notify the
		user that they will need to wait */
	if (m_print_active == PRINT_ACTIVE)
	{
		int total_pages = GetPrintPageCount();
		auto str1 = "Cannot open new file.  Currently rendering page " + 
					m_curr_print_count + " of " + total_pages + " for print queue";
		NotifyUser(str1, StatusMessage);
		return;
	}

	FileOpenPicker^ openPicker = ref new FileOpenPicker();
	openPicker->ViewMode = PickerViewMode::List;
	openPicker->SuggestedStartLocation = PickerLocationId::DocumentsLibrary;
	openPicker->FileTypeFilter->Append(".pdf");
	openPicker->FileTypeFilter->Append(".xps");
	openPicker->FileTypeFilter->Append(".cbz");
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
			  Point ras_size, Page_Content_t content_type, double zoom_in)
{
	assert(IsMainThread());

	WriteableBitmap ^bmp = ref new WriteableBitmap((int)ras_size.X, (int) ras_size.Y);
	if (bmp == nullptr)
	{
#ifdef _DEBUG
		NotifyUser("BMP UpdatePage Failed Page " + page_num, ErrorMessage);
#endif 
		return;
	}
	bmp->SetSource(ras);

	DocumentPage^ doc_page = ref new DocumentPage();
	if (doc_page == nullptr)
	{
#ifdef _DEBUG
		NotifyUser("doc_page UpdatePage Failed Page " + page_num, ErrorMessage);
#endif 
		return;
	}
	doc_page->Image = bmp;

	if (content_type == THUMBNAIL)
	{
		doc_page->Height = (int) (ras_size.Y / SCALE_THUMB);
		doc_page->Width = (int) (ras_size.X / SCALE_THUMB);
	}
	else
	{
		doc_page->Height = (int) ras_size.Y;
		doc_page->Width = (int) ras_size.X;
	}
	doc_page->Content = content_type;
	doc_page->PageZoom = zoom_in;

	/* We do not want flipview change notification to occur for ourselves */
	m_page_update = true;
	this->m_docPages->SetAt(page_num, doc_page);
	m_page_update = false;
}

/* Set the page with the new raster information but only the image data */
void MainPage::ReplaceImage(int page_num, InMemoryRandomAccessStream^ ras,
				Point ras_size, double page_zoom)
{
	assert(IsMainThread());

	WriteableBitmap ^bmp = ref new WriteableBitmap((int) ras_size.X, (int) ras_size.Y);
	if (bmp == nullptr)
	{
#ifdef _DEBUG
		NotifyUser("BMP ReplaceImage Failed Page " + page_num, ErrorMessage);
#endif 
		return;
	}

	bmp->SetSource(ras);
	DocumentPage^ doc_page = this->m_docPages->GetAt(page_num);
	if (doc_page == nullptr)
	{
#ifdef _DEBUG
		NotifyUser("doc_page ReplaceImage Failed Page " + page_num, ErrorMessage);
#endif 
		return;
	}
	doc_page->Image = bmp;
	doc_page->Height = (int) ras_size.Y;
	doc_page->Width = (int) ras_size.X;
	doc_page->PageZoom = page_zoom;
}

int MainPage::ComputePageSize(spatial_info_t spatial_info, int page_num, 
								Point *render_size, float *scale_factor)
{
	Point screenSize;
	Point renpageSize;
	Point size;
	
	try
	{
		size = mu_doc->GetPageSize(page_num);
	}
	catch (Exception ^except)
	{
#ifdef _DEBUG
		NotifyUser(except->Message, ErrorMessage);
#endif 
		return E_FAILURE;
	}

	screenSize = spatial_info.size;
	screenSize.Y *= screenScale;
	screenSize.X *= screenScale;

	float hscale = screenSize.X / size.X;
	float vscale = screenSize.Y / size.Y;
	float scale = min(hscale, vscale);
	renpageSize.X = (float)(size.X * scale * spatial_info.scale_factor);
	renpageSize.Y = (float)(size.Y * scale * spatial_info.scale_factor);

	*scale_factor = (float) (scale * spatial_info.scale_factor);
	*render_size = renpageSize;

	return S_ISOK;
}

static Point fitPageToScreen(Point page, Point screen)
{
	Point pageSize;

	float hscale = screen.X / page.X;
	float vscale = screen.Y / page.Y;
	float scale = min(hscale, vscale);
	pageSize.X = floorf(page.X * scale) / page.X;
	pageSize.Y = floorf(page.Y * scale) / page.Y;

	return pageSize;
}

spatial_info_t MainPage::InitSpatial(double scale)
{
	spatial_info_t value;

	value.size.Y = (float) (this->ActualHeight);
	value.size.X = (float) (this->ActualWidth);
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
				SetThumb(k);
			}
		}
	}
}

/* Return this page from a full res image to the thumb image or only set
   to thumb if it has not already been set */
void MainPage::SetThumb(unsigned int page_num)
{
	/* See what is there now */
	auto doc = this->m_docPages->GetAt(page_num);
	if (doc->Content == THUMBNAIL && doc->PageZoom == m_doczoom) return;

	if (this->m_thumbnails->Size > page_num)
	{
		m_page_update = true;
		auto thumb_page = this->m_thumbnails->GetAt(page_num);
		thumb_page->Height = (int)(thumb_page->NativeHeight * m_doczoom);
		thumb_page->Width = (int)(thumb_page->NativeWidth * m_doczoom);
		thumb_page->PageZoom = 1.0;
		this->m_docPages->SetAt(page_num, thumb_page);
		m_page_update = false;
	}
}

/* Initializes the flipview items with the thumb pages as they become 
   available */
void MainPage::SetThumbInit(unsigned int page_num)
{
	/* See what is there now */
	auto doc = this->m_docPages->GetAt(page_num);
	if (doc->Content == THUMBNAIL || doc->Content == FULL_RESOLUTION) return;

	if (this->m_thumbnails->Size > page_num)
	{
		doc->Content = THUMBNAIL;
		auto thumb_page = this->m_thumbnails->GetAt(page_num);
		thumb_page->Height = (int)(thumb_page->NativeHeight);
		thumb_page->Width = (int)(thumb_page->NativeWidth);
		doc->Image = thumb_page->Image;
		doc->Height = thumb_page->Height;
		doc->Width = thumb_page->Width;
		doc->PageZoom = 1.0;
	}
}

/* Create white image for us to use as place holder in large document for flip
	view filling instead of the thumbnail image  */
void MainPage::CreateBlank(int width, int height)
{
	Array<unsigned char>^ bmp_data = ref new Array<unsigned char>(height * 4 * width);
	if (bmp_data == nullptr)
	{
#ifdef _DEBUG
		NotifyUser("CreateBlank failed", ErrorMessage);
#endif 
		return;
	}
	/* Set up the memory stream */
	WriteableBitmap ^bmp = ref new WriteableBitmap(width, height);
	InMemoryRandomAccessStream ^ras = ref new InMemoryRandomAccessStream();
	if (bmp == nullptr || ras == nullptr)
	{
#ifdef _DEBUG
		NotifyUser("CreateBlank failed", ErrorMessage);
#endif 
		return;
	}
	DataWriter ^dw = ref new DataWriter(ras->GetOutputStreamAt(0));
	if (dw == nullptr)
	{
#ifdef _DEBUG
		NotifyUser("CreateBlank failed", ErrorMessage);
#endif 
		return;
	}	/* Go ahead and write our header data into the memory stream */
	Prepare_bmp(width, height, dw);

	/* Set the data to all white */
	memset(bmp_data->Data, 255, height * 4 * width);

	/* Write the data */
	dw->WriteBytes(bmp_data);

	DataWriterStoreOperation^ result = dw->StoreAsync();
	/* Block on the Async call */
	while(result->Status != Windows::Foundation::AsyncStatus::Completed) {
	}
	/* And store in a the image brush */
	bmp->SetSource(ras);
	m_BlankBmp = bmp;
}

void MainPage::SetFlipView()
{
	int height = (int) (this->ActualHeight);
	int width = (int) (this->ActualWidth);

	CreateBlank(BLANK_WIDTH, BLANK_HEIGHT);
	/* Set the current flip view mode */
	if (height > width)
		this->m_curr_flipView = xaml_vert_flipView;
	else
		this->m_curr_flipView = xaml_horiz_flipView;
}

/* Clean up everything as we are opening a new document after having another
	one open */
void MainPage::CleanUp()
{
	m_init_done = false;
	/* Remove current pages in the flipviews */
	if (m_docPages != nullptr && m_docPages->Size > 0)
		m_docPages->Clear();
	if (m_thumbnails != nullptr && m_thumbnails->Size > 0)
		m_thumbnails->Clear();
	/* With the ref counting this should not leak */
	if (m_page_link_list != nullptr && m_page_link_list->Size > 0)
		m_page_link_list->Clear();
	if (m_text_list->Size > 0)
		m_text_list->Clear();
	m_ppage_num_list.clear();

	if (m_linkset != nullptr && m_linkset->Size > 0)
		m_linkset->Clear();

	if (this->mu_doc != nullptr)
		mu_doc->CleanUp();

	mu_doc = ref new mudocument();
	if (mu_doc == nullptr)
		throw ref new FailureException("Document allocation failed!");

	this->m_curr_flipView = nullptr;
	m_currpage = -1;
	m_file_open = false;
	m_slider_min = 0;
	m_slider_max = 0;
	m_memory_use = 0;
	m_insearch = false;
	m_search_active = false;
	m_sliderchange = false;
	m_flip_from_searchlink = false;
	m_num_pages = -1;
	m_search_rect_count = 0;
	m_ren_status = REN_AVAILABLE;
	m_links_on = false;
	m_rectlist_page = -1;
	m_Progress = 0.0;
	m_doczoom = 1.0;
	m_print_active = PRINT_INACTIVE;
	m_curr_print_count = 1;

	this->xaml_PageSlider->Minimum = m_slider_min;
	this->xaml_PageSlider->Maximum = m_slider_max;
	this->xaml_PageSlider->IsEnabled = false;
}

/* Create the thumbnail images */
void MainPage::RenderThumbs()
{
	spatial_info_t spatial_info = this->InitSpatial(1);
	int num_pages = this->m_num_pages;
	cancellation_token_source cts;
	auto token = cts.get_token();
	m_ThumbCancel = cts;
	auto ui = task_continuation_context::use_current();

	this->m_ren_status = REN_THUMBS;
	auto task_thumb = create_task([spatial_info, num_pages, this, ui, token]()-> int
	{
		spatial_info_t spatial_info_local = spatial_info;
		Point ras_size;
		Array<unsigned char>^ bmp_data;
		int code;
		float scale_factor;

		/* The renderings run on a background thread */
		assert(IsBackgroundThread());
		spatial_info_local.scale_factor = SCALE_THUMB;

		for (int k = 0; k < num_pages; k++)
		{
			if (ComputePageSize(spatial_info_local, k, &ras_size, &scale_factor) == S_ISOK)
			{
				code = mu_doc->RenderPageBitmapSync(k, (int)ras_size.X,
					(int)ras_size.Y, scale_factor, false, true, false, { 0, 0 }, 
					{ ras_size.X, ras_size.Y }, &bmp_data);

				DocumentPage^ doc_page = ref new DocumentPage();
				doc_page->Height = (int)(ras_size.Y / SCALE_THUMB);
				doc_page->Width = (int)(ras_size.X / SCALE_THUMB);
				doc_page->NativeHeight = (int)(ras_size.Y / SCALE_THUMB);
				doc_page->NativeWidth = (int)(ras_size.X / SCALE_THUMB);
				doc_page->TextBox = nullptr;
				doc_page->LinkBox = nullptr;
				doc_page->Content = THUMBNAIL;

				InMemoryRandomAccessStream ^ras = ref new InMemoryRandomAccessStream();
				DataWriter ^dw = ref new DataWriter(ras->GetOutputStreamAt(0));
				Prepare_bmp((int)ras_size.X, (int)ras_size.Y, dw);
				dw->WriteBytes(bmp_data);
				auto t = create_task(dw->StoreAsync());
				t.wait();

				/* The update with the WriteableBitmap has to take place in the
					UI thread.  The fact that you cannot create a WriteableBitmap 
					object execept in the UI thread is a poor design in WinRT.   
					We will do the callback but with a low priority */
				this->Dispatcher->RunAsync(CoreDispatcherPriority::Low,
					ref new DispatchedHandler([this, ras_size, k, ras, doc_page]()
				{
					assert(IsMainThread());
					WriteableBitmap ^bmp = ref new WriteableBitmap((int)ras_size.X, (int)ras_size.Y);
					bmp->SetSource(ras);
					doc_page->Image = bmp;
					m_thumbnails->SetAt(k, doc_page);
					SetThumbInit((unsigned int) k);
				}));
			}
		}
		return num_pages; /* all done with thumbnails! */
	}, token).then([this](task<int> the_task)
	{
		/* Finish adding them, but not if we were cancelled. */
		this->m_ren_status = REN_AVAILABLE;
		bool is_cancelled = false;
		try
		{
			the_task.get();
		}
		catch (const task_canceled& e)
		{
			(void)e;	// Unused parameter
			is_cancelled = true;
		}
	}, task_continuation_context::use_current());
}

void MainPage::OpenDocumentPrep(StorageFile^ file)
{
	if (this->m_num_pages != -1)
	{
		m_init_done = false;

		/* Set the index to the start of the document */
		this->xaml_vert_flipView->SelectedIndex = 0;
		this->xaml_horiz_flipView->SelectedIndex = 0;

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

void MainPage::OpenDocument(StorageFile^ file)
{
	this->SetFlipView();

	/* Open document and when open, push on */
	auto open_task = create_task(mu_doc->OpenFileAsync(file));
	open_task.then([this](int code) -> int
	{
		assert(IsMainThread());
		if (code != S_ISOK)
		{
			return code;
		}
		/* We need to check if password is required */
		if (mu_doc->RequiresPassword())
		{
			xaml_PasswordStack->Visibility = Windows::UI::Xaml::Visibility::Visible;
			return E_NEEDPASSWORD;
		}
		else
		{
			xaml_PasswordStack->Visibility = Windows::UI::Xaml::Visibility::Collapsed;
			return S_ISOK;
		}
	}).then([this](int code)->int
	{
		assert(IsMainThread());
		if (code == S_ISOK)
			InitialRender();
		return code;
	}, task_continuation_context::use_current()).then([this](int code)
	{
		if (code == S_ISOK)
			RenderThumbs();
		else
		{
			if (code != E_NEEDPASSWORD)
			{
				NotifyUser("Sorry, an issue was encountered in opening file", 
							StatusMessage);
			}
		}
	}, task_continuation_context::use_current());
}

void MainPage::InitialRender()
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
	/* Initialize all the flipvew items with blanks and the thumbnails. */
	for (int k = 0; k < m_num_pages; k++)
	{
		/* Blank pages */
		DocumentPage^ doc_page = ref new DocumentPage();
		Vector<RectList^>^ temp_link = ref new Vector<RectList^>();
		if (doc_page == nullptr || temp_link == nullptr)
			throw ref new FailureException("Document allocation failed!");
		doc_page->Image = m_BlankBmp;
		doc_page->Height = BLANK_HEIGHT;
		doc_page->Width = BLANK_WIDTH;
		doc_page->NativeHeight = BLANK_HEIGHT;
		doc_page->NativeWidth = BLANK_WIDTH;
		doc_page->Content = DUMMY;
		doc_page->TextBox = nullptr;
		doc_page->LinkBox = nullptr;
		m_docPages->Append(doc_page);
		m_thumbnails->Append(doc_page);
		/* Create empty lists for our links and specify that they have
			not been computed for these pages */
		m_page_link_list->Append(temp_link);
		m_linkset->Append(false);
	}

	this->xaml_horiz_flipView->ItemsSource = m_docPages;
	this->xaml_vert_flipView->ItemsSource = m_docPages;

	/* Do the first few pages, then start the thumbs */
	spatial_info_t spatial_info = InitSpatial(1);
	for (int k = 0; k < LOOK_AHEAD + 2; k++)
	{
		if (m_num_pages > k )
		{
			Point ras_size;
			float scale_factor;

			if (ComputePageSize(spatial_info, k, &ras_size, &scale_factor) == S_ISOK)
			{
				auto render_task = create_task(mu_doc->RenderPageAsync(k, (int)ras_size.X, (int)ras_size.Y, true, scale_factor));
				render_task.then([this, k, ras_size](InMemoryRandomAccessStream^ ras)
				{
					if (ras != nullptr)
						UpdatePage(k, ras, ras_size, FULL_RESOLUTION, 1.0);
				}, task_continuation_context::use_current());
			}
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
}

void MainPage::RenderRange(int curr_page)
{
	/* Render +/- the look ahead from where we are if blank page is present */
	spatial_info_t spatial_info = InitSpatial(m_doczoom);
	bool curr_page_rendered = true;
	int range = LOOK_AHEAD;

	assert(IsMainThread());
	if (m_flip_from_searchlink)
		range = 0;
	for (int k = curr_page - LOOK_AHEAD; k <= curr_page + LOOK_AHEAD; k++)
	{
		if (k >= 0 && k < m_num_pages)
		{
			/* Check if page is already rendered */
			auto doc = this->m_docPages->GetAt(k);
			if (doc->Content != FULL_RESOLUTION ||
				doc->PageZoom != m_doczoom)
			{
				Point ras_size;
				float scale_factor;
				if (ComputePageSize(spatial_info, k, &ras_size, &scale_factor) == S_ISOK)
				{
					double zoom = m_doczoom;
					auto render_task = create_task(mu_doc->RenderPageAsync(k, (int)ras_size.X, (int)ras_size.Y, true, scale_factor));
					render_task.then([this, k, ras_size, zoom, curr_page](InMemoryRandomAccessStream^ ras)
					{
						if (ras != nullptr)
						{
							Point new_ras_size = ras_size;

							/* This is so that the scroll update will apply the zoom
							keeping us in-sync.  And making sure that we can't
							exceed our limits with keyboard vs touch.  I.e. any
							resolution changes must go through the scrollviewer.
							It makes the upcoming page appear to come in at its
							zoom level of 1.0 but it is smoothly scaled to the
							current scale resolution. */
							new_ras_size.X = (float) (new_ras_size.X / zoom);
							new_ras_size.Y = (float)(new_ras_size.Y / zoom);
							UpdatePage(k, ras, new_ras_size, FULL_RESOLUTION, zoom);
						}
					}, task_continuation_context::use_current()).then([this, k, curr_page]()
					{
						if (k == curr_page && this->m_links_on)
							AddLinkCanvas();
						if (k == curr_page && this->m_text_list->Size > 0 &&
							m_flip_from_searchlink)
						{
							AddTextCanvas();
							m_flip_from_searchlink = false;
						}
						if (k == curr_page)
						{
							m_curr_flipView->UpdateLayout();
							UpdateZoom();
						}
					}, task_continuation_context::use_current());

				}
			}
			else
			{
				/* We did not need to render the curr_page, so add links below if
				   needed.   Otherwise, we need to wait for the task above to
				   complete before we add the links. */
				if (k == curr_page)
				{
					curr_page_rendered = false;
					UpdateZoom();
				}
			}
		}
	}
	m_currpage = curr_page;
	if (this->m_links_on && !curr_page_rendered)
		AddLinkCanvas();
	if (this->m_text_list->Size > 0 && !curr_page_rendered && m_flip_from_searchlink)
	{
		AddTextCanvas();
		m_flip_from_searchlink = false;
	}
}

void MainPage::FlipView_SelectionChanged(Object^ sender, SelectionChangedEventArgs^ e)
{
	if (m_init_done && !m_page_update)
	{
		int pos = this->m_curr_flipView->SelectedIndex;

		if (pos >= 0)
		{
			if (xaml_PageSlider->IsEnabled)
			{
				xaml_PageSlider->Value = pos + 1;
			}
			if (m_sliderchange)
			{
				m_sliderchange = false;
				return;
			}
			else
			{
				/* Make sure to clear any text search */
				auto doc_old = this->m_docPages->GetAt(m_currpage);
				doc_old->TextBox = nullptr;
			}
			/* Get the current page */
			int curr_page = this->m_currpage;
			this->m_currpage = pos;
			this->RenderRange(pos);
			this->ReleasePages(curr_page, pos);
		}
	}
}

/* Slider via drag */
void MainPage::Slider_ValueChanged(Platform::Object^ sender, Windows::UI::Xaml::Input::PointerRoutedEventArgs^ e)
{
	Slider_Common();
}

/* Slider via keyboard */
void MainPage::Slider_Key(Platform::Object^ sender, Windows::UI::Xaml::Input::KeyRoutedEventArgs^ e)
{
	Slider_Common();
}

void MainPage::Slider_Common()
{
	if (IsNotStandardView() || m_currpage == this->xaml_PageSlider->Value - 1)
		return;

	int newValue = (int) this->xaml_PageSlider->Value - 1;  /* zero based */

	if (m_init_done && this->xaml_PageSlider->IsEnabled)
	{
		this->m_curr_flipView->SelectedIndex = (int) (this->xaml_PageSlider->Value - 1);
	}
	return;
}

/* Search Related Code */
void MainPage::Searcher(Platform::Object^ sender, Windows::UI::Xaml::RoutedEventArgs^ e)
{
	ShowSearchBox();
	UpdateAppBarButtonViewState();
}

void MainPage::ShowSearchBox()
{
	/* Update the app bar so that we can do the search */
	StackPanel^ leftPanel = (StackPanel^) this->TopAppBar->FindName("LeftPanel");

	if (leftPanel != nullptr && m_insearch)
	{
		m_insearch = false;
		FindBox->Visibility = Windows::UI::Xaml::Visibility::Collapsed;
		PrevSearch->Visibility = Windows::UI::Xaml::Visibility::Collapsed;
		NextSearch->Visibility = Windows::UI::Xaml::Visibility::Collapsed;
	}
	else if (leftPanel != nullptr && !m_insearch)
	{
		/* Search is not going to work in the squashed view */
		if (this->ActualWidth < SEARCH_FIT)
		{
			NotifyUser("Please enlarge application to use search", StatusMessage);
			return;
		}
		m_insearch = true;
		FindBox->Visibility = Windows::UI::Xaml::Visibility::Visible;
		PrevSearch->Visibility = Windows::UI::Xaml::Visibility::Visible;
		NextSearch->Visibility = Windows::UI::Xaml::Visibility::Visible;
	}
}

void MainPage::ClearTextSearch()
{
	/* Clear out any old search result */
	if (m_text_list->Size > 0)
		m_text_list->Clear();
}

void MainPage::ShowSearchResults(int page_num, unsigned int box_count)
{
	int old_page = this->m_currpage;
	int new_page = page_num;

	ClearTextSearch();

	/* Compute any scalings */
	Point screenSize;
	Point pageSize;
	Point scale;

	screenSize.Y = (float) (this->ActualHeight);
	screenSize.X = (float) (this->ActualWidth);
	screenSize.X *= screenScale;
	screenSize.Y *= screenScale;

	try
	{
		pageSize = mu_doc->GetPageSize(m_currpage);
	}
	catch (Exception ^except)
	{
#ifdef _DEBUG
		NotifyUser(except->Message, ErrorMessage);
#endif 
		return;
	}
	scale = fitPageToScreen(pageSize, screenSize);
	auto doc_page = this->m_docPages->GetAt(old_page);

	/* Construct our list of rectangles */
	for (unsigned int k = 0; k < box_count; k++)
	{
		RectList^ rect_item = ref new RectList();
		if (rect_item == nullptr)
		{
			break;
		}
		auto curr_box = mu_doc->GetTextSearch(k);

		rect_item->Color = m_textcolor;
		rect_item->Height = (int) (curr_box->LowerRight.Y - curr_box->UpperLeft.Y);
		rect_item->Width = (int) (curr_box->LowerRight.X - curr_box->UpperLeft.X);
		rect_item->X = (int) (curr_box->UpperLeft.X * scale.X);
		rect_item->Y = (int) (curr_box->UpperLeft.Y * scale.Y);
		rect_item->Width = (int)((double)rect_item->Width * scale.X);
		rect_item->Height = (int)((double)rect_item->Height * scale.Y);
		rect_item->Index = k.ToString();
		m_text_list->Append(rect_item);
	}
	/* Make sure the current page has its text results cleared */
	doc_page->TextBox = nullptr;

	/* Go ahead and set our doc item to this in the vertical and horizontal view */
	m_searchpage = new_page;
	m_flip_from_searchlink = true;

	if (old_page == new_page)
	{
		FlipView_SelectionChanged(nullptr, nullptr);
	}
	else
	{
		this->m_curr_flipView->SelectedIndex = new_page;
	}
	return;
}

void MainPage::SearchNext(Platform::Object^ sender, Windows::UI::Xaml::RoutedEventArgs^ e)
{
	if (IsNotStandardView())
		return;

	StackPanel^ leftPanel = (StackPanel^) this->TopAppBar->FindName("LeftPanel");
	TextBox^ findBox = (TextBox^) leftPanel->FindName("FindBox");
	String^ textToFind = findBox->Text;

	if (this->m_search_active == false && textToFind != nullptr)
		SearchInDirection(1, textToFind);
}

void MainPage::SearchPrev(Platform::Object^ sender, Windows::UI::Xaml::RoutedEventArgs^ e)
{
	if (IsNotStandardView())
		return;

	StackPanel^ leftPanel = (StackPanel^) this->TopAppBar->FindName("LeftPanel");
	TextBox^ findBox = (TextBox^) leftPanel->FindName("FindBox");
	String^ textToFind = findBox->Text;

	if (this->m_search_active == false && textToFind != nullptr)
		SearchInDirection(-1, textToFind);
}

void MainPage::CancelSearch(Platform::Object^ sender, Windows::UI::Xaml::RoutedEventArgs^ e)
{
	m_searchcts.cancel();
	xaml_ProgressStack->Visibility = Windows::UI::Xaml::Visibility::Collapsed;
	this->m_search_active = false;
}

void MainPage::AddTextCanvas()
{
	/* Go ahead and set our doc item to this in the vertical and horizontal view */
	auto doc_page = this->m_docPages->GetAt(m_currpage);
	assert(doc_page->Content == FULL_RESOLUTION);
	if (doc_page->Content == FULL_RESOLUTION)  // We should not be doing links for thumbnails
	{
		doc_page->TextBox = m_text_list;
	}
	this->m_search_active = false;
}

void MainPage::SearchProgress(IAsyncOperationWithProgress<int, double>^ operation, double status)
{
	xaml_Progress->Value = status;
}

void MainPage::SearchInDirection(int dir, String^ textToFind)
{
	cancellation_token_source cts;
	auto token = cts.get_token();
	m_searchcts = cts;
	int pos = m_currpage;
	int start;

	if (m_searchpage == pos)
		start = pos + dir;
	else
		start = pos;

	if (start < 0)
		return;
	if (start > this->m_num_pages - 1)
		return;
	this->m_search_active = true;

	ProgressBar^ my_xaml_Progress = (ProgressBar^) (this->FindName("xaml_Progress"));
	xaml_ProgressStack->Visibility = Windows::UI::Xaml::Visibility::Visible;
	auto temp = mu_doc->SearchDocumentWithProgressAsync(textToFind, dir, start, 
														m_num_pages);
	temp->Progress = ref new AsyncOperationProgressHandler<int, double>(this, &MainPage::SearchProgress);

	auto search_task = create_task(temp, token);

	/* Do the continuation on the ui thread */
	auto con_task = search_task.then([this, textToFind](int page_num)
	{
		xaml_ProgressStack->Visibility = Windows::UI::Xaml::Visibility::Collapsed;
		if (page_num == TEXT_NOT_FOUND)
		{
			auto str1 = "\"" + textToFind + "\" Was Not Found In The Search";
			NotifyUser(str1, StatusMessage);
			this->m_search_active = false;
		}
		else
		{
			int box_count = mu_doc->TextSearchCount();

			if (box_count > 0)
			{
				this->ShowSearchResults(page_num, (unsigned int) box_count);
			}
		}
	}, task_continuation_context::use_current());
}

/* This is here to handle when we rotate or go into the snapview mode  */
void MainPage::GridSizeChanged()
{
	int height = (int) (this->ActualHeight);
	int width = (int) (this->ActualWidth);
	FlipView^ old_flip = m_curr_flipView;

	if (TopAppBar1->IsOpen)
	{
		UpdateAppBarButtonViewState();
	}

	if (height > width)
	{
		m_curr_flipView = this->xaml_vert_flipView;
		this->xaml_zoomCanvas->Height = height;
		this->xaml_zoomCanvas->Width = width;
		this->m_curr_flipView->Height = height;
		this->m_curr_flipView->Width = width;

		xaml_vert_flipView->IsEnabled = true;
		xaml_vert_flipView->Opacity = 1;
		xaml_horiz_flipView->IsEnabled = false;
		xaml_horiz_flipView->Opacity = 0;	
	}
	else
	{
		m_curr_flipView = this->xaml_horiz_flipView;
		this->xaml_zoomCanvas->Height = height;
		this->xaml_zoomCanvas->Width = width;
		this->m_curr_flipView->Height = height;
		this->m_curr_flipView->Width = width;

		xaml_horiz_flipView->IsEnabled = true;
		xaml_horiz_flipView->Opacity = 1;
		xaml_vert_flipView->IsEnabled = false;
		xaml_vert_flipView->Opacity = 0;
	}

	if (xaml_WebView->Visibility == Windows::UI::Xaml::Visibility::Visible)
		xaml_WebView->Height = xaml_OutsideGrid->ActualHeight;

	UpdateThumbSizes();

	if (m_num_pages > 0 && old_flip != m_curr_flipView && old_flip != nullptr)
	{
		/* If links are on or off, we need to invalidate */
		ClearLinks();
		InvalidateLinks();

		/* And force a rerender */
		for (int k = m_currpage - LOOK_AHEAD; k <= m_currpage + LOOK_AHEAD; k++)
		{
			if (k >= 0 && k < m_num_pages)
			{
				DocumentPage ^doc = this->m_docPages->GetAt(k);
				doc->Content = OLD_RESOLUTION;
			}
		}
		this->m_curr_flipView->SelectedIndex = this->m_currpage;
		FlipView_SelectionChanged(nullptr, nullptr);
	}
}

void MainPage::UpdatePreRenderedPageSizes()
{
	if (m_num_pages > 0)
	{
		for (int k = m_currpage - LOOK_AHEAD; k <= m_currpage + LOOK_AHEAD; k++)
		{
			if (k >= 0 && k < m_num_pages && k != m_currpage)
			{
				DocumentPage ^doc = this->m_docPages->GetAt(k);
				doc->Content = OLD_RESOLUTION;
				int curr_height = doc->Height;
				int curr_width = doc->Width;

				double scale_x = (double)curr_height / (double)(this->xaml_zoomCanvas->Height);
				double scale_y = (double)curr_width / (double)(this->xaml_zoomCanvas->Width);

				double min_scale = max(scale_x, scale_y);
				doc->Height = (int) (curr_height * m_doczoom / min_scale);
				doc->Width = (int) (curr_width * m_doczoom / min_scale);
			}
		}
	}
}

void MainPage::UpdateThumbSizes()
{
	/* Reset the thumbview scaling values */
	if (m_num_pages > 0)
	{
		int num_items = m_docPages->Size;
		for (int i = 0; i < num_items; i++)
		{
			DocumentPage ^thumb_page = m_docPages->GetAt(i);
			if (thumb_page != nullptr && thumb_page->Image != nullptr
				&& thumb_page->Content == THUMBNAIL)
			{
				int curr_height = thumb_page->NativeHeight;
				int curr_width = thumb_page->NativeWidth;

				double scale_x = (double)curr_height / (double)(this->xaml_zoomCanvas->Height);
				double scale_y = (double)curr_width / (double)(this->xaml_zoomCanvas->Width);

				double min_scale = max(scale_x, scale_y);
				thumb_page->Height = (int)(curr_height / min_scale);
				thumb_page->Width = (int)(curr_width / min_scale);
			}
		}
	}
};

/* Link related code */
void MainPage::Linker(Platform::Object^ sender, Windows::UI::Xaml::RoutedEventArgs^ e)
{
	m_links_on = !m_links_on;

	if (!m_init_done || IsNotStandardView())
		return;
	if (m_links_on)
		AddLinkCanvas();
	else
		ClearLinks();
}

void MainPage::ClearLinks()
{
	/* Make sure surrounding render pages lose their links */
	for (int k = m_currpage - LOOK_AHEAD; k <= m_currpage + LOOK_AHEAD; k++)
	{
		if (k >= 0 && k < m_num_pages)
		{
			auto doc_page = this->m_docPages->GetAt(k);
			if (doc_page->Content == FULL_RESOLUTION)
			{
				doc_page->LinkBox = nullptr;
			}
		}
	}
}

void MainPage::InvalidateLinks()
{
	for (int k = 0; k < m_num_pages; k++)
		m_linkset->SetAt(k, false);
}

/* Add in the link rects.  If we have not already computed them then do that now */
void MainPage::AddLinkCanvas()
{
	/* See if the link object for this page has already been computed */
	int link_page = m_linkset->GetAt(m_currpage);
	auto doc_page = this->m_docPages->GetAt(m_currpage);

	if (!link_page)
	{
		m_linkset->SetAt(m_currpage, true);
		unsigned int num_links = mu_doc->ComputeLinks(m_currpage);
		if (num_links == 0) return;

		Point screenSize;
		Point pageSize;
		Point scale;

		screenSize.Y = (float) (this->ActualHeight);
		screenSize.X = (float)(this->ActualWidth);
		screenSize.X *= screenScale;
		screenSize.Y *= screenScale;

		try
		{
			pageSize = mu_doc->GetPageSize(m_currpage);
		}
		catch (Exception ^except)
		{
#ifdef _DEBUG
			NotifyUser(except->Message, ErrorMessage);
#endif 
			return;
		}
		scale = fitPageToScreen(pageSize, screenSize);

		/* Create a new RectList collection */
		auto link_list = ref new Platform::Collections::Vector<RectList^>();
		if (link_list == nullptr)
			return;

		/* Now add the rects */
		for (unsigned int k = 0; k < num_links; k++)
		{
			auto curr_link = mu_doc->GetLink(k);
			if (curr_link->Type != NOT_SET)
			{
				RectList^ rect_item = ref new RectList();
				if (rect_item == nullptr)
					break;
				rect_item->Color = m_linkcolor;
				rect_item->Height = (int) (curr_link->LowerRight.Y - curr_link->UpperLeft.Y);
				rect_item->Width = (int) (curr_link->LowerRight.X - curr_link->UpperLeft.X);
				rect_item->X = (int) (curr_link->UpperLeft.X * scale.X);
				rect_item->Y = (int) (curr_link->UpperLeft.Y * scale.Y);
				rect_item->Width = (int)((double)rect_item->Width * scale.X);
				rect_item->Height = (int)((double)rect_item->Height * scale.Y);
				rect_item->Type = curr_link->Type;
				rect_item->Urilink = curr_link->Uri;
				rect_item->PageNum = curr_link->PageNum;
				rect_item->Index = k.ToString();
				link_list->Append(rect_item);
			}
		}
		/* Now set it in our list of links */
		m_page_link_list->SetAt(m_currpage, link_list);
	}
	/* Go ahead and set our doc item to this in the vertical and horizontal view */
	if (doc_page->LinkBox == nullptr)
	{
		if (doc_page->Content == FULL_RESOLUTION)  // We should not be doing links for thumbnails
		{
			doc_page->LinkBox = m_page_link_list->GetAt(m_currpage);
		}
	}
}

/* A link was tapped */
void MainPage::LinkTapped(Platform::Object^ sender, Windows::UI::Xaml::Input::TappedRoutedEventArgs^ e)
{
	Rectangle^ rect = safe_cast<Rectangle^>(e->OriginalSource);
	String^ str_index = safe_cast<String^>(rect->Tag);
	int index = (int) (_wtof(str_index->Data()));

	if (index >= 0 && index < m_num_pages)
	{
		auto link_list = m_page_link_list->GetAt(m_currpage);
		auto link = link_list->GetAt(index);

		if (link->Type == LINK_GOTO)
		{
			this->m_curr_flipView->SelectedIndex = link->PageNum;
		}
		else if (link->Type == LINK_URI)
		{
			// Set the option to show a warning
			auto launchOptions = ref new Windows::System::LauncherOptions();
			launchOptions->TreatAsUntrusted = true;

			// Launch the URI with a warning prompt
			concurrency::task<bool> launchUriOperation(Windows::System::Launcher::LaunchUriAsync(link->Urilink, launchOptions));
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
		}
	}
}

/* Bring up the contents */
void MainPage::ContentDisplay(Platform::Object^ sender, Windows::UI::Xaml::RoutedEventArgs^ e)
{
	if (this->m_num_pages < 0)
		return;

	if (IsNotStandardView() && !this->xaml_ListView->IsEnabled)
		return;

	if (this->xaml_ListView->IsEnabled)
	{
		this->xaml_ListView->Opacity = 0.0;
		this->xaml_ListView->IsEnabled = false;
		this->m_curr_flipView->Opacity = 1.0;
		this->m_curr_flipView->IsEnabled = true;
		this->xaml_PageSlider->IsEnabled = true;
	}
	else
	{
		if (xaml_ListView->Items->Size == 0)
		{
			unsigned int size_content = mu_doc->ComputeContents();
			/* Bring up the content now */
			for (unsigned int k = 0; k < size_content; k++)
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
				this->xaml_PageSlider->IsEnabled = false;
			}
		}
		else
		{
			this->xaml_ListView->Opacity = 1.0;
			this->xaml_ListView->IsEnabled = true;
			this->m_curr_flipView->Opacity = 0.0;
			this->m_curr_flipView->IsEnabled = false;
			this->xaml_PageSlider->IsEnabled = false;
		}
	}
}

void MainPage::ContentSelected(Platform::Object^ sender, Windows::UI::Xaml::Controls::ItemClickEventArgs^ e)
{
	ContentItem^ b = safe_cast<ContentItem^>(e->ClickedItem);
	int newpage = b->Page;

	if (newpage > -1 && newpage < this->m_num_pages)
	{
		this->xaml_ListView->Opacity = 0.0;
		this->xaml_ListView->IsEnabled = false;
		this->m_curr_flipView->Opacity = 1.0;
		this->m_curr_flipView->IsEnabled = true;
		this->xaml_PageSlider->IsEnabled = true;

		int old_page = this->m_currpage;
		this->m_curr_flipView->SelectedIndex = newpage;
		this->m_currpage = newpage;
	}
}

void MainPage::Reflower(Platform::Object^ sender, Windows::UI::Xaml::RoutedEventArgs^ e)
{
	if (this->m_num_pages < 0) return;

	if (xaml_WebView->Visibility == Windows::UI::Xaml::Visibility::Visible)
	{
		/* Go back to flip view */
		xaml_WebView->Visibility = Windows::UI::Xaml::Visibility::Collapsed;
		this->xaml_MainGrid->Opacity = 1.0;
		this->m_curr_flipView->IsEnabled = true;
		this->xaml_PageSlider->IsEnabled = true;
	}
	else if (this->m_curr_flipView->IsEnabled)
	{
		String^ html_string = mu_doc->ComputeHTML(this->m_currpage);
		xaml_WebView->Visibility = Windows::UI::Xaml::Visibility::Visible;
		this->xaml_MainGrid->Opacity = 0.0;
		this->m_curr_flipView->IsEnabled = false;
		this->xaml_PageSlider->IsEnabled = false;
		this->xaml_WebView->NavigateToString(html_string);
		this->xaml_WebView->Height = this->ActualHeight;
	}
}

/* Need to handle resizing of app bar to make sure everything fits */
void MainPage::topAppBar_Loaded(Platform::Object^ sender, Windows::UI::Xaml::RoutedEventArgs^ e)
{
	/* Remove search box in snapped view as we don't have the room for it */
	int temp = (int) (this->ActualWidth);
	if (this->ActualWidth < SEARCH_FIT && m_insearch)
		ShowSearchBox();
	UpdateAppBarButtonViewState();
	/* This is needed to make sure we get the proper state during start-up.  The
	   object has to be visible to set the state.  So that is the way we start */
	if (!m_insearch && FindBox->Visibility == Windows::UI::Xaml::Visibility::Visible)
	{
		FindBox->Visibility = Windows::UI::Xaml::Visibility::Collapsed;
		PrevSearch->Visibility = Windows::UI::Xaml::Visibility::Collapsed;
		NextSearch->Visibility = Windows::UI::Xaml::Visibility::Collapsed;
	}
}

String^ MainPage::GetVisualState()
{
	String^ visualstate = "FullScreenLandscape";

	int width = (int) (this->ActualWidth);
	int height = (int) (this->ActualHeight);

	if (width < VS_SMALL)
	{
		visualstate = "Snapped";
	}
	else if (width < VS_LARGE)
	{
		if (width < height)
		{
			visualstate = "FullScreenPortrait";
		}
		else
		{
			visualstate = "Snapped";
		}
	}
	return visualstate;
}

void MainPage::UpdateAppBarButtonViewState()
{
	String ^viewState = GetVisualState();
	VisualStateManager::GoToState(Search, viewState, true);
	VisualStateManager::GoToState(Contents, viewState, true);
	VisualStateManager::GoToState(Links, viewState, true);
	VisualStateManager::GoToState(Reflow, viewState, true);
	VisualStateManager::GoToState(ZoomIn, viewState, true);
	VisualStateManager::GoToState(ZoomOut, viewState, true);
	VisualStateManager::GoToState(PrevSearch, viewState, true);
	VisualStateManager::GoToState(NextSearch, viewState, true);
}

/* Scroll viewer scale changes.  If first time to this page, then we essentially
	have our scroll setting set at 1.0.   */
void MainPage::ScrollChanged(Platform::Object^ sender,
					Windows::UI::Xaml::Controls::ScrollViewerViewChangedEventArgs^ e)
{
	ScrollViewer^ scrollviewer = safe_cast<ScrollViewer^> (sender);
	auto doc_page = this->m_docPages->GetAt(m_currpage);
	double new_scroll_zoom = scrollviewer->ZoomFactor;

	/* Check if we are already at this resolution with this page */
	if (new_scroll_zoom == doc_page->PageZoom)
		return;

	if (!e->IsIntermediate)
	{
		int page = m_currpage;

		m_doczoom = new_scroll_zoom;
		if (m_doczoom > ZOOM_MAX)
		{
			m_doczoom = ZOOM_MAX;
		}
		if (m_doczoom < ZOOM_MIN)
		{
			m_doczoom = ZOOM_MIN;
		}
		/* Render at new resolution. */
		spatial_info_t spatial_info = InitSpatial(m_doczoom);
		Point ras_size;
		float scale_factor;
		if (ComputePageSize(spatial_info, page, &ras_size, &scale_factor) == S_ISOK)
		{
			doc_page->PageZoom = m_doczoom;
			auto render_task = create_task(mu_doc->RenderPageAsync(page, (int)ras_size.X, (int)ras_size.Y, true, scale_factor));
			render_task.then([this, page, ras_size, scrollviewer](InMemoryRandomAccessStream^ ras)
			{
				if (ras != nullptr)
					ReplaceImage(page, ras, ras_size, m_doczoom);
			}, task_continuation_context::use_current());
		}
	}
}

/* Needed to find scrollviewer child from template of flipview item */
Windows::UI::Xaml::FrameworkElement^ FindVisualChildByName(DependencyObject^ obj, String^ name)
{
	FrameworkElement^ ret;
	if (obj == nullptr) return nullptr;

	int numChildren = VisualTreeHelper::GetChildrenCount(obj);

	for (int i = 0; i < numChildren; i++)
	{
		auto objChild = VisualTreeHelper::GetChild(obj, i);
		auto child = safe_cast<FrameworkElement^>(objChild);
		if (child != nullptr && child->Name == name)
		{
			return child;
		}
		ret = FindVisualChildByName(objChild, name);
		if (ret != nullptr)
			break;
	}
	return ret;
}

void MainPage::ZoomInPress(Platform::Object^ sender, Windows::UI::Xaml::RoutedEventArgs^ e)
{
	if (!m_init_done || IsNotStandardView()) return;
	NonTouchZoom(ZOOM_IN);
}

void MainPage::ZoomOutPress(Platform::Object^ sender, Windows::UI::Xaml::RoutedEventArgs^ e)
{
	if (!m_init_done || IsNotStandardView()) return;
	NonTouchZoom(ZOOM_OUT);
}

void MainPage::NonTouchZoom(int zoom)
{
	auto doc_page = this->m_docPages->GetAt(m_currpage);
	double curr_zoom = doc_page->PageZoom;

	ScrollViewer^ scrollviewer;
	FlipViewItem^ item = safe_cast<FlipViewItem^>
		(m_curr_flipView->ContainerFromIndex(m_currpage));
	auto item2 = m_curr_flipView->ContainerFromIndex(m_currpage);

	/* We don't know which one so check for both */
	ScrollViewer^ t1 =
		safe_cast<ScrollViewer^> (FindVisualChildByName(item2, "xaml_ScrollView_v"));
	ScrollViewer^ t2 =
		safe_cast<ScrollViewer^> (FindVisualChildByName(item2, "xaml_ScrollView_h"));

	if (t1 != nullptr)
		scrollviewer = t1;
	else
		scrollviewer = t2;

	if (scrollviewer == nullptr)
		return;

	if (zoom == ZOOM_IN)
	{
		curr_zoom = curr_zoom + KEYBOARD_ZOOM_STEP;
		if (curr_zoom > ZOOM_MAX) curr_zoom = ZOOM_MAX;
	}
	else if (zoom == ZOOM_OUT)
	{
		curr_zoom = curr_zoom - KEYBOARD_ZOOM_STEP;
		if (curr_zoom < ZOOM_MIN) curr_zoom = ZOOM_MIN;
	} else
		return;

	/* It all needs to be driven by the scroll viewer otherwise we
	   end up out of sync */
	Platform::Object^ obj_zoom = (float)curr_zoom;
	Platform::IBox<float>^ box_zoom;
	box_zoom = safe_cast<Platform::IBox<float>^>(obj_zoom);

	scrollviewer->ChangeView(nullptr, nullptr, box_zoom, false);
}

/* Adjust the page scrollviewer to the current zoom level */
void MainPage::UpdateZoom()
{
	ScrollViewer^ scrollviewer;
	FlipViewItem^ item = safe_cast<FlipViewItem^>
		(m_curr_flipView->ContainerFromIndex(m_currpage));
	auto item2 = m_curr_flipView->ContainerFromIndex(m_currpage);

	/* We don't know which one so check for both */
	ScrollViewer^ t1 =
		safe_cast<ScrollViewer^> (FindVisualChildByName(item2, "xaml_ScrollView_v"));
	ScrollViewer^ t2 =
		safe_cast<ScrollViewer^> (FindVisualChildByName(item2, "xaml_ScrollView_h"));

	if (t1 != nullptr)
		scrollviewer = t1;
	else
		scrollviewer = t2;

	if (scrollviewer == nullptr)
		return;

	float curr_zoom = scrollviewer->ZoomFactor;
	Platform::Object^ obj_zoom = (float)m_doczoom;
	Platform::IBox<float>^ box_zoom;
	box_zoom = safe_cast<Platform::IBox<float>^>(obj_zoom);
	scrollviewer->ChangeView(nullptr, nullptr, box_zoom, false);
}

/* Zoom in and out for keyboard only case. */
void MainPage::OnKeyDown(KeyRoutedEventArgs^ e)
{
	if (!m_init_done || IsNotStandardView()) return;

	long val = (long) (e->Key);

	if (val == KEY_PLUS)
		NonTouchZoom(ZOOM_IN);
	else if (val == KEY_MINUS)
		NonTouchZoom(ZOOM_OUT);
	else
		return;
}

void MainPage::PasswordOK(Platform::Object^ sender, Windows::UI::Xaml::RoutedEventArgs^ e)
{
	/* If password checks out then go ahead and start rendering */
	if (mu_doc->ApplyPassword(xaml_password->Password))
	{
		xaml_password->Password = nullptr;
		xaml_PasswordStack->Visibility = Windows::UI::Xaml::Visibility::Collapsed;
		InitialRender();
		RenderThumbs();
	}
	else
		NotifyUser("Incorrect Password", StatusMessage);
}

/* So that we know if we are in a standard view case and not in reflow, or
 * content type */
bool MainPage::IsNotStandardView()
{
	return (this->xaml_ListView->Opacity == 1.0 ||
		xaml_WebView->Visibility == Windows::UI::Xaml::Visibility::Visible);
}

/* The following code is for print support. */
void MainPage::RegisterForPrinting()
{
	m_print_manager = Windows::Graphics::Printing::PrintManager::GetForCurrentView();
	m_print_manager->PrintTaskRequested +=
		ref new TypedEventHandler<PrintManager^, PrintTaskRequestedEventArgs^>(this, &MainPage::SetPrintTask);
}

void MainPage::SetPrintTask(PrintManager^ sender, PrintTaskRequestedEventArgs^ args)
{
	PrintTaskSourceRequestedHandler^ source_handler =
		ref new PrintTaskSourceRequestedHandler([this](PrintTaskSourceRequestedArgs^ args)-> void{
		Microsoft::WRL::ComPtr<PrintPages> document_source;
		ThrowIfFailed(Microsoft::WRL::MakeAndInitialize<PrintPages>(&document_source, reinterpret_cast<IUnknown*>(this)));
		IPrintDocumentSource^ objSource(reinterpret_cast<IPrintDocumentSource^>(document_source.Get()));
		args->SetSource(objSource);
	});

	PrintTask^ print_task = 
		args->Request->CreatePrintTask(L"MuPDF WinRT Print", source_handler);
	
	/* Call backs so that we know when we are all done with the printing */
	print_task->Progressing += 
		ref new TypedEventHandler<PrintTask^, PrintTaskProgressingEventArgs^>(this, &MainPage::PrintProgress);
	print_task->Completed +=
		ref new TypedEventHandler<PrintTask^, PrintTaskCompletedEventArgs^>(this, &MainPage::PrintCompleted);
	m_print_active = PRINT_ACTIVE;
	m_curr_print_count = 0;

	PrintTaskOptionDetails^ printDetailedOptions = 
		PrintTaskOptionDetails::GetFromPrintTaskOptions(print_task->Options);

	// Some standard printer options
	printDetailedOptions->DisplayedOptions->Clear();
	printDetailedOptions->DisplayedOptions->Append(Windows::Graphics::Printing::StandardPrintTaskOptions::MediaSize);
	printDetailedOptions->DisplayedOptions->Append(Windows::Graphics::Printing::StandardPrintTaskOptions::Copies);

	// Our custom options
	PrintCustomItemListOptionDetails^ resolution = 
	printDetailedOptions->CreateItemListOption("resolution", "Render Resolution");
	resolution->AddItem("sres96", "96dpi");
	resolution->AddItem("sres150", "150 dpi");
	resolution->AddItem("sres300", "300 dpi");
	resolution->AddItem("sres600", "600 dpi");
	resolution->TrySetValue("sres600");
	m_printresolution = 600;
	printDetailedOptions->DisplayedOptions->Append("resolution");

	PrintCustomItemListOptionDetails^ location = printDetailedOptions->CreateItemListOption("location", "Location");
	location->AddItem("sCenter", "Center");
	location->AddItem("sTopleft", "Top Left");
	// Add the custom option to the option list.
	printDetailedOptions->DisplayedOptions->Append("location");
	location->TrySetValue("sCenter");
	m_centerprint = true;
	print_task->Options->MediaSize = PrintMediaSize::NorthAmericaLetter;

	PrintCustomItemListOptionDetails^ pageFormat = printDetailedOptions->CreateItemListOption(L"PageRange", L"Page Range");
	pageFormat->AddItem(L"PrintAll", L"Print all");
	pageFormat->AddItem(L"PrintRange", L"Print Range");
	printDetailedOptions->DisplayedOptions->Append(L"PageRange");
	PrintCustomTextOptionDetails^ pageRangeEdit = printDetailedOptions->CreateTextOption(L"PageRangeEdit", L"Range");

	printDetailedOptions->OptionChanged += 
		ref new TypedEventHandler<PrintTaskOptionDetails^, PrintTaskOptionChangedEventArgs^>(this, &MainPage::PrintOptionsChanged);
}

int MainPage::GetPrintPageCount()
{
	if (m_ppage_num_list.size() > 0)
		return (int) m_ppage_num_list.size();
	else
		return m_num_pages;
}

void MainPage::PrintOptionsChanged(PrintTaskOptionDetails^ sender, PrintTaskOptionChangedEventArgs^ args)
{
	bool force_reset = false;

	if (args->OptionId == nullptr)
		return;

	String^ optionId = safe_cast<String^>(args->OptionId);

	if (optionId == "resolution")
	{
		IPrintOptionDetails^ resolution = sender->Options->Lookup(optionId);
		String^ resolutionValue = safe_cast<String^>(resolution->Value);

		if (resolutionValue == "sres96")
		{
			m_printresolution = 96;
		}
		else if (resolutionValue == "sres150")
		{
			m_printresolution = 150;
		}
		else if (resolutionValue == "sres300")
		{
			m_printresolution = 300;
		}
		else if(resolutionValue == "sres600")
		{
			m_printresolution = 600;
		}
	}

	/* Need to update preview with a change of this one */
	if (optionId == "location")
	{
		IPrintOptionDetails^ scaling = sender->Options->Lookup(optionId);
		String^ scaleValue = safe_cast<String^>(scaling->Value);

		if (scaleValue == "sCenter")
		{
			m_centerprint = true;
		}
		if (scaleValue == "sTopleft")
		{
			m_centerprint = false;
		}
		force_reset = true;
	}

	if (optionId == L"PageRange")
	{
		IPrintOptionDetails^ pagerange = sender->Options->Lookup(optionId);
		String^ pageRangeValue = pagerange->Value->ToString();

		if(pageRangeValue == L"PrintRange")
		{
			sender->DisplayedOptions->Append(L"PageRangeEdit");
			m_pageRangeEditVisible = true;
		}
		else
		{
			RemovePageRangeEdit(sender);
		}
		RefreshPreview();
	}
	
	if (optionId == L"PageRangeEdit")
	{
		IPrintOptionDetails^ pagerange = sender->Options->Lookup(optionId);

		std::wregex rangePattern(L"^\\s*\\d+\\s*(\\-\\s*\\d+\\s*)?(\\,\\s*\\d+\\s*(\\-\\s*\\d+\\s*)?)*$");
		std::wstring pageRangeValue(pagerange->Value->ToString()->Data());

		if(!std::regex_match(pageRangeValue.begin(), pageRangeValue.end(), rangePattern))
		{
			pagerange->ErrorText = L"Invalid Page Range (eg: 1-3, 5)";
		}
		else
		{
			pagerange->ErrorText = L"";
			try
			{
				GetPagesInRange(pagerange->Value->ToString());
			}
			catch(PageRangeException* rangeException)
			{
				pagerange->ErrorText = ref new String(rangeException->get_DisplayMessage().data());
				delete rangeException;
			}
			force_reset = true;
		}
	}
	if (force_reset)
	{
		RefreshPreview();
	}
}

void MainPage::SplitString(String^ string, wchar_t delimiter, std::vector<std::wstring>& words)
	{
	std::wistringstream iss(string->Data());

	std::wstring part;
	while(std::getline(iss, part, delimiter))
	{
		words.push_back(part);
	};
}

void MainPage::GetPagesInRange(String^ pagerange)
{
	std::vector<std::wstring> vector_range;
	SplitString(pagerange, ',', vector_range);

	m_ppage_num_list.clear();
	for(std::vector<std::wstring>::iterator it = vector_range.begin(); it != vector_range.end(); ++ it)
	{
		int intervalPos = static_cast<int>((*it).find('-'));
		if( intervalPos != -1)
		{
			int start = _wtoi((*it).substr(0, intervalPos).data());
			int end = _wtoi((*it).substr(intervalPos + 1, (*it).length() - intervalPos - 1).data());

			if ((start < 1) || (end > static_cast<int>(m_num_pages)) || (start >= end))
			{
				std::wstring message(L"Invalid page(s) in range ");

				message.append(std::to_wstring(start));
				message.append(L" - ");
				message.append(std::to_wstring(end));

				throw new PageRangeException(message);
			}

			for(int intervalPage=start; intervalPage <= end; ++intervalPage)
			{
				m_ppage_num_list.push_back(intervalPage);
			}
		}
		else
		{
			int pageNr = _wtoi((*it).data());
			std::wstring message(L"Invalid page ");

			if (pageNr < 1)
			{
				message.append(std::to_wstring(pageNr));
				throw new PageRangeException(message);
			}
			if (pageNr > static_cast<int>(m_num_pages))
			{
				message.append(std::to_wstring(pageNr));
				throw new PageRangeException(message);
			}
			m_ppage_num_list.push_back(pageNr);
		}
	}
	std::sort(m_ppage_num_list.begin(), m_ppage_num_list.end(), std::less<int>());
	std::unique(m_ppage_num_list.begin(), m_ppage_num_list.end());
}

void MainPage::RemovePageRangeEdit(PrintTaskOptionDetails^ printTaskOptionDetails)
{
	if (m_pageRangeEditVisible)
	{
		unsigned int index;
		if(printTaskOptionDetails->DisplayedOptions->IndexOf(ref new String(L"PageRangeEdit"), &index))
		{
			printTaskOptionDetails->DisplayedOptions->RemoveAt(index);
		}
		m_pageRangeEditVisible = false;
	}
}

void MainPage::CreatePrintControl(_In_  IPrintDocumentPackageTarget* docPackageTarget,
									_In_  D2D1_PRINT_CONTROL_PROPERTIES* printControlProperties)
{
	m_d2d_printcontrol = nullptr;
	ThrowIfFailed(m_d2d_device->CreatePrintControl(m_wic_factory.Get(), docPackageTarget,
					printControlProperties, &m_d2d_printcontrol));
}

void MainPage::DrawPreviewSurface(float width, float height, float scale_in, 
								  D2D1_RECT_F contentBox, uint32 page_num, 
								  IPrintPreviewDxgiPackageTarget* previewTarget)
{
	int dpi = 96;
	int index_page_num = page_num - 1;
	int ren_page_num = index_page_num;

	if (m_ppage_num_list.size() > 0)
		ren_page_num = m_ppage_num_list[page_num - 1] - 1;

	/* This goes on in a background thread.  Hence is non-blocking for UI */
	assert(IsBackgroundThread());

	/* Set up all the DirectX stuff */
	CD3D11_TEXTURE2D_DESC textureDesc(DXGI_FORMAT_B8G8R8A8_UNORM, 
									static_cast<uint32>(ceil(width  * dpi / 96)),
									static_cast<uint32>(ceil(height * dpi / 96)),
									1, 1, D3D11_BIND_RENDER_TARGET | D3D11_BIND_SHADER_RESOURCE);
	ComPtr<ID3D11Texture2D> texture;
	ThrowIfFailed(m_d3d_device->CreateTexture2D(&textureDesc, nullptr, &texture));
	ComPtr<IDXGISurface> dxgi_surface;
	ThrowIfFailed(texture.As<IDXGISurface>(&dxgi_surface));

	// Create a new D2D device context for rendering the preview surface. D2D
	// device contexts are stateful, and hence a unique device context must be
	// used on each thread.
	ComPtr<ID2D1DeviceContext> d2d_context;
	ThrowIfFailed(m_d2d_device->CreateDeviceContext(D2D1_DEVICE_CONTEXT_OPTIONS_NONE,
													&d2d_context));
	// Update DPI for preview surface as well.
	d2d_context->SetDpi(96, 96);

	D2D1_BITMAP_PROPERTIES1 bitmap_properties =
		D2D1::BitmapProperties1(D2D1_BITMAP_OPTIONS_TARGET | D2D1_BITMAP_OPTIONS_CANNOT_DRAW,
		D2D1::PixelFormat(DXGI_FORMAT_B8G8R8A8_UNORM, D2D1_ALPHA_MODE_IGNORE));

	// Create surface bitmap on which page content is drawn.
	ComPtr<ID2D1Bitmap1> d2d_surfacebitmap;
	ThrowIfFailed(d2d_context->CreateBitmapFromDxgiSurface(dxgi_surface.Get(),
									&bitmap_properties, &d2d_surfacebitmap));
	d2d_context->SetTarget(d2d_surfacebitmap.Get());

	/* Figure out all the sizing */
	spatial_info_t spatial_info;
	spatial_info.scale_factor = 1.0;
	spatial_info.size.X = width;
	spatial_info.size.Y = height;
	Point ras_size;
	float scale_factor;

	if (ComputePageSize(spatial_info, ren_page_num, &ras_size, &scale_factor) != S_ISOK)
		return;

	ras_size.X = ceil(ras_size.X);
	ras_size.Y = ceil(ras_size.Y);

	Array<unsigned char>^ bmp_data;
	int code = mu_doc->RenderPageBitmapSync(ren_page_num, (int) ras_size.X, 
		(int)ras_size.Y, scale_factor, true, false, false, { 0, 0 }, 
		{ ras_size.X, ras_size.Y }, &bmp_data);
	if (bmp_data == nullptr)
		return;
	D2D1_SIZE_U bit_map_rect;
	bit_map_rect.width = (UINT32) (ras_size.X);
	bit_map_rect.height = (UINT32) (ras_size.Y);

	D2D1_BITMAP_PROPERTIES1 bitmap_prop =
		D2D1::BitmapProperties1(D2D1_BITMAP_OPTIONS_NONE,
		D2D1::PixelFormat(DXGI_FORMAT_B8G8R8A8_UNORM, D2D1_ALPHA_MODE_IGNORE));

	ID2D1Bitmap1 *bit_map;
	ThrowIfFailed(d2d_context->CreateBitmap(bit_map_rect,  &(bmp_data[0]), 
											(UINT32) (ras_size.X * 4), 
											&bitmap_prop, &bit_map));
	D2D1_SIZE_F size = bit_map->GetSize();

	/* Handle centering */
	float y_offset = 0;
	float x_offset = 0;
	if (m_centerprint) 
	{
		y_offset = (float) ((height - size.height) / 2.0);
		x_offset = (float) ((width - size.width) / 2.0);
	}

	d2d_context->BeginDraw();
	d2d_context->DrawBitmap(bit_map, D2D1::RectF(x_offset, y_offset, 
							size.width + x_offset, size.height + y_offset));
	ThrowIfFailed(d2d_context->EndDraw());
	ThrowIfFailed(previewTarget->DrawPage(page_num, dxgi_surface.Get(), 
											(float) dpi, (float) dpi));
}

HRESULT MainPage::ClosePrintControl()
{
	return (m_d2d_printcontrol == nullptr) ? S_OK : m_d2d_printcontrol->Close();
}

/* To support high resolution printing, we tile renderings at the maxbitmap size
   allowed with DirectX for this particular device.  e.g the low end surface
   will have a smaller maxbitmap size compared to a laptop or desktop. */
void MainPage::PrintPage(uint32 page_num, D2D1_RECT_F image_area, D2D1_SIZE_F page_area, 
						 float device_dpi, IStream* print_ticket) 
{
	int dpi = m_printresolution;
	int index_page_num = page_num - 1;
	int ren_page_num = index_page_num;
	bool tile = false;
	Point tile_count;
	D2D1_SIZE_U bit_map_rect;
	Array<unsigned char>^ bmp_data;

	if (index_page_num == 0)
	{
		this->Dispatcher->RunAsync(CoreDispatcherPriority::Low,
			ref new DispatchedHandler([this]()
		{
			xaml_PrintStack->Visibility = Windows::UI::Xaml::Visibility::Visible;
		}));
	}

	/* Windoze seems to hand me a bogus dpi.  Need to follow up on this */
	device_dpi = 96;

	if (m_ppage_num_list.size() > 0)
		ren_page_num = m_ppage_num_list[page_num - 1] - 1;

	/* This goes on in a background thread.  Hence is non-blocking for UI */
	assert(IsBackgroundThread());

	/* Print command list set up */
	ComPtr<ID2D1DeviceContext> d2d_context;
	ThrowIfFailed(m_d2d_device->CreateDeviceContext(D2D1_DEVICE_CONTEXT_OPTIONS_NONE,
													&d2d_context));

	/* This should let us work in pixel dimensions but after much testing
	   it clearly has some issues.  May investigate this further later. */
	//d2d_context->SetUnitMode(D2D1_UNIT_MODE_PIXELS);
	ComPtr<ID2D1CommandList> clist;
	ThrowIfFailed(d2d_context->CreateCommandList(&clist));
	d2d_context->SetTarget(clist.Get());

	/* Width and height here are at 96 dpi */
	float width = image_area.right - image_area.left;
	float height  = image_area.bottom - image_area.top;

	/*  MuPDF native resolution is 72dpi */
	spatial_info_t spatial_info;
	spatial_info.scale_factor = 1.0;
	spatial_info.size.X = (width / device_dpi) * (m_printresolution);
	spatial_info.size.Y = (height /device_dpi) * (m_printresolution);
	Point ras_size;
	float scale_factor;

	if (ComputePageSize(spatial_info, ren_page_num, &ras_size, &scale_factor) != S_ISOK)
		return;
	ras_size.X = ceil(ras_size.X);
	ras_size.Y = ceil(ras_size.Y);

	/* Determine if we need to do any tiling */
	int tile_size = d2d_context->GetMaximumBitmapSize();
	tile_count.Y = 1;
	if (ras_size.X > tile_size)
	{
		tile = true;
		tile_count.X = (float) ceil((float) ras_size.X / (float) tile_size);
		bit_map_rect.width = (UINT32) (tile_size);
	}
	else
	{
		tile_count.X = 1;
		bit_map_rect.width = (UINT32) (ras_size.X);
	}
	if (ras_size.Y > tile_size)
	{
		tile = true;
		tile_count.Y = (float) ceil((float) ras_size.Y / (float) tile_size);
		bit_map_rect.height = (UINT32) (tile_size);
	}
	else
	{
		tile_count.Y = 1;
		bit_map_rect.height = (UINT32) (ras_size.Y);
	}

	/* Adjust for centering in media page */
	float y_offset = 0;
	float x_offset = 0;
	if (m_centerprint)
	{
		y_offset = (float)round(((page_area.height - (ras_size.Y) * device_dpi / m_printresolution) / 2.0));
		x_offset = (float)round(((page_area.width - (ras_size.X) * device_dpi / m_printresolution) / 2.0));
	}

	D2D1_BITMAP_PROPERTIES1 bitmap_prop =
		D2D1::BitmapProperties1(D2D1_BITMAP_OPTIONS_NONE,
		D2D1::PixelFormat(DXGI_FORMAT_B8G8R8A8_UNORM, D2D1_ALPHA_MODE_IGNORE), 
		(float) m_printresolution, (float) m_printresolution);

	ID2D1Bitmap1 *bit_map = NULL;
	Point top_left, top_left_dip;
	Point bottom_right, bottom_right_dip;

	/* Initialize X location */
	top_left.X = 0;
	bottom_right.X = (float) bit_map_rect.width;

	d2d_context->BeginDraw();
	/* Useful for debugging */
	//d2d_context->Clear(D2D1::ColorF(D2D1::ColorF::Coral));
	int total_tile = (int) (tile_count.X * tile_count.Y);

	for (int x = 0; x < tile_count.X; x++)
	{
		/* Reset Y location */
		top_left.Y = 0;
		bottom_right.Y = (float) bit_map_rect.height;

		for (int y = 0; y < tile_count.Y; y++)
		{
			int code = mu_doc->RenderPageBitmapSync(ren_page_num, (int)bit_map_rect.width,
				(int)bit_map_rect.height, scale_factor, true, false, tile, top_left,
				bottom_right, &bmp_data);
			if (bmp_data == nullptr || code != 0)
				break;

			ThrowIfFailed(d2d_context->CreateBitmap(bit_map_rect, &(bmp_data[0]),
				(UINT32)(bit_map_rect.width * 4), &bitmap_prop, &bit_map));  

			// This is where D2D1_UNIT_MODE_PIXELS fails to work.  Essentially,
			// DirectX ends up clipping based upon the origin still in DIPS 
			// instead of actual pixel positions.  
			top_left_dip.X = (float)((double) top_left.X * (double)device_dpi / (double)m_printresolution + x_offset - 0.5);
			top_left_dip.Y = (float)((double)top_left.Y * (double)device_dpi / (double)m_printresolution + y_offset - 0.5);
			bottom_right_dip.X = (float)((double)bottom_right.X * (double)device_dpi / (double)m_printresolution + x_offset + 0.5);
			bottom_right_dip.Y = (float)((double)bottom_right.Y * (double)device_dpi / (double)m_printresolution + y_offset + 0.5);
			d2d_context->DrawBitmap(bit_map, D2D1::RectF(top_left_dip.X, top_left_dip.Y,
				bottom_right_dip.X, bottom_right_dip.Y));
			bit_map->Release();

			/* Increment Y location */
			top_left.Y += (float) bit_map_rect.height;
			bottom_right.Y += (float) bit_map_rect.height;
			PrintProgressTile(total_tile);
		}
		/* Increment X location */
		top_left.X += (float) bit_map_rect.width;
		bottom_right.X += (float) bit_map_rect.width;
	}
	ThrowIfFailed(d2d_context->EndDraw());
	ThrowIfFailed(clist->Close());
	ThrowIfFailed(m_d2d_printcontrol->AddPage(clist.Get(), page_area, print_ticket));
}

void MainPage::RefreshPreview()
{
	PrintPages *p_struct = (PrintPages*) m_print_struct;
	p_struct->ResetPreview();
}

/* This reference is needed so that we can reset preview when changes occur on options */
void MainPage::SetPrintTarget(void *print_struct)
{
	m_print_struct = print_struct;
}

void MainPage::PrintProgress(PrintTask^ sender, PrintTaskProgressingEventArgs^ args)
{
	assert(IsBackgroundThread());
	this->m_curr_print_count = args->DocumentPageCount;

	/* Update the progress bar if it is still active */
	this->Dispatcher->RunAsync(CoreDispatcherPriority::Low,
		ref new DispatchedHandler([this]()
	{
		if (this->xaml_PrintStack->Visibility != Windows::UI::Xaml::Visibility::Collapsed)
		{
			xaml_PrintProgress->Value =
				100.0 * (double)m_curr_print_count / (double)GetPrintPageCount();
		}
	}));
}

void MainPage::PrintProgressTile(int total_tiles)
{
	assert(IsBackgroundThread());
	double step_size = 100.0 / ((double)GetPrintPageCount() * (double)total_tiles);
	/* Update the progress bar if it is still active.  The tiling of each
	   page can be slow on the surface if the resolution is high, hence
	   the need for this feedback */
	this->Dispatcher->RunAsync(CoreDispatcherPriority::Low,
		ref new DispatchedHandler([this, step_size]()
	{
		if (this->xaml_PrintStack->Visibility != Windows::UI::Xaml::Visibility::Collapsed)
		{
			xaml_PrintProgress->Value += step_size;
		}
	}));
}

void MainPage::PrintCompleted(PrintTask^ sender, PrintTaskCompletedEventArgs^ args)
{
	assert(IsBackgroundThread());
	m_print_active = PRINT_INACTIVE;
	this->Dispatcher->RunAsync(CoreDispatcherPriority::Low,
		ref new DispatchedHandler([this]()
	{
		xaml_PrintStack->Visibility = Windows::UI::Xaml::Visibility::Collapsed;
		xaml_PrintProgress->Value = 0;
	}));
}

void mupdf_cpp::MainPage::HideProgress(Platform::Object^ sender, Windows::UI::Xaml::RoutedEventArgs^ e)
{
	xaml_PrintStack->Visibility = Windows::UI::Xaml::Visibility::Collapsed;
}
