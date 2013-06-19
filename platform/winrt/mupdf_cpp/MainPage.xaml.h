//
// MainPage.xaml.h
// Declaration of the MainPage class.
//

#pragma once

#include "MainPage.g.h"
#include "ppl.h"
#include "ppltasks.h"
#include <collection.h>
#include <algorithm>
#include <assert.h>
#include "DocumentPage.h"
#include "status.h"

using namespace Platform;
using namespace Concurrency;
using namespace Windows::Storage;
using namespace Windows::UI::Xaml;
using namespace Windows::UI::Xaml::Media::Imaging;
using namespace Windows::Storage::Streams;
using namespace Windows::Foundation;
using namespace Windows::UI::Xaml::Controls;
using namespace Windows::UI::Xaml::Media;
using namespace Windows::UI::Xaml::Input;
using namespace Windows::UI::Xaml::Shapes;
using namespace Windows::Foundation::Collections;
using namespace Platform::Collections;
using namespace Windows::UI::ViewManagement;
using namespace Windows::UI::Popups;
using namespace Windows::UI::Xaml::Navigation;
using namespace Windows::ApplicationModel;
using namespace mupdfwinrt;

typedef enum
{
	StatusMessage,
	ErrorMessage
} NotifyType_t;

typedef enum {
	REN_AVAILABLE = 0,
	REN_THUMBS,
	REN_UPDATE_THUMB_CANVAS,
	REN_PAGE			/* Used to ignore value when source based setting */
} RenderingStatus_t;

typedef struct spatial_info_s
{
	Point size;
	double scale_factor;
} spatial_info_t;

namespace mupdf_cpp
{
	/// <summary>
	/// An empty page that can be used on its own or navigated to within a Frame.
	/// </summary>
	public ref class MainPage sealed
	{
	public:
		MainPage();

		property Windows::ApplicationModel::Activation::ProtocolActivatedEventArgs^ ProtocolEvent
		{
			Windows::ApplicationModel::Activation::ProtocolActivatedEventArgs^ get() { return _protocolEventArgs; }
			void set(Windows::ApplicationModel::Activation::ProtocolActivatedEventArgs^ value) { _protocolEventArgs = value; }
		}

		property Windows::ApplicationModel::Activation::FileActivatedEventArgs^ FileEvent
		{
			Windows::ApplicationModel::Activation::FileActivatedEventArgs^ get() { return _fileEventArgs; }
			void set(Windows::ApplicationModel::Activation::FileActivatedEventArgs^ value) { _fileEventArgs = value; }
		}

	protected:
		virtual void OnNavigatedTo(Windows::UI::Xaml::Navigation::NavigationEventArgs^ e) override;
		virtual void OnKeyDown(Windows::UI::Xaml::Input::KeyRoutedEventArgs^ e) override;

	private:
		Windows::Foundation::EventRegistrationToken _pageLoadedHandlerToken;
		Vector<DocumentPage^>^ m_docPages;
		Vector<DocumentPage^>^ m_thumbnails;
		Vector<IVector<RectList^>^>^ m_page_link_list;
		Vector<int>^ m_linkset;
		Vector<RectList^>^ m_text_list;
		int m_rectlist_page;
		mudocument^ mu_doc;
		bool m_file_open;
		int  m_currpage;
		int  m_searchpage;
		int  m_num_pages;
		int  m_slider_min;
		int  m_slider_max;
		bool m_init_done;
		bool m_flip_from_searchlink;
		bool m_links_on;
		int m_search_rect_count;
		cancellation_token_source m_searchcts;
		bool m_page_update;
		long long m_memory_use;
		WriteableBitmap ^m_BlankBmp;
		String^ m_textcolor;
		String^ m_linkcolor;
		FlipView^ m_curr_flipView;
		RenderingStatus_t m_ren_status;
		cancellation_token_source m_ThumbCancel;
		bool m_insearch;		/* Used for UI display */
		bool m_search_active;  /* Used to avoid multiple UI clicks */
		bool m_sliderchange;
		bool m_update_flip;
		double m_Progress;

		void ReplaceImage(int page_num, InMemoryRandomAccessStream^ ras, Point ras_size);
		void Picker(Platform::Object^ sender, Windows::UI::Xaml::RoutedEventArgs^ e);
		void Searcher(Platform::Object^ sender, Windows::UI::Xaml::RoutedEventArgs^ e);
		void OpenDocumentPrep(StorageFile^ file);
		void OpenDocument(StorageFile^ file);
		void InitialRender();
		void RenderRange(int curr_page);
		void CleanUp();
		void UpdatePage(int page_num, InMemoryRandomAccessStream^ ras, Point ras_size, Page_Content_t content_type);
		void CreateBlank(int width, int height);
		void HandleFileNotFoundException(Platform::COMException^ e);
		void NotifyUserFileNotExist();
		void SetFlipView();
		void Slider_ValueChanged(Platform::Object^ sender, Windows::UI::Xaml::Controls::Primitives::RangeBaseValueChangedEventArgs^ e);
		void Slider_Released(Platform::Object^ sender, Windows::UI::Xaml::Controls::Primitives::RangeBaseValueChangedEventArgs^ e);
		void FlipView_SelectionChanged(Object^ sender, SelectionChangedEventArgs^ e);
		void SearchNext(Platform::Object^ sender, Windows::UI::Xaml::RoutedEventArgs^ e);
		void SearchPrev(Platform::Object^ sender, Windows::UI::Xaml::RoutedEventArgs^ e);
		void CancelSearch(Platform::Object^ sender, Windows::UI::Xaml::RoutedEventArgs^ e);
		void SearchInDirection(int dir, String^ textToFind);
		void ShowSearchResults(int page_num, int box_count);
		void ClearTextSearch();
		void AddTextCanvas();
		void GridSizeChanged();
		void UpDatePageSizes();
		void ShowThumbnail();
		void Canvas_ManipulationCompleted(Platform::Object^ sender, Windows::UI::Xaml::Input::ManipulationCompletedRoutedEventArgs^ e);
		void AddThumbNail(int page_num, FlipView^ flip_view);
		spatial_info_t InitSpatial(double scale);
		void RenderThumbs();
		void SetThumb(int page_num, bool replace);
		void ReleasePages(int old_page, int new_page);
		void Linker(Platform::Object^ sender, Windows::UI::Xaml::RoutedEventArgs^ e);
		void AddLinkCanvas();
		void ClearLinks();
		void InvalidateLinks();
		void ContentDisplay(Platform::Object^ sender, Windows::UI::Xaml::RoutedEventArgs^ e);
		void ListView_Single_Tap(Platform::Object^ sender, Windows::UI::Xaml::Input::TappedRoutedEventArgs^ e);
		void ContentSelected(Platform::Object^ sender, Windows::UI::Xaml::Controls::ItemClickEventArgs^ e);
		void ContentChanged(Platform::Object^ sender, Windows::UI::Xaml::Controls::SelectionChangedEventArgs^ e);
		void Reflower(Platform::Object^ sender, Windows::UI::Xaml::RoutedEventArgs^ e);
		void topAppBar_Loaded(Platform::Object^ sender, Windows::UI::Xaml::RoutedEventArgs^ e);
		void UpdateAppBarButtonViewState();
		bool EnsureUnsnapped();
		void NotifyUser(String^ strMessage, NotifyType_t type);
		void ExitInvokedHandler(Windows::UI::Popups::IUICommand^ command);
		void OKInvokedHandler(Windows::UI::Popups::IUICommand^ command);
		Point ComputePageSize(spatial_info_t spatial_info, int page_num);
		void ScrollChanged(Platform::Object^ sender, Windows::UI::Xaml::Controls::ScrollViewerViewChangedEventArgs^ e);
		void LinkTapped(Platform::Object^ sender, Windows::UI::Xaml::Input::TappedRoutedEventArgs^ e);
		void SearchProgress(IAsyncOperationWithProgress<int, double>^ operation, double status);
		void PasswordOK(Platform::Object^ sender, Windows::UI::Xaml::RoutedEventArgs^ e);
		void App_Suspending(Object^ sender, SuspendingEventArgs^ e);
		void ZoomInPress(Platform::Object^ sender, Windows::UI::Xaml::RoutedEventArgs^ e);
		void ZoomOutPress(Platform::Object^ sender, Windows::UI::Xaml::RoutedEventArgs^ e);
		void NonTouchZoom(int zoom);
		void ShowSearchBox();
		bool IsNotStandardView();
		void Page_Loaded(Object^ sender, RoutedEventArgs^ e);
		Windows::ApplicationModel::Activation::ProtocolActivatedEventArgs^ _protocolEventArgs;
		Windows::ApplicationModel::Activation::FileActivatedEventArgs^ _fileEventArgs;
	};
}
