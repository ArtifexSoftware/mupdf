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
#include "LVContents.h"
#include "mudocument.h"
#include "DocumentPage.h"

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
using namespace ListViewContents;
using namespace Windows::UI::ViewManagement;
using namespace Windows::UI::Popups;
using namespace Windows::UI::Xaml::Navigation;
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
    REN_PAGE            /* Used to ignore value when source based setting */  
} RenderingStatus_t;

typedef struct SearchResult_s
{
    int box_count;
    int page_num;
} SearchResult_t;

typedef struct spatial_info_s
{
    Point size;   
    double scale_factor;
} spatial_info_t;

typedef struct thumbs_s
{
    Array<InMemoryRandomAccessStream^>^ raster;  
    Array<double>^ scale;
    Array<Point>^  size;
} thumbs_t;

typedef struct content_s
{
    int num;
    Vector<int>^  page;
    Vector<String^>^ string_orig;
    Vector<String^>^ string_margin;
} content_t;

namespace mupdf_cpp
{
	/// <summary>
	/// An empty page that can be used on its own or navigated to within a Frame.
	/// </summary>
	public ref class MainPage sealed
	{
	public:
		MainPage();

	protected:
		virtual void OnNavigatedTo(Windows::UI::Xaml::Navigation::NavigationEventArgs^ e) override;

    /* added */
    private:
        Vector<DocumentPage^>^ m_docPages;
        mudocument^ mu_doc; 
        LVContents temp;
        bool m_file_open;
        int  m_currpage;
        int  m_searchpage;
        int  m_num_pages;
        int  m_slider_min;
        int  m_slider_max;
        bool m_init_done;
        bool m_first_time;
        bool m_flip_from_searchlink;
        bool m_links_on;
        int m_search_rect_count;
        Point m_display_size;
        cancellation_token_source m_searchcts;
        cancellation_token_source m_thumbcts;
        bool m_page_update;
        long long m_memory_use;
        double m_curr_zoom;
        Point m_zoom_size;
        Point m_touchpoint;
        Point m_canvas_translate;
        Windows::UI::Input::ManipulationDelta m_changes;
        ImageBrush^ m_renderedImage;
        ImageBrush^ m_blankPage;
        WriteableBitmap ^m_BlankBmp;
        Canvas^ m_renderedCanvas;
        ImageBrush^ m_zoomedImage;
        SolidColorBrush^ m_textcolor_brush; 
        SolidColorBrush^ m_linkcolor_brush; 
        FlipView^ m_curr_flipView;
        thumbs_t m_thumbnails;
        RenderingStatus_t m_ren_status;
        int m_thumb_page_start;
        int m_thumb_page_stop;
        cancellation_token_source m_ThumbCancel;
        content_t m_content;
        TextBlock^ m_StatusBlock;
        bool m_zoom_mode;
        bool m_from_doubleflip;
        bool m_scaling_occured;
        bool m_insearch;  /* Used for UI display */
        bool m_search_active;  /* Used to avoid multiple UI clicks */
        bool m_sliderchange;
        bool m_update_flip;
		void Picker(Platform::Object^ sender, Windows::UI::Xaml::RoutedEventArgs^ e);
        void Searcher(Platform::Object^ sender, Windows::UI::Xaml::RoutedEventArgs^ e);
        void OpenDocumentPrep(StorageFile^ file);
        void OpenDocument(StorageFile^ file);
        task<int> RenderRange(int curr_page);
        void CleanUp();
        void UpdatePage(int page_num, InMemoryRandomAccessStream^ ras, Point ras_size, Page_Content_t content_type);
        void CreateBlank(int width, int height);
        void HandleFileNotFoundException(Platform::COMException^ e); 
        void NotifyUserFileNotExist();
        void SetFlipView();
        Point currPageSize(int page);
        void Slider_ValueChanged(Platform::Object^ sender, Windows::UI::Xaml::Controls::Primitives::RangeBaseValueChangedEventArgs^ e);
        void Slider_Released(Platform::Object^ sender, Windows::UI::Xaml::Controls::Primitives::RangeBaseValueChangedEventArgs^ e);
        void FlipView_SelectionChanged(Object^ sender, SelectionChangedEventArgs^ e);
        void SearchNext(Platform::Object^ sender, Windows::UI::Xaml::RoutedEventArgs^ e);
        void SearchPrev(Platform::Object^ sender, Windows::UI::Xaml::RoutedEventArgs^ e);
        void ResetSearch(void);  
        void CancelSearch(Platform::Object^ sender, Windows::UI::Xaml::RoutedEventArgs^ e);
        void SearchInDirection(int dir, String^ textToFind);    
        void ShowSearchResults(SearchResult_t result);
        void GridSizeChanged();
        void UpDatePageSizes();
        void ShowThumbnail();
        void Canvas_ManipulationCompleted(Platform::Object^ sender, Windows::UI::Xaml::Input::ManipulationCompletedRoutedEventArgs^ e);
        void AddThumbNail(int page_num, FlipView^ flip_view);
        spatial_info_t InitSpatial(double scale);
        void InitThumbnails();
        void RenderThumbs();
        void SetThumb(int page_num, bool replace);
        void ReleasePages(int old_page, int new_page);
        void Linker(Platform::Object^ sender, Windows::UI::Xaml::RoutedEventArgs^ e);
        void AddLinkCanvas();
        void Canvas_Single_Tap(Platform::Object^ sender, Windows::UI::Xaml::Input::TappedRoutedEventArgs^ e);
        bool CheckRect(Rectangle^ curr_rect, Point pt);
        int JumpToLink(int index);
        void ClearLinksCanvas();
        void ContentDisplay(Platform::Object^ sender, Windows::UI::Xaml::RoutedEventArgs^ e);
        void FlattenOutline(fz_outline *outline, int level);
        void ListView_Single_Tap(Platform::Object^ sender, Windows::UI::Xaml::Input::TappedRoutedEventArgs^ e);
        void ContentSelected(Platform::Object^ sender, Windows::UI::Xaml::Controls::ItemClickEventArgs^ e);
        void ContentChanged(Platform::Object^ sender, Windows::UI::Xaml::Controls::SelectionChangedEventArgs^ e);
        void Reflower(Platform::Object^ sender, Windows::UI::Xaml::RoutedEventArgs^ e);
        void WebViewDelta(Platform::Object^ sender, Windows::UI::Xaml::Input::ManipulationDeltaRoutedEventArgs^ e);
        void WebViewStarting(Platform::Object^ sender, Windows::UI::Xaml::Input::ManipulationStartingRoutedEventArgs^ e);
        void WebViewCompleted(Platform::Object^ sender, Windows::UI::Xaml::Input::ManipulationCompletedRoutedEventArgs^ e);
        void TempViewStarting(Platform::Object^ sender, Windows::UI::Xaml::Input::ManipulationStartingRoutedEventArgs^ e);
        void RichGridSizeChanged(Platform::Object^ sender, Windows::UI::Xaml::SizeChangedEventArgs^ e);
        void RichGridManipulationStarting(Platform::Object^ sender, Windows::UI::Xaml::Input::ManipulationStartingRoutedEventArgs^ e);
        void RichGridManipulationDelta(Platform::Object^ sender, Windows::UI::Xaml::Input::ManipulationDeltaRoutedEventArgs^ e);
        void RichGridManipulationStarted(Platform::Object^ sender, Windows::UI::Xaml::Input::ManipulationStartedRoutedEventArgs^ e);
        void RichGridManipulationCompleted(Platform::Object^ sender, Windows::UI::Xaml::Input::ManipulationCompletedRoutedEventArgs^ e);
        void topAppBar_Loaded(Platform::Object^ sender, Windows::UI::Xaml::RoutedEventArgs^ e);
        void UpdateAppBarButtonViewState();
        bool EnsureUnsnapped();
        void NotifyUser(String^ strMessage, NotifyType_t type);
        void ExitInvokedHandler(Windows::UI::Popups::IUICommand^ command);
        void OKInvokedHandler(Windows::UI::Popups::IUICommand^ command);
        Point ComputePageSize(spatial_info_t spatial_info, int page_num);
        void ScrollChanged(Platform::Object^ sender, Windows::UI::Xaml::Controls::ScrollViewerViewChangedEventArgs^ e);
};
}
