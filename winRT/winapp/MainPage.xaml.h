//
// MainPage.xaml.h
// Declaration of the MainPage class.
//

#pragma once

#include "MainPage.g.h"
#include "fitz.h"
#include "fitz-internal.h"
#include "muxps.h"
#include "mupdf.h"
#include "ppl.h"
#include "Binding.h"

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
using namespace winapp::DataBinding;

typedef struct SearchResult_s
{
    int box_count;
    int page_num;
} SearchResult_t;

typedef struct RectSize_s
{
    float width;
    float height;
} RectSize;

namespace winapp
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
        bool m_file_open;
        int  m_currpage;
        int  m_searchpage;
        int  m_num_pages;
        int  m_slider_min;
        int  m_slider_max;
        bool m_init_done;
        bool m_first_time;
        bool m_flip_from_search;
        Point m_display_size;
        cancellation_token_source m_searchcts;
        long long m_memory_use;
        double m_curr_zoom;
        Point m_zoom_size;
        fz_document *m_doc; 
        Point m_touchpoint;
        Point m_canvas_translate;
        Windows::UI::Input::ManipulationDelta m_changes;
        ImageBrush^ m_renderedImage;
        ImageBrush^ m_blankPage;
        Canvas^ m_renderedCanvas;
        ImageBrush^ m_zoomedImage;
        SolidColorBrush^ m_color_brush; 
        bool m_zoom_mode;
        bool m_zoom_handled;
        bool m_insearch;
        bool m_sliderchange;
        bool m_update_flip;
		void Picker(Platform::Object^ sender, Windows::UI::Xaml::RoutedEventArgs^ e);
        void Searcher(Platform::Object^ sender, Windows::UI::Xaml::RoutedEventArgs^ e);
        void OpenDocument(StorageFile^ file);
        void RenderPage(fz_document *doc, fz_page *page, int *width, int *height, double scale);
        void RenderRange(int curr_page, int *height, int *width);
        void CleanUp();
        void AddPage(int page_num);
        void ReplacePage(int page_num);
        void AddBlankPage(int page_num);
        void CreateBlank(int width, int height);
        void HandleFileNotFoundException(Platform::COMException^ e); 
        void NotifyUserFileNotExist();
        void SetupZoomCanvas();
        RectSize currPageSize(int page);
        void Prepare_bmp(int width, int height, DataWriter ^dw);
        void PixToMemStream(fz_pixmap *pix, DataWriter ^dw, Platform::Array<unsigned char> ^arr);
        void Slider_ValueChanged(Platform::Object^ sender, Windows::UI::Xaml::Controls::Primitives::RangeBaseValueChangedEventArgs^ e);
        void Slider_Released(Platform::Object^ sender, Windows::UI::Xaml::Controls::Primitives::RangeBaseValueChangedEventArgs^ e);
        void FlipView_SelectionChanged(Object^ sender, SelectionChangedEventArgs^ e);
        void FlipView_Double(Object^ sender, DoubleTappedRoutedEventArgs^ e);
        void Canvas_ManipulationDelta(Object^ sender, ManipulationDeltaRoutedEventArgs^ e);
        void Canvas_ManipulationStarted(Object^ sender, ManipulationStartedRoutedEventArgs^ e);
        void Canvas_ManipulationStarting(Object^ sender, ManipulationStartingRoutedEventArgs^ e);  
        void Canvas_Double(Object^ sender, DoubleTappedRoutedEventArgs^ e);
        void SearchNext(Platform::Object^ sender, Windows::UI::Xaml::RoutedEventArgs^ e);
        void SearchPrev(Platform::Object^ sender, Windows::UI::Xaml::RoutedEventArgs^ e);
        void ResetSearch(void);  
        void CancelSearch(Platform::Object^ sender, Windows::UI::Xaml::RoutedEventArgs^ e);
        void SearchInDirection(int dir, String^ textToFind);    
        void ShowSearchResults(SearchResult_t result);
        void GridSizeChanged();
        void UpDatePageSizes();
    };
}
