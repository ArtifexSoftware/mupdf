using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Navigation;
using Microsoft.Phone.Controls;
using Microsoft.Phone.Shell;
using Windows.Storage;
using Windows.Storage.Streams;
using Windows.Storage.Pickers;
using Windows.Foundation;
using winphone.Resources;
using System.Windows.Media.Imaging;
using mupdfwinrt;
using System.Threading.Tasks;
using System.Runtime.InteropServices.WindowsRuntime;
using Windows.Phone.Storage.SharedAccess;
using System.IO;
using System.Collections.ObjectModel;
using System.Windows.Media;
using System.Windows.Input;
using Telerik.Windows.Controls.SlideView;
using Telerik.Windows.Controls;

enum AppBar_t
{
	TEXT_SEARCH,
	STANDARD
}

enum NotifyType_t
{
	MESS_STATUS,
	MESS_ERROR
};

enum RenderingStatus_t 
{
	REN_AVAILABLE,
	REN_THUMBS,
	REN_UPDATE_THUMB_CANVAS,
	REN_PAGE			/* Used to ignore value when source based setting */
};

enum status_t 
{
	S_ISOK,
	E_FAILURE,
	E_OUTOFMEM,
	E_NEEDPASSWORD
};

enum view_t
{
	VIEW_WEB,
	VIEW_CONTENT,
	VIEW_PAGE,
	VIEW_PASSWORD,
	VIEW_TEXTSEARCH
};

public enum Page_Content_t
{
	FULL_RESOLUTION = 0,
	THUMBNAIL,
	DUMMY,
	OLD_RESOLUTION,
	NOTSET
};

public struct spatial_info_t
{
	public Windows.Foundation.Point size;
	public double scale_factor;
} ;

/* C# has no defines.... */
static class Constants {
	public const int LOOK_AHEAD = 2;  /* A +/- count on the pages to pre-render */
	public const int THUMB_PREADD = 10;
	public const double  MIN_SCALE = 0.5;
	public const double SCALE_THUMB = 0.05;
	public const int BLANK_WIDTH = 17;
	public const int BLANK_HEIGHT = 22;
	public const double KEYBOARD_ZOOM_STEP = 0.25;
	public const int ZOOM_MAX = 4;
	public const double ZOOM_MIN = 0.25;
	public const int KEY_PLUS = 0xbb;
	public const int KEY_MINUS = 0xbd;
	public const int ZOOM_IN = 0;
	public const int ZOOM_OUT = 1;
	public const double screenScale = 1;
	public const int HEADER_SIZE = 54;
	public const int SEARCH_FORWARD = 1;
	public const int SEARCH_BACKWARD = -1;
	public const int TEXT_NOT_FOUND = -1;
	public const int MAX_FILMSTRIP_THUMB = 2;
}

namespace winphone
{
	public partial class MainPage : PhoneApplicationPage
	{
		public Pages m_docPages;
		List<DocumentPage> m_thumbnails;
		List<List<RectList>> m_page_link_list;
		int m_contents_size;
		int m_content_item;
		List<bool> m_linkset;
		List<RectList> m_text_list;
		private int m_rectlist_page;
		private List<ContentEntry> m_content_list; 
		mudocument mu_doc;
		private bool m_file_open;
		private int  m_currpage;
		private int  m_searchpage;
		private int  m_num_pages;
		private int  m_slider_min;
		private int  m_slider_max;
		private bool m_init_done;
		private bool m_flip_from_searchlink;
		private bool m_links_on;
		private int m_search_rect_count;
		private bool m_page_update;
		WriteableBitmap m_BlankBmp;
		String m_textcolor;
		String m_linkcolor;
		RenderingStatus_t m_ren_status;
		private bool m_insearch;		/* Used for UI display */
		private bool m_search_active;  /* Used to avoid multiple UI clicks */
		private bool m_sliderchange;
		private double m_Progress;
		int m_width;
		int m_height;
		private bool m_handlingzoom;
		private double m_panX;
		private double m_panY;
		private bool m_have_thumbs;

		// Constructor
		public MainPage()
		{
			InitializeComponent();
			this.Loaded += Page_Loaded;

			m_textcolor="#402572AC";
			m_linkcolor="#40AC7225";
			xaml_Pages.ShowOverlayContent();
			m_docPages = new Pages();
			m_thumbnails = new List<DocumentPage>();
			m_page_link_list = new List<List<RectList>>();
			m_text_list = new List<RectList>();
			m_content_list = new List<ContentEntry>();
			m_linkset = new List<bool>();
			m_contents_size = -1;  /* Not yet computed */
			m_content_item = -1;
			SetView(view_t.VIEW_PAGE);
			m_handlingzoom = false;
			CleanUp();
			InitAppBar();
		}

		private void InitAppBar()
		{
			ApplicationBar = new ApplicationBar();
			ApplicationBar.Mode = ApplicationBarMode.Default;
			ApplicationBar.Opacity = 1.0;
			ApplicationBar.IsVisible = true;
			ApplicationBar.IsMenuEnabled = true;

			ApplicationBarIconButton SearchButton = new ApplicationBarIconButton();
			SearchButton.IconUri = new Uri("/Assets/search.png", UriKind.Relative);
			SearchButton.Text = "Search";
			SearchButton.Click += Search_Click;
			ApplicationBar.Buttons.Add(SearchButton);

			ApplicationBarIconButton LinksButton = new ApplicationBarIconButton();
			LinksButton.IconUri = new Uri("/Assets/links.png", UriKind.Relative);
			LinksButton.Text = "Show Links";
			LinksButton.Click += Links_Click;
			ApplicationBar.Buttons.Add(LinksButton);

			ApplicationBarIconButton ContentsButton = new ApplicationBarIconButton();
			ContentsButton.IconUri = new Uri("/Assets/content.png", UriKind.Relative);
			ContentsButton.Text = "Contents";
			ContentsButton.Click += Content_Click;
			ApplicationBar.Buttons.Add(ContentsButton);

			ApplicationBarIconButton OpenButton = new ApplicationBarIconButton();
			OpenButton.IconUri = new Uri("/Assets/open.png", UriKind.Relative);
			OpenButton.Text = "Open";
			OpenButton.Click += Open_Click;
			ApplicationBar.Buttons.Add(OpenButton);

			ApplicationBarMenuItem ReflowItem = new ApplicationBarMenuItem();
			ReflowItem.Text = "Show Page as HTML";
			ReflowItem.Click += Reflow_Click;
			ApplicationBar.MenuItems.Add(ReflowItem);
		}

		private void SetAppBar(AppBar_t type)
		{
			if (type == AppBar_t.STANDARD)
			{
				ApplicationBarIconButton btn1 = (ApplicationBarIconButton)ApplicationBar.Buttons[1];
				btn1.IconUri = new Uri("/Assets/links.png", UriKind.Relative);
				btn1.Text = "Show Links";
				btn1.Click -= BackSearch;
				btn1.Click += Links_Click;

				ApplicationBarIconButton btn2 = (ApplicationBarIconButton)ApplicationBar.Buttons[2];
				btn2.IconUri = new Uri("/Assets/content.png", UriKind.Relative);
				btn2.Text = "Contents";
				btn2.Click -= ForwardSearch;
				btn2.Click += Content_Click;

				ApplicationBarIconButton OpenButton = new ApplicationBarIconButton();
				OpenButton.IconUri = new Uri("/Assets/open.png", UriKind.Relative);
				OpenButton.Text = "Open";
				OpenButton.Click += Open_Click;
				ApplicationBar.Buttons.Add(OpenButton);

				ApplicationBarMenuItem ReflowItem = new ApplicationBarMenuItem();
				ReflowItem.Text = "Show Page as HTML";
				ReflowItem.Click += Reflow_Click;
				ApplicationBar.MenuItems.Add(ReflowItem);
			}
			else
			{
				/* Keep button 0 (search button) swap button 1 and 2 disable rest */
				ApplicationBarIconButton btn1 = (ApplicationBarIconButton)ApplicationBar.Buttons[1];
				btn1.IconUri = new Uri("/Assets/back.png", UriKind.Relative);
				btn1.Text = "Back";
				btn1.Click -= Links_Click;
				btn1.Click += BackSearch;

				ApplicationBarIconButton btn2 = (ApplicationBarIconButton)ApplicationBar.Buttons[2];
				btn2.IconUri = new Uri("/Assets/next.png", UriKind.Relative);
				btn2.Text = "Forward";
				btn2.Click -= Content_Click;
				btn2.Click += ForwardSearch;

				ApplicationBar.Buttons.RemoveAt(3);
				ApplicationBar.MenuItems.RemoveAt(0);
			}
		}

		private void SetView(view_t newview)
		{
			switch (newview)
			{
				case view_t.VIEW_WEB:
					this.xaml_PageView.Visibility = Visibility.Collapsed;
					this.xaml_ContentView.Visibility = Visibility.Collapsed;
					this.xaml_PasswordView.Visibility = Visibility.Collapsed;
					this.xaml_TextSearchView.Visibility = Visibility.Collapsed;
					this.xaml_WebView.Visibility = Visibility.Visible;
					break;

				case view_t.VIEW_PAGE:
					this.xaml_WebView.Visibility = Visibility.Collapsed;
					this.xaml_ContentView.Visibility = Visibility.Collapsed;
					this.xaml_PasswordView.Visibility = Visibility.Collapsed;
					this.xaml_TextSearchView.Visibility = Visibility.Collapsed;
					this.xaml_PageView.Visibility = Visibility.Visible;
					break;

				case view_t.VIEW_CONTENT:
					this.xaml_PageView.Visibility = Visibility.Collapsed;
					this.xaml_WebView.Visibility = Visibility.Collapsed;
					this.xaml_PasswordView.Visibility = Visibility.Collapsed;
					this.xaml_TextSearchView.Visibility = Visibility.Collapsed;
					this.xaml_ContentView.Visibility = Visibility.Visible;
					break;

				case view_t.VIEW_PASSWORD:
					this.xaml_PageView.Visibility = Visibility.Collapsed;
					this.xaml_WebView.Visibility = Visibility.Collapsed;
					this.xaml_ContentView.Visibility = Visibility.Collapsed;
					this.xaml_TextSearchView.Visibility = Visibility.Collapsed;
					this.xaml_PasswordView.Visibility = Visibility.Visible;
					break;

				case view_t.VIEW_TEXTSEARCH:
					//this.xaml_PageView.Visibility = Visibility.Collapsed;
					this.xaml_WebView.Visibility = Visibility.Collapsed;
					this.xaml_ContentView.Visibility = Visibility.Collapsed;
					this.xaml_PasswordView.Visibility = Visibility.Collapsed;
					this.xaml_TextSearchView.Visibility = Visibility.Visible;
					break;
			}
		}

		void Page_Loaded(object sender, RoutedEventArgs e)
		{
			if (xaml_PageView.Visibility == Visibility.Visible)
			{
				m_height = (int)xaml_Pages.ActualHeight;
				m_width = (int)xaml_Pages.ActualWidth;
				(App.Current as App).appHeight = (int)xaml_Pages.ActualHeight;
				(App.Current as App).appWidth = (int)xaml_Pages.ActualWidth;
			}
		}

		private void Prepare_bmp(int width, int height, DataWriter dw, bool clear)
		{
			int row_size = width * 4;
			int bmp_size = row_size * height + 54;

			dw.WriteString("BM");
			dw.ByteOrder = ByteOrder.LittleEndian;
			dw.WriteInt32(bmp_size);
			dw.WriteInt16(0);
			dw.WriteInt16(0);
			dw.WriteInt32(54);
			dw.WriteInt32(40);
			dw.WriteInt32(width);
			dw.WriteInt32(height);
			dw.WriteInt16(1);
			dw.WriteInt16(32);
			dw.WriteInt32(0);
			dw.WriteInt32(row_size * height);
			dw.WriteInt32(2835);
			dw.WriteInt32(2835);
			dw.WriteInt32(0);
			dw.WriteInt32(0);

			if (clear)
				for (int k = 0; k < width * height * 4; k++)
					dw.WriteByte(255);
		}

		private async Task RenderThumb(double zoom, int page_num)
		{
			spatial_info_t spatial_info = InitSpatial(zoom);
			Windows.Foundation.Point ras_size = ComputePageSize(spatial_info, page_num);
			IBuffer buffer = new Windows.Storage.Streams.Buffer((uint)(ras_size.X) * (uint)(ras_size.Y) * 4 + 54);
			buffer.Length = (uint)(ras_size.X) * (uint)(ras_size.Y) * 4 + 54;
			int canvas_Y = -(int) ((double) this.m_height/2.0);
			int canvas_X = -(int) ((double) this.m_width/2.0);
	
			/* Handle header here */
			var buff_array = buffer.ToArray();
			var mem_stream = new MemoryStream(buff_array, true);
			var out_stream = mem_stream.AsOutputStream();
			var dw = new DataWriter(out_stream);

			int code = await mu_doc.RenderPageAsync(page_num, (int)(ras_size.X),
										  (int)(ras_size.Y), true, dw,
										  Constants.HEADER_SIZE);

			WriteableBitmap bmp = new WriteableBitmap((int)ras_size.X,
													  (int)ras_size.Y);
			bmp.SetSource(mem_stream);

			var mat = new Matrix();
			mat.OffsetX = 0;
			mat.OffsetY = 0;
			mat.M11 = 1.0 / zoom;
			mat.M22 = 1.0 / zoom;
			m_thumbnails[page_num].Image = bmp;
			m_thumbnails[page_num].Zoom = zoom;
			m_thumbnails[page_num].Height = (int)ras_size.Y;
			m_thumbnails[page_num].Width = (int)ras_size.X;
			m_thumbnails[page_num].Content = Page_Content_t.THUMBNAIL;
		}


		private async Task<status_t> RenderPage(double zoom, int page_num, double can_offsetX,
										double can_offsetY)
		{
			spatial_info_t spatial_info = InitSpatial(zoom);
			Windows.Foundation.Point ras_size = ComputePageSize(spatial_info, page_num);
			IBuffer buffer = new Windows.Storage.Streams.Buffer((uint)(ras_size.X) * (uint)(ras_size.Y) * 4 + 54);
			buffer.Length = (uint)(ras_size.X) * (uint)(ras_size.Y) * 4 + 54;
			int canvas_Y = -(int) ((double) this.m_height/2.0);
			int canvas_X = -(int) ((double) this.m_width/2.0);
	
			/* Handle header here */
			var buff_array = buffer.ToArray();
			var mem_stream = new MemoryStream(buff_array, true);
			var out_stream = mem_stream.AsOutputStream();
			var dw = new DataWriter(out_stream);

			int code = await mu_doc.RenderPageAsync(page_num, (int)(ras_size.X),
										  (int)(ras_size.Y), true, dw,
										  Constants.HEADER_SIZE);

			WriteableBitmap bmp = new WriteableBitmap((int)ras_size.X,
													  (int)ras_size.Y);
			bmp.SetSource(mem_stream);

			m_docPages[page_num].Image = bmp;
			m_docPages[page_num].Zoom = zoom;
			m_docPages[page_num].Height = (int)ras_size.Y;
			m_docPages[page_num].Width = (int)ras_size.X;
		
			m_docPages[page_num].Content = Page_Content_t.FULL_RESOLUTION;
			m_docPages[page_num].PageRefresh();
			return (status_t) code;
		}

		private async Task<status_t> RenderRange(int curr_page)
		{
			/* Render +/- the look ahead from where we are if blank page is present */
			spatial_info_t spatial_info = InitSpatial(1);
			int range = Constants.LOOK_AHEAD;
			status_t code = status_t.S_ISOK;

			for (int k = curr_page - range;
					k <= curr_page + range; k++)
			{
				if (k >= 0 && k < m_num_pages)
				{
					/* Check if page is already rendered */
					var doc = m_docPages[k];
					if (doc.Content != Page_Content_t.FULL_RESOLUTION)
					{
						code = await RenderPage(1.0, k, 0, 0);
					}
				}
				if (code != status_t.S_ISOK)
				{
					break;
				}
			}
			return code;
		}

		/* Return this page from a full res image to the thumb image or only set
	   to thumb if it has not already been set */
		private void SetThumb(int page_num)
		{
			var doc = m_docPages[page_num];
			if (doc.Content == Page_Content_t.THUMBNAIL) return;
			m_docPages[page_num] = m_thumbnails[page_num];
		}

		private void SetBlank(int page_num)
		{
			var doc = m_docPages[page_num];
			if (doc.Content == Page_Content_t.DUMMY) return;
			var temp = new DocumentPage(Constants.BLANK_HEIGHT,
					Constants.BLANK_WIDTH, (float)1.0, m_BlankBmp, null, null,
					Page_Content_t.DUMMY, page_num);
			m_docPages[page_num] = temp;
		}

		private void ReleasePages(int old_page, int new_page)
		{
			if (old_page == new_page) return;
			/* To keep from having memory issue reset the page back to
				the thumb if we are done rendering the thumbnails or a blank 
				page */
			for (int k = old_page - Constants.LOOK_AHEAD; 
				k <= old_page + Constants.LOOK_AHEAD; k++)
			{
				if (k < new_page - Constants.LOOK_AHEAD || 
					k > new_page + Constants.LOOK_AHEAD)
				{
					if (k >= 0 && k < m_num_pages)
					{
						if (m_have_thumbs)
						{
							SetThumb(k);
						}
						else
						{
							SetBlank(k);
						}
					}
				}
			}
		}

		private async Task<status_t> GotoPage(int new_page)
		{
			status_t code = await RenderRange(new_page);
			ReleasePages(m_currpage, new_page);
			m_currpage = new_page;
			return code;
		}

		/* Create white image for us to use as place holder in large document 
		   instead of the thumbnail image  */
		private async Task CreateBlank(int width, int height)
		{
			/* Allocate buffer */
			IBuffer buffer = new Windows.Storage.Streams.Buffer((uint) width * (uint) height * 4 + 
																Constants.HEADER_SIZE);
			buffer.Length = (uint)(width * height * 4 + Constants.HEADER_SIZE);
			var buff_array = buffer.ToArray();
			var mem_stream = new MemoryStream(buff_array, true);
			var out_stream = mem_stream.AsOutputStream();
			var dw = new DataWriter(out_stream);
			Prepare_bmp(width, height, dw, true);
			var TResult = await dw.StoreAsync();
			WriteableBitmap bmp = new WriteableBitmap((int) width, (int) height);
			bmp.SetSource(mem_stream);
			m_BlankBmp = bmp;
		}

		/* Clean up everything as we are opening a new document after having another
		   one open */
		private void CleanUp()
		{
			m_init_done = false;
			/* Remove current pages in the flipviews */
			if (m_docPages.Count > 0)
				m_docPages.Clear();
			if (m_thumbnails.Count > 0)
				m_thumbnails.Clear();
			/* With the ref counting this should not leak */
			if (m_page_link_list.Count > 0)
				m_page_link_list.Count();
			if (m_text_list.Count > 0)
				m_text_list.Clear();
			if (m_linkset.Count > 0)
				m_linkset.Clear();

			//if (this.mu_doc != null)
			//	mu_doc.CleanUp();
			
			mu_doc = new mudocument();
			//mu_doc.CleanUp();

			if (mu_doc == null)
				throw new Exception("Document allocation failed!");

			m_currpage = -1;
			m_file_open = false;
			m_slider_min = 0;
			m_slider_max = 0;
			m_insearch = false;
			m_search_active = false;
			m_sliderchange = false;
			m_flip_from_searchlink = false;
			m_num_pages = -1;
			m_search_rect_count = 0;
			m_ren_status = RenderingStatus_t.REN_AVAILABLE;
			m_links_on = false;
			m_rectlist_page = -1;
			m_Progress = 0.0;
		}

		private async void GetFile(string fileID, bool shared)
		{
			string incomingFileName;
			IStorageFile File;
			if (shared)
			{
				/* Copy file locally */
				incomingFileName = SharedStorageAccessManager.GetSharedFileName(fileID);
				File = 
					await SharedStorageAccessManager.CopySharedFileAsync(ApplicationData.Current.LocalFolder,
																		incomingFileName,
																		NameCollisionOption.ReplaceExisting,
																		NavigationContext.QueryString["fileToken"]);
			}
			else
			{
				/* File is already local */
				incomingFileName = fileID;
				StorageFolder local = Windows.Storage.ApplicationData.Current.LocalFolder;
				File = await local.GetFileAsync(incomingFileName);
			}
			string target = ".";
			char[] anyOf = target.ToCharArray();
			var index = incomingFileName.LastIndexOfAny(anyOf);
			string extension = incomingFileName.Substring(index + 1);

			/* Now do our rendering */
			OpenDocumentPrep(File, extension);
		}

		private spatial_info_t InitSpatial(double scale)
		{
			spatial_info_t value = new spatial_info_t();

			value.size.Y = this.m_height;
			value.size.X = this.m_width;
			value.scale_factor = scale;
			return value;
		}

		private Windows.Foundation.Point ComputePageSize(spatial_info_t spatial_info, int page_num)
		{
			Windows.Foundation.Point screenSize;
			Windows.Foundation.Point pageSize = new Windows.Foundation.Point();
			Windows.Foundation.Point size = mu_doc.GetPageSize(page_num);

			screenSize = spatial_info.size;
			screenSize.Y *= Constants.screenScale;
			screenSize.X *= Constants.screenScale;

			double hscale = screenSize.X / size.X;
			double vscale = screenSize.Y / size.Y;
			double scale = Math.Min(hscale, vscale);
			pageSize.X = Math.Ceiling(size.X * scale * spatial_info.scale_factor);
			pageSize.Y = Math.Ceiling(size.Y * scale * spatial_info.scale_factor);

			return pageSize;
		}

		private void OpenDocumentPrep(IStorageFile file, String extension)
		{

#if temp
			if (this.m_num_pages != -1)
			{
				m_init_done = false;

				/* Set the index to the start of the document */
				//this->xaml_vert_flipView->SelectedIndex = 0;
				//this->xaml_horiz_flipView->SelectedIndex = 0;

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
#endif
			OpenDocument(file, extension);
		}

		async private void InitialRender()
		{
			m_num_pages = mu_doc.GetNumPages();

			if ((m_currpage) >= m_num_pages)
			{
				m_currpage = m_num_pages - 1;
			}
			else if (m_currpage < 0)
			{
				m_currpage = 0;
			}

			if (m_BlankBmp == null)
			{
				await CreateBlank(Constants.BLANK_WIDTH, Constants.BLANK_HEIGHT);
			}

			/* Initialize all the flipvew items with blanks and the thumbnails. */
			for (int k = 0; k < m_num_pages; k++)
			{
				/* Blank pages */
				DocumentPage doc_page = new DocumentPage(Constants.BLANK_HEIGHT, 
					Constants.BLANK_WIDTH, (float) 1.0, m_BlankBmp, null, null,
					Page_Content_t.DUMMY, k);
				m_docPages.Add(doc_page);

				DocumentPage thumb_page = new DocumentPage(Constants.BLANK_HEIGHT,
					Constants.BLANK_WIDTH, (float)1.0, m_BlankBmp, null, null,
					Page_Content_t.DUMMY, k);
				m_thumbnails.Add(thumb_page);

				/* Create empty lists for our links and specify that they have
					not been computed for these pages */
				List<RectList> temp_link = new List<RectList>();
				m_page_link_list.Add(temp_link);
				m_linkset.Add(false);
			}

			/* Do the first few pages, then start the thumbs */
			for (int k = 0; k < Constants.LOOK_AHEAD + 3; k++)
			{
				if (m_num_pages > k )
				{
					await RenderPage(1.0, k, 0, 0);
				}
			}

			xaml_Pages.DataContext = m_docPages;
			//this.xaml_Pages.ShowOverlayContent();

			/* All done with initial pages */
			this.m_init_done = true;

			/* Start thumb rendering if we have a small number of pages */
			if (m_num_pages < Constants.MAX_FILMSTRIP_THUMB)
			{
				this.xaml_StackBusy.Visibility = Visibility.Visible;
				this.xaml_Busy.Content = "Rendering Thumbnails...";
				this.xaml_Busy.IsRunning = true;
				await RenderThumbs();
				xaml_PageSlider.Visibility = Visibility.Collapsed;
				m_have_thumbs = true;
			}
			else
			{
				/* Use the slider for fast movement */
				xaml_PageSlider.Maximum = m_num_pages;
				xaml_PageSlider.Minimum = 1;
				xaml_PageSlider.IsEnabled = true;
				this.xaml_Pages.IsFilmstripModeEnabled = false;
				xaml_PageSlider.Visibility = Visibility.Visible;
				xaml_PageNumber.Visibility = Visibility.Visible;
				var str1 = "1/" + m_num_pages;
				xaml_PageNumber.Text = str1;
				m_have_thumbs = false;
			}
		}

		private async void OpenDocument(IStorageFile file, String extension)
		{
			/* Open document and when open, push on */
			int result = await mu_doc.OpenFileAsync(file, extension);

			/* Check if we need password */
			if (mu_doc.RequiresPassword())
			{
				SetView(view_t.VIEW_PASSWORD);
				return;
			} else
				InitialRender();
		}

		private void PasswordOK(object sender, RoutedEventArgs e)
		{

		}

		private void Search_Click(object sender, EventArgs e)
		{
			if (this.m_num_pages < 0)
				return;

			if (xaml_TextSearchView.Visibility == Visibility.Visible)
			{
				SetView(view_t.VIEW_PAGE);
				SetAppBar(AppBar_t.STANDARD);
				return;
			}
			SetView(view_t.VIEW_TEXTSEARCH);
			SetAppBar(AppBar_t.TEXT_SEARCH);
		}

		private void Links_Click(object sender, EventArgs e)
		{

		}

		private void Content_Click(object sender, EventArgs e)
		{
			if (this.m_num_pages < 0 || m_contents_size == 0 )
				return;

			if (xaml_ContentView.Visibility == Visibility.Visible)
			{
				SetView(view_t.VIEW_PAGE);
				return;
			}

			if (m_contents_size < 0)
			{
				/* compute the contents  */
				m_contents_size = mu_doc.ComputeContents();
			}

			if (m_contents_size > 0)
			{
				for (int k = 0; k < m_contents_size; k++)
				{
					ContentItem item = mu_doc.GetContent(k);
					ContentEntry entry = new ContentEntry(item.StringMargin, item.Page);
					m_content_list.Add(entry);
				}
				this.xaml_Contents.ItemsSource = m_content_list;
				SetView(view_t.VIEW_CONTENT);
			}
		}

		private void Open_Click(object sender, EventArgs e)
		{
			string targetPageUri = "/FilesPage.xaml?method={0}";
			NavigationService.Navigate(new Uri(targetPageUri, UriKind.Relative));
		}
		
		protected override void OnNavigatedTo(NavigationEventArgs e)
		{
			if (NavigationContext.QueryString.ContainsKey("fileToken"))
			{
				string tempUri = e.Uri.ToString();
				int fileIDIndex = tempUri.IndexOf("fileToken=") + 10;
				string fileID = tempUri.Substring(fileIDIndex);
				GetFile(fileID, true);
			}

			if (this.ReceivedData != null)
			{
				if (this.ReceivedData != string.Empty)
				{
					m_height = (App.Current as App).appHeight;
					m_width = (App.Current as App).appWidth;
					GetFile(this.ReceivedData, false);
				}
			}
			base.OnNavigatedTo(e);
		}

		protected override void OnNavigatedFrom(NavigationEventArgs e)
		{
			base.OnNavigatedFrom(e);
			// Reset values when the user leaves this target page.
			this.ReceivedData = string.Empty;
		}

		public string ReceivedData { get; set; }

		private void Reflow_Click(object sender, EventArgs e)
		{
			if (this.xaml_WebView.Visibility == Visibility.Collapsed)
			{
				String html = mu_doc.ComputeHTML(this.m_currpage);
				xaml_viewhtml.NavigateToString(html);
				SetView(view_t.VIEW_WEB);
			}
			else
			{
				SetView(view_t.VIEW_PAGE);
			}
		}

		private void NotifyUser(String strMessage, NotifyType_t type)
		{
			switch (type)
			{
			case NotifyType_t.MESS_STATUS:
				MessageBox.Show(strMessage);
				break;
			case NotifyType_t.MESS_ERROR:
				MessageBox.Show("Error", strMessage, MessageBoxButton.OK);
				break;
			default:
				break;
			}
		}

		private void PassOK(object sender, RoutedEventArgs e)
		{
			/* Check password */
			if (mu_doc.ApplyPassword(this.xaml_Password.Password))
			{
				SetView(view_t.VIEW_PAGE);
				InitialRender();
			}
			else
				NotifyUser("Incorrect Password", NotifyType_t.MESS_STATUS);
		}

		private void PassCancel(object sender, RoutedEventArgs e)
		{
			SetView(view_t.VIEW_PAGE);
			return;
		}

		private void SlideAnimationStart(object sender, EventArgs e)
		{
			//xaml_Pages.HideOverlayContent();
		}

		private void SlideAnimationDone(object sender, EventArgs e)
		{
			// Selection changed will handle page update stuff
			//xaml_Pages.ShowOverlayContent();
		}

		private async void SelectionChanged(object sender, SelectionChangedEventArgs e)
		{
			if (m_init_done)
			{
				DocumentPage currPage = (DocumentPage)xaml_Pages.SelectedItem;
				if (xaml_PageSlider.IsEnabled)
				{
					xaml_PageSlider.Value = currPage.PageNum + 1;
				}
				var code = await GotoPage(currPage.PageNum);
			}
		}

		private void ContentPicked(object sender, SelectionChangedEventArgs e)
		{
			if (xaml_Contents.SelectedItem == null)
				return;

			var curr_item = (ContentEntry)xaml_Contents.SelectedItem;
			int page_num = curr_item.PageNum;

			if ((page_num > -1) && (page_num < m_num_pages))
			{
				this.xaml_Pages.SelectedItem = m_docPages[page_num];
				SetView(view_t.VIEW_PAGE);
			}
		}

		private void ZoomBlock_ManipulationStarted(object sender, ManipulationStartedEventArgs e)
		{
			PanAndZoomImage panzoom = (PanAndZoomImage)sender;
			this.m_panX = panzoom.Pan.X;
			this.m_panY = panzoom.Pan.Y;
		}

		private void ZoomBlock_ManipulationDelta(object sender, ManipulationDeltaEventArgs e)
		{
			PanAndZoomImage panzoom = (PanAndZoomImage)sender;
			this.m_panX = panzoom.Pan.X;
			this.m_panY = panzoom.Pan.Y;

		}

		async private void ZoomBlock_ManipulationCompleted(object sender, ManipulationCompletedEventArgs e)
		{
			PanAndZoomImage panzoom = (PanAndZoomImage)sender;
			var temp = panzoom.RenderTransform;
			var temp2 = panzoom.RenderTransformOrigin;
			if (panzoom.Zoom != m_docPages[m_currpage].Zoom)
			{
				m_docPages[m_currpage].Zoom = panzoom.Zoom;
				await RenderPage(panzoom.Zoom, m_currpage, 0, 0);
			}
			var deltaX = this.m_panX - panzoom.Pan.X;
			var deltaY = this.m_panY - panzoom.Pan.Y;
		}

		private async void SearchText(object sender, EventArgs e)
		{
			RadTextBox tbox = (RadTextBox)sender;
			String text = tbox.Text;

			if (text.Length == 0) return;
			xaml_TextSearchView.Visibility = Visibility.Collapsed;
			await SearchInDirection(Constants.SEARCH_FORWARD, text);
		}

		private async void BackSearch(object sender, EventArgs e)
		{
			String text = xaml_TextEnter.Text;

			if (text.Length == 0) return;
			xaml_TextSearchView.Visibility = Visibility.Collapsed;
			await SearchInDirection(Constants.SEARCH_BACKWARD, text);
		}

		private async void ForwardSearch(object sender, EventArgs e)
		{
			String text = xaml_TextEnter.Text;

			if (text.Length == 0) return;
			xaml_TextSearchView.Visibility = Visibility.Collapsed;
			await SearchInDirection(Constants.SEARCH_FORWARD, text);
		}

		public void SearchProgress(IAsyncOperationWithProgress<int, double> operation, double status)
		{
			//ProgressBar temp = xaml_Progress;
			//temp.Value = status;
		}

		private async Task SearchInDirection(int dir, String textToFind)
		{
			//cancellation_token_source cts;
			//auto token = cts.get_token();
			//m_searchcts = cts;
			int pos = m_currpage;
			int start;

			if (m_searchpage == pos)
				start = pos + dir;
			else
				start = pos;

			if (start < 0)
				return;
			if (start > this.m_num_pages - 1)
				return;
			this.m_search_active = true;

			ProgressBar my_xaml_Progress = (ProgressBar)(this.FindName("xaml_Progress"));

			xaml_ProgressStack.Visibility = Visibility.Visible;
			var temp = mu_doc.SearchDocumentWithProgressAsync(textToFind, dir, start, m_num_pages);
			temp.Progress = new AsyncOperationProgressHandler<int, double>(SearchProgress);

			var page_num = await temp;
			xaml_ProgressStack.Visibility = Visibility.Collapsed;

			if (page_num == Constants.TEXT_NOT_FOUND)
			{
				var str1 = "\"" + textToFind + "\" Was Not Found In The Search";
				NotifyUser(str1, NotifyType_t.MESS_STATUS);
				this.m_search_active = false;
				return;
			}
			else
			{
				int box_count = mu_doc.TextSearchCount();

				if (box_count > 0)
				{
					ShowSearchResults(page_num, box_count);
				}
				return;
			}
		}

		private void CancelSearch(object sender, RoutedEventArgs e)
		{

		}

		private void ClearTextSearch()
		{
			/* Clear out any old search result */
			if (m_text_list.Count > 0)
				m_text_list.Clear();
		}

		static Windows.Foundation.Point fitPageToScreen(Windows.Foundation.Point page, 
														Windows.Foundation.Point screen)
		{
			Windows.Foundation.Point pageSize;

			double hscale = screen.X / page.X;
			double vscale = screen.Y / page.Y;
			double scale = Math.Min(hscale, vscale);
			pageSize.X = Math.Floor(page.X * scale) / page.X;
			pageSize.Y = Math.Floor(page.Y * scale) / page.Y;
			return pageSize;
		}

		private void ShowSearchResults(int page_num, int box_count)
		{
			int old_page = this.m_currpage;
			int new_page = page_num;

			ClearTextSearch();

			/* Compute any scalings */
			Windows.Foundation.Point screenSize;
			Windows.Foundation.Point pageSize;
			Windows.Foundation.Point scale;

			screenSize.Y = (App.Current as App).appHeight;
			screenSize.X = (App.Current as App).appWidth;
			screenSize.X *= Constants.screenScale;
			screenSize.Y *= Constants.screenScale;
			pageSize = mu_doc.GetPageSize(new_page);
			scale = fitPageToScreen(pageSize, screenSize);
			var doc_page = this.m_docPages.ElementAt(new_page);

			/* Construct our list of rectangles */
			for (int k = 0; k < box_count; k++)
			{
				RectList rect_item = new RectList();
				var curr_box = mu_doc.GetTextSearch(k);

				rect_item.Color = m_textcolor;
				rect_item.Height = (int) ((curr_box.LowerRight.Y - curr_box.UpperLeft.Y) * (scale.Y * doc_page.Zoom));
				rect_item.Width = (int) ((curr_box.LowerRight.X - curr_box.UpperLeft.X) * (scale.X * doc_page.Zoom));
				rect_item.X = (int) (curr_box.UpperLeft.X * scale.X);
				rect_item.Y = (int) (curr_box.UpperLeft.Y * scale.Y);
				rect_item.Index = k.ToString();
				m_text_list.Add(rect_item);
			}
			/* Make sure the current page has its text results cleared */
			this.m_docPages[old_page].TextBox = null;

			/* Go ahead and set our doc item to this in the vertical and horizontal view */
			m_searchpage = new_page;
			m_flip_from_searchlink = true;

			if (old_page != new_page)
			{
				if ((page_num > -1) && (page_num < m_num_pages))
				{
					m_docPages[m_currpage] = m_thumbnails[m_currpage];
					this.xaml_Pages.SelectedItem = m_docPages[new_page];
					this.m_currpage = new_page;
				}
			}

			/* Turn on the search result */
			m_docPages[new_page].TextBox = m_text_list;
			m_docPages[new_page].PageRefresh();
			return;
		}

		private async Task RenderThumbs()
		{
			spatial_info_t spatial_info = InitSpatial(1);
			int num_pages = m_num_pages;
			//cancellation_token_source cts;
			//auto token = cts.get_token();
			//m_ThumbCancel = cts;
			//auto ui = task_continuation_context::use_current();

			//m_ren_status = REN_THUMBS;
			List<DocumentPage> thumbnails = m_thumbnails;
			for (int k = 0; k < m_num_pages; k++)
			{
				await RenderThumb(Constants.SCALE_THUMB, k);
				/* Once this one is rendered then see if we should set it */
				if (m_docPages[k].Content != Page_Content_t.FULL_RESOLUTION)
				{
					m_docPages[k] = m_thumbnails[k];
				}
				this.xaml_Busy.Content = "Rendering Thumbnail "+ (k + 1) + " of " + (m_num_pages + 1);
			}
			this.xaml_Busy.IsRunning = false;
			this.xaml_StackBusy.Visibility = Visibility.Collapsed;
			this.xaml_Pages.IsFilmstripModeEnabled = true;
		}

		private async void Slider_Done(object sender, ManipulationCompletedEventArgs e)
		{
			int newValue = (int)xaml_PageSlider.Value - 1;  /* zero based */

			if (m_init_done && xaml_PageSlider.IsEnabled)
			{
				if ((newValue > -1) && (newValue < m_num_pages))
				{
					/* Use current zoom value */
					DocumentPage currPage = (DocumentPage)xaml_Pages.SelectedItem;
					double curr_zoom = currPage.Zoom;
					await RenderPage(curr_zoom, newValue, 0, 0);
					this.xaml_Pages.SelectedItem = m_docPages[newValue];
				}
			}
		}

		private void Slider_Change(object sender, RoutedPropertyChangedEventArgs<double> e)
		{
			int newValue = (int)xaml_PageSlider.Value; 

			if (m_init_done && xaml_PageSlider.IsEnabled)
			{
				var str1 = newValue + "/" + m_num_pages;
				xaml_PageNumber.Text = str1;
			}
		}
	}
}
