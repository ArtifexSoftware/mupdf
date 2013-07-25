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
	VIEW_PASSWORD
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
	public Point size;
	public double scale_factor;
} ;

/* C# has no defines.... */
static class Constants {
	public const int LOOK_AHEAD = 0;  /* A +/- count on the pages to pre-render */
	public const int THUMB_PREADD = 10;
	public const double  MIN_SCALE = 0.5;
	public const double SCALE_THUMB = 0.1;
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
		private bool m_update_flip;
		private double m_Progress;
		int m_width;
		int m_height;

		// Constructor
		public MainPage()
		{
			InitializeComponent();
			this.Loaded += Page_Loaded;

			m_textcolor="#402572AC";
			m_linkcolor="#40AC7225";

			m_docPages = new Pages();
			m_thumbnails = new List<DocumentPage>();
			m_page_link_list = new List<List<RectList>>();
			m_text_list = new List<RectList>();
			m_content_list = new List<ContentEntry>();
			m_linkset = new List<bool>();
			m_contents_size = -1;  /* Not yet computed */
			m_content_item = -1;
			SetView(view_t.VIEW_PAGE);
			CleanUp();
		}

		private void SetView(view_t newview)
		{
			switch (newview)
			{
				case view_t.VIEW_WEB:
					this.xaml_PageView.Visibility = Visibility.Collapsed;
					this.xaml_ContentView.Visibility = Visibility.Collapsed;
					this.xaml_PasswordView.Visibility = Visibility.Collapsed;
					this.xaml_WebView.Visibility = Visibility.Visible;
					break;

				case view_t.VIEW_PAGE:
					this.xaml_WebView.Visibility = Visibility.Collapsed;
					this.xaml_ContentView.Visibility = Visibility.Collapsed;
					this.xaml_PasswordView.Visibility = Visibility.Collapsed;
					this.xaml_PageView.Visibility = Visibility.Visible;
					break;

				case view_t.VIEW_CONTENT:
					this.xaml_PageView.Visibility = Visibility.Collapsed;
					this.xaml_WebView.Visibility = Visibility.Collapsed;
					this.xaml_PasswordView.Visibility = Visibility.Collapsed;
					this.xaml_ContentView.Visibility = Visibility.Visible;
					break;

				case view_t.VIEW_PASSWORD:
					this.xaml_PageView.Visibility = Visibility.Collapsed;
					this.xaml_WebView.Visibility = Visibility.Collapsed;
					this.xaml_ContentView.Visibility = Visibility.Collapsed;
					this.xaml_PasswordView.Visibility = Visibility.Visible;
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
		/* Set the page with the new raster information */
		private void UpdatePage(int page_num, IBuffer buff, Point ras_size, 
							Page_Content_t content_type)
		{
			WriteableBitmap bmp = new WriteableBitmap((int) ras_size.X, (int) ras_size.Y);
			using (var stream = buff.AsStream())
			{
				bmp.SetSource(stream);
			}
			DocumentPage doc_page = new DocumentPage((int) ras_size.Y, 
													(int) ras_size.X, (float) 1.0, 
													bmp, null, null, content_type, 
													"Page " + page_num);
			doc_page.Image = bmp;

			if (content_type == Page_Content_t.THUMBNAIL)
			{
				doc_page.Height = (int) (ras_size.Y / Constants.SCALE_THUMB);
				doc_page.Width = (int) (ras_size.X / Constants.SCALE_THUMB);
			}
			else
			{
				doc_page.Height = (int) ras_size.Y;
				doc_page.Width = (int) ras_size.X;
			}
			doc_page.Content = content_type;
			m_page_update = true;
			this.m_docPages[page_num] = doc_page;
			m_page_update = false;
		}

		private spatial_info_t InitSpatial(double scale)
		{
			spatial_info_t value = new spatial_info_t();

			value.size.Y = this.m_height;
			value.size.X = this.m_width;
			value.scale_factor = scale;
			return value;
		}

		private Point ComputePageSize(spatial_info_t spatial_info, int page_num)
		{
			Point screenSize;
			Point pageSize = new Point();
			Windows.Foundation.Point size = mu_doc.GetPageSize(page_num);

			screenSize = spatial_info.size;
			screenSize.Y *= Constants.screenScale;
			screenSize.X *= Constants.screenScale;

			double hscale = screenSize.X / size.X;
			double vscale = screenSize.Y / size.Y;
			double scale = Math.Min(hscale, vscale);
			pageSize.X = size.X * scale * spatial_info.scale_factor;
			pageSize.Y = size.Y * scale * spatial_info.scale_factor;

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
					Page_Content_t.DUMMY, "Page " + (k+1));

				m_docPages.Add(doc_page);
				m_thumbnails.Add(doc_page);
				/* Create empty lists for our links and specify that they have
					not been computed for these pages */
				List<RectList> temp_link = new List<RectList>();
				m_page_link_list.Add(temp_link);
				m_linkset.Add(false);
			}
			this.xaml_Pages.ItemsSource = m_docPages;

			//this->xaml_horiz_flipView->ItemsSource = m_docPages;
			//this->xaml_vert_flipView->ItemsSource = m_docPages;

			/* Do the first few pages, then start the thumbs */
			spatial_info_t spatial_info = InitSpatial(1);
			for (int k = 0; k < Constants.LOOK_AHEAD + 3; k++)
			{
				if (m_num_pages > k )
				{
					Point ras_size = ComputePageSize(spatial_info, k);
					IBuffer buffer = new Windows.Storage.Streams.Buffer((uint) (ras_size.X) * (uint) (ras_size.Y) * 4 + 54);
					buffer.Length = (uint)(ras_size.X) * (uint)(ras_size.Y) * 4 + 54;

					/* Handle header here */
					var buff_array = buffer.ToArray();
					var mem_stream = new MemoryStream(buff_array, true);
					var out_stream = mem_stream.AsOutputStream();
					var dw = new DataWriter(out_stream);
	
					int code = await mu_doc.RenderPageAsync(k, (int) (ras_size.X), 
												  (int) (ras_size.Y), true, dw,
												  Constants.HEADER_SIZE);

					WriteableBitmap bmp = new WriteableBitmap((int)ras_size.X, 
															  (int)ras_size.Y);
					bmp.SetSource(mem_stream);
					DocumentPage doc_page = new DocumentPage((int)ras_size.Y,
						(int)(ras_size.X), (float)1.0, bmp, null, null,
						Page_Content_t.FULL_RESOLUTION, "Page " + (k + 1));
					m_docPages[k] = doc_page;
				}
			}

			/* Update the slider settings, if more than one page */
			if (m_num_pages > 1)
			{
				//this->xaml_PageSlider->Maximum = m_num_pages;
				//this->xaml_PageSlider->Minimum = 1;
				//this->xaml_PageSlider->IsEnabled = true;
			}
			else
			{
				//this->xaml_PageSlider->Maximum = 0;
				//this->xaml_PageSlider->Minimum = 0;
				//this->xaml_PageSlider->IsEnabled = false;
			}

			/* All done with initial pages */
			this.m_init_done = true;
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
			bool from_file = false;

			if (NavigationContext.QueryString.ContainsKey("fileToken"))
			{
				string tempUri = e.Uri.ToString();
				int fileIDIndex = tempUri.IndexOf("fileToken=") + 10;
				string fileID = tempUri.Substring(fileIDIndex);
				GetFile(fileID, true);
				from_file = true;
			}

			if (this.ReceivedData != null)
			{
				if (this.ReceivedData != string.Empty)
				{
					m_height = (App.Current as App).appHeight;
					m_width = (App.Current as App).appWidth;
					GetFile(this.ReceivedData, false);
					from_file = true;
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
	}
}
