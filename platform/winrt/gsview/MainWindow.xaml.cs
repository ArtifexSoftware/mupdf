using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;
using System.Windows.Forms;
using System.ComponentModel;
using System.IO;
using System.Windows.Xps.Packaging;
using System.Printing;
using System.Windows.Markup;

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

public enum status_t
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
	public Point size;
	public double scale_factor;
};

/* C# has no defines.... */
static class Constants
{
	public const int LOOK_AHEAD = 1;  /* A +/- count on the pages to pre-render */
	public const int THUMB_PREADD = 10;
	public const double MIN_SCALE = 0.5;
	public const double SCALE_THUMB = 0.05;
	public const int BLANK_WIDTH = 17;
	public const int BLANK_HEIGHT = 22;
	public const double ZOOM_STEP = 0.25;
	public const int ZOOM_MAX = 4;
	public const double ZOOM_MIN = 0.25;
	public const int KEY_PLUS = 0xbb;
	public const int KEY_MINUS = 0xbd;
	public const int ZOOM_IN = 0;
	public const int ZOOM_OUT = 1;
	public const double SCREEN_SCALE = 1;
	public const int HEADER_SIZE = 54;
	public const int SEARCH_FORWARD = 1;
	public const int SEARCH_BACKWARD = -1;
	public const int TEXT_NOT_FOUND = -1;
}

namespace gsview
{
	/// <summary>
	/// Interaction logic for MainWindow.xaml
	/// </summary>
	/// 

	public struct thumb_t
	{
		public int page_num;
		public Byte[] bitmap;
		public Point size;
	}

	public partial class MainWindow : Window
	{
		mudocument mu_doc;
		public Pages m_docPages;
		List<DocPage> m_thumbnails;
		List<List<RectList>> m_page_link_list;
		int m_contents_size;
		int m_content_item;
		List<bool> m_linkset;
		List<RectList> m_text_list;
		private int m_rectlist_page;
		private List<ContentEntry> m_content_list;
		private bool m_file_open;
		private int m_currpage;
		private int m_searchpage;
		private int m_num_pages;
		private bool m_init_done;
		private bool m_links_on;
		private int m_search_rect_count;
		private bool m_page_update;
		String m_textcolor;
		String m_linkcolor;
		RenderingStatus_t m_ren_status;
		private bool m_insearch;
		private bool m_search_active;
		private bool m_handlingzoom;
		private bool m_have_thumbs;
		private bool m_have_contents;
		double m_doczoom;
		ghostsharp m_ghostscript;
		String m_currfile;
		private gsprint m_ghostprint = null;
		bool m_isXPS;
		gsOutput m_gsoutput;
		Convert m_convertwin;
		Password m_password = null;
		bool m_zoomhandled;
		BackgroundWorker m_thumbworker = null;

		public MainWindow()
		{
			InitializeComponent();
			this.Closing += new System.ComponentModel.CancelEventHandler(Window_Closing);
			m_file_open = false;
			status_t result = CleanUp();

			/* Allocations */
			try
			{
				m_docPages = new Pages();
				m_thumbnails = new List<DocPage>();
				m_page_link_list = new List<List<RectList>>();
				m_text_list = new List<RectList>();
				m_linkset = new List<bool>();
				m_ghostscript = new ghostsharp();
				m_ghostscript.gsUpdateMain += new ghostsharp.gsCallBackMain(gsProgress);
				m_gsoutput = new gsOutput();
				m_gsoutput.Activate();
				m_ghostscript.gsIOUpdateMain += new ghostsharp.gsIOCallBackMain(gsIO);
				m_convertwin = null;
			}
			catch (OutOfMemoryException e)
			{
				Console.WriteLine("Memory allocation failed at initialization\n");
				ShowMessage(NotifyType_t.MESS_ERROR, "Out of memory: " + e.Message);
			}
		}

		void Window_Closing(object sender, System.ComponentModel.CancelEventArgs e)
		{
			m_gsoutput.RealWindowClosing();
		}

		private status_t CleanUp()
		{
			m_init_done = false;

			/* Collapse this stuff since it is going to be released */
			xaml_ThumbGrid.Visibility = System.Windows.Visibility.Collapsed;
			xaml_ContentGrid.Visibility = System.Windows.Visibility.Collapsed;

			/* Clear out everything */
			if (m_docPages != null && m_docPages.Count > 0)
				m_docPages.Clear();
			if (m_thumbnails != null && m_thumbnails.Count > 0)
				m_thumbnails.Clear();
			if (m_page_link_list != null && m_page_link_list.Count > 0)
				m_page_link_list.Clear();
			if (m_text_list != null && m_text_list.Count > 0)
				m_text_list.Clear();
			if (m_linkset != null && m_linkset.Count > 0)
				m_linkset.Clear();

			if (mu_doc != null)
				mu_doc.CleanUp();
			try
			{
				mu_doc = new mudocument();
			}
			catch (OutOfMemoryException e)
			{
				Console.WriteLine("Memory allocation failed during clean up\n");
				ShowMessage(NotifyType_t.MESS_ERROR, "Out of memory: " + e.Message);
			}
			status_t result = mu_doc.Initialize();

			if (result != status_t.S_ISOK)
			{
				Console.WriteLine("Library allocation failed during clean up\n");
				ShowMessage(NotifyType_t.MESS_ERROR, "Library allocation failed!");
				return result;
			}

			m_have_thumbs = false;
			m_file_open = false;
			m_insearch = false;
			m_search_active = false;
			m_num_pages = -1;
			m_search_rect_count = 0;
			m_links_on = false;
			m_rectlist_page = -1;
			m_doczoom = 1.0;
			m_isXPS = false;
			m_zoomhandled = false;
			xaml_CancelThumb.IsEnabled = true;
			m_currpage = 0;
			return result;
		}

		private void ShowMessage(NotifyType_t type, String Message)
		{
			if (type == NotifyType_t.MESS_ERROR)
			{
				System.Windows.Forms.MessageBox.Show(Message, "Error",
					MessageBoxButtons.OK, MessageBoxIcon.Exclamation);
			}
			else
			{
				System.Windows.Forms.MessageBox.Show(Message, "Notice",
					MessageBoxButtons.OK);
			}
		}

		private void CloseDoc()
		{
			CleanUp();
		}

		/* Set the page with the new raster information */
		private void UpdatePage(int page_num, Byte[] bitmap, Point ras_size,
			Page_Content_t content, double zoom_in)
		{
			DocPage doc_page = this.m_docPages[page_num];

			doc_page.Width = (int)ras_size.X;
			doc_page.Height = (int)ras_size.Y;

			doc_page.Content = content;
			doc_page.Zoom = zoom_in;

			int stride = doc_page.Width * 4;
			doc_page.BitMap = BitmapSource.Create(doc_page.Width, doc_page.Height, 72, 72, PixelFormats.Pbgra32, BitmapPalettes.Halftone256, bitmap, stride);
			doc_page.PageNum = page_num;

			if (content == Page_Content_t.THUMBNAIL)
			{
				doc_page.Width = (int)(ras_size.X / Constants.SCALE_THUMB);
				doc_page.Height = (int)(ras_size.Y / Constants.SCALE_THUMB);
			}
		}

		void SetThumbInit(int page_num, Byte[] bitmap, Point ras_size, double zoom_in)
		{
			/* Two jobs. Store the thumb and possibly update the full page */
			DocPage doc_page = m_thumbnails[page_num];

			doc_page.Width = (int)ras_size.X;
			doc_page.Height = (int)ras_size.Y;
			doc_page.Content = Page_Content_t.THUMBNAIL;
			doc_page.Zoom = zoom_in;
			int stride = doc_page.Width * 4;
			doc_page.BitMap = BitmapSource.Create(doc_page.Width, doc_page.Height, 72, 72, PixelFormats.Pbgra32, BitmapPalettes.Halftone256, bitmap, stride);
			doc_page.PageNum = page_num;

			/* And the main page */
			var doc = m_docPages[page_num];
			if (doc.Content == Page_Content_t.THUMBNAIL || doc.Content == Page_Content_t.FULL_RESOLUTION)
				return;
			else
			{
				doc_page = this.m_docPages[page_num];
				doc_page.Content = Page_Content_t.THUMBNAIL;
				doc_page.Zoom = zoom_in;

				doc_page.BitMap = m_thumbnails[page_num].BitMap;
				doc_page.Width = (int)(ras_size.X / Constants.SCALE_THUMB);
				doc_page.Height = (int)(ras_size.Y / Constants.SCALE_THUMB);
				doc_page.PageNum = page_num;
			}
		}

		private void ThumbsWork(object sender, DoWorkEventArgs e)
		{
			Point ras_size;
			status_t code;
			double scale_factor = Constants.SCALE_THUMB;
			BackgroundWorker worker = sender as BackgroundWorker;

			Byte[] bitmap;

			for (int k = 0; k < m_num_pages; k++)
			{
				if (ComputePageSize(k, scale_factor, out ras_size) == status_t.S_ISOK)
				{
					try
					{
						bitmap = new byte[(int)ras_size.X * (int)ras_size.Y * 4];
						/* Synchronous call on our background thread */
						code = (status_t)mu_doc.RenderPage(k, bitmap, (int)ras_size.X, (int)ras_size.Y, scale_factor, false, false);
					}
					catch (OutOfMemoryException em)
					{
						Console.WriteLine("Memory allocation failed thumb page " + k + em.Message + "\n");
						break;
					}
					/* Use thumb if we rendered ok */
					if (code == status_t.S_ISOK)
					{
						double percent = 100 * (double)(k + 1) / (double)m_num_pages;
						thumb_t curr_thumb = new thumb_t();
						curr_thumb.page_num = k;
						curr_thumb.bitmap = bitmap;
						curr_thumb.size = ras_size;
						worker.ReportProgress((int)percent, curr_thumb);
					}
				}
				if (worker.CancellationPending == true)
				{
					e.Cancel = true;
					break;
				}
			}
		}

		private void ThumbsCompleted(object sender, RunWorkerCompletedEventArgs e)
		{
			xaml_ProgressGrid.Visibility = System.Windows.Visibility.Collapsed;
			xaml_ThumbProgress.Value = 0;
			xaml_ThumbList.ItemsSource = m_thumbnails;
			m_have_thumbs = true;
			m_thumbworker = null;
			xaml_CancelThumb.IsEnabled = true;
		}

		private void ThumbsProgressChanged(object sender, ProgressChangedEventArgs e)
		{
			thumb_t thumb = (thumb_t)(e.UserState);

			xaml_ThumbProgress.Value = e.ProgressPercentage;
			SetThumbInit(thumb.page_num, thumb.bitmap, thumb.size, 1.0);
			m_docPages[thumb.page_num].PageRefresh();
			m_thumbnails[thumb.page_num].PageRefresh();
		}

		private void RenderThumbs()
		{
			/* Create background task for rendering the thumbnails.  Allow
			this to be cancelled if we open a new doc while we are in loop
			rendering.  Put the UI updates in the progress changed which will
			run on the main thread */
			try
			{
				m_thumbworker = new BackgroundWorker();
				m_thumbworker.WorkerReportsProgress = true;
				m_thumbworker.WorkerSupportsCancellation = true;
				m_thumbworker.DoWork += new DoWorkEventHandler(ThumbsWork);
				m_thumbworker.RunWorkerCompleted += new RunWorkerCompletedEventHandler(ThumbsCompleted);
				m_thumbworker.ProgressChanged += new ProgressChangedEventHandler(ThumbsProgressChanged);
				xaml_ProgressGrid.Visibility = System.Windows.Visibility.Visible;
				m_thumbworker.RunWorkerAsync();
			}
			catch (OutOfMemoryException e)
			{
				Console.WriteLine("Memory allocation failed during thumb rendering\n");
				ShowMessage(NotifyType_t.MESS_ERROR, "Out of memory: " + e.Message);
			}
		}

		private void OpenFile(object sender, RoutedEventArgs e)
		{
			if (m_password != null && m_password.IsActive)
				m_password.Close();

			/* Check if gs is currently busy. If it is then don't allow a new
			 * file to be opened. They can cancel gs with the cancel button if
			 * they want */
			if (m_ghostscript.GetStatus() != gsStatus.GS_READY)
			{
				ShowMessage(NotifyType_t.MESS_STATUS, "GS busy. Cancel to open new file."); 
				return;
			}
			OpenFileDialog dlg = new OpenFileDialog();
			dlg.Filter = "Document Files(*.ps;*.eps;*.pdf;*.xps;*.cbz)|*.ps;*.eps;*.pdf;*.xps;*.cbz|All files (*.*)|*.*";
			dlg.FilterIndex = 1;
			if (dlg.ShowDialog() == System.Windows.Forms.DialogResult.OK)
			{
				if (m_file_open)
				{
					CloseDoc();
				}
				/* If we have a ps or eps file then launch the distiller first
				 * and then we will get a temp pdf file which will be opened by
				 * mupdf */
				string extension = System.IO.Path.GetExtension(dlg.FileName);
				if (extension.ToUpper() == ".PS" || extension.ToUpper() == ".EPS")
				{
					xaml_DistillProgress.Value = 0;
					if (m_ghostscript.DistillPS(dlg.FileName) == gsStatus.GS_BUSY)
					{
						ShowMessage(NotifyType_t.MESS_STATUS, "GS currently busy");
						return;
					}
					xaml_DistillGrid.Visibility = System.Windows.Visibility.Visible;
					return;
				}
				/* Set if this is already xps for printing */
				if (extension.ToUpper() == ".XPS")
					m_isXPS = true;
				OpenFile2(dlg.FileName);
			}
		}

		private void OpenFile2(String File)
		{
			m_currfile = File;

			status_t code = mu_doc.OpenFile(m_currfile);
			if (code == status_t.S_ISOK)
			{
				/* Check if we need a password */
				if (mu_doc.RequiresPassword())
					GetPassword();
				else
					StartViewer();
			}
			else
			{
				m_currfile = null;
				ShowMessage(NotifyType_t.MESS_ERROR, "Failed to open file!");
			}
		}

		private void StartViewer()
		{
			InitialRender();
			RenderThumbs();
			m_file_open = true;
		}

		private status_t ComputePageSize(int page_num, double scale_factor,
									out Point render_size)
		{
			Point renpageSize = new Point();

			status_t code = (status_t)mu_doc.GetPageSize(page_num, out render_size);
			if (code != status_t.S_ISOK)
				return code;

			renpageSize.X = (render_size.X * scale_factor);
			renpageSize.Y = (render_size.Y * scale_factor);

			render_size = renpageSize;

			return status_t.S_ISOK;
		}

		private DocPage InitDocPage()
		{
			DocPage doc_page = new DocPage();

			doc_page.BitMap = null;
			doc_page.Height = Constants.BLANK_HEIGHT;
			doc_page.Width = Constants.BLANK_WIDTH;
			doc_page.NativeHeight = Constants.BLANK_HEIGHT;
			doc_page.NativeWidth = Constants.BLANK_WIDTH;
			doc_page.Content = Page_Content_t.DUMMY;
			doc_page.TextBox = null;
			doc_page.LinkBox = null;
			return doc_page;
		}

		async private void InitialRender()
		{
			m_num_pages = mu_doc.GetPageCount();
			m_currpage = 0;

			for (int k = 0; k < m_num_pages; k++)
			{
				m_docPages.Add(InitDocPage());
				m_docPages[k].PageNum = k;
				m_thumbnails.Add(InitDocPage());
				/* Create empty lists for our links and specify that they have
					not been computed for these pages */
				List<RectList> temp_link = new List<RectList>();
				m_page_link_list.Add(temp_link);
				m_linkset.Add(false);
			}

			/* Do the first few full res pages */
			for (int k = 0; k < Constants.LOOK_AHEAD + 2; k++)
			{
				if (m_num_pages > k)
				{
					Point ras_size;
					double scale_factor = 1.0;

					if (ComputePageSize(k, scale_factor, out ras_size) == status_t.S_ISOK)
					{
						try
						{
							Byte[] bitmap = new byte[(int)ras_size.X * (int)ras_size.Y * 4];

							Task<int> ren_task =
								new Task<int>(() => mu_doc.RenderPage(k, bitmap, (int)ras_size.X, (int)ras_size.Y, scale_factor, false, true));
							ren_task.Start();
							await ren_task.ContinueWith((antecedent) =>
							{
								status_t code = (status_t)ren_task.Result;
								if (code == status_t.S_ISOK)
									UpdatePage(k, bitmap, ras_size, Page_Content_t.FULL_RESOLUTION, 1.0);
							}, TaskScheduler.FromCurrentSynchronizationContext());
						}
						catch (OutOfMemoryException e)
						{
							Console.WriteLine("Memory allocation failed page " + k + "\n");
							ShowMessage(NotifyType_t.MESS_ERROR, "Out of memory: " + e.Message);
						}
					}
				}
			}
			m_init_done = true;
			xaml_PageList.ItemsSource = m_docPages;
		}

		private void OnBackPageClick(object sender, RoutedEventArgs e)
		{
			if (m_currpage == 0 || !m_init_done) return;

			m_currpage = m_currpage - 1;
			xaml_PageList.ScrollIntoView(m_docPages[m_currpage]);
		}

		private void OnForwardPageClick(object sender, RoutedEventArgs e)
		{
			if (m_currpage == m_num_pages - 1 || !m_init_done) return;

			m_currpage = m_currpage + 1;
			xaml_PageList.ScrollIntoView(m_docPages[m_currpage]);
		}

		private void CancelLoadClick(object sender, RoutedEventArgs e)
		{
			/* Cancel during thumbnail loading. Deactivate the button 
			 * and cancel the thumbnail rendering */
			if (m_thumbworker != null)
				m_thumbworker.CancelAsync();
			xaml_CancelThumb.IsEnabled = false;
		}

		private void ToggleThumbs(object sender, RoutedEventArgs e)
		{
			if (m_have_thumbs)
			{
				if (xaml_ThumbGrid.Visibility == System.Windows.Visibility.Collapsed)
				{
					xaml_ThumbGrid.Visibility = System.Windows.Visibility.Visible;
				}
				else
				{
					xaml_ThumbGrid.Visibility = System.Windows.Visibility.Collapsed;
				}
			}
		}

		private void ToggleContents(object sender, RoutedEventArgs e)
		{
			if (xaml_ContentGrid.Visibility == System.Windows.Visibility.Visible)
			{
				xaml_ContentGrid.Visibility = System.Windows.Visibility.Collapsed;
				return;
			}

			if (m_num_pages < 0)
				return;

			if (xaml_ContentList.Items.IsEmpty)
			{
				int size_content = mu_doc.ComputeContents();
				if (size_content == 0)
					return;
				xaml_ContentList.ItemsSource = mu_doc.contents;
			}
			xaml_ContentGrid.Visibility = System.Windows.Visibility.Visible;
		}

		private void ThumbSelected(object sender, MouseButtonEventArgs e)
		{
			var item = ((FrameworkElement)e.OriginalSource).DataContext as DocPage;
			if (item != null)
			{
				if (item.PageNum < 0)
					return;
				m_currpage = item.PageNum;
				xaml_PageList.ScrollIntoView(m_docPages[item.PageNum]);
			}
		}

		private void ContentSelected(object sender, MouseButtonEventArgs e)
		{
			var item = ((FrameworkElement)e.OriginalSource).DataContext as ContentItem;
			if (item != null && item.Page < m_num_pages)
			{
				m_currpage = m_docPages[item.Page].PageNum;
				xaml_PageList.ScrollIntoView(m_docPages[item.Page]);
			}
		}

		/* We need to avoid rendering due to size changes */
		private void ListViewScrollChanged(object sender, ScrollChangedEventArgs e)
		{
			var lv = (System.Windows.Controls.ListView)sender;
			foreach (var lvi in lv.Items)
			{
				var container = lv.ItemContainerGenerator.ContainerFromItem(lvi) as ListBoxItem;
				if (container != null && Visible(container, lv))
				{
					var found = container.Content;
					if (found != null)
					{
						var Item = (DocPage)found;
						m_currpage = Item.PageNum;
						RenderRange(Item.PageNum, false);
					}
					return;
				}
			}
		}

		/* Render +/- the look ahead from where we are if blank page is present */
		async private void RenderRange(int curr_page, bool scrollto)
		{
			int range = Constants.LOOK_AHEAD;

			for (int k = curr_page - range; k <= curr_page + range; k++)
			{
				if (k >= 0 && k < m_num_pages)
				{
					/* Check if page is already rendered */
					var doc = m_docPages[k];
					if (doc.Content != Page_Content_t.FULL_RESOLUTION ||
						doc.Zoom != m_doczoom)
					{
						Point ras_size;
						double scale_factor = m_doczoom;

						if (ComputePageSize(k, scale_factor, out ras_size) == status_t.S_ISOK)
						{
							try
							{
								Byte[] bitmap = new byte[(int)ras_size.X * (int)ras_size.Y * 4];

								Task<int> ren_task =
									new Task<int>(() => mu_doc.RenderPage(k, bitmap, (int)ras_size.X, (int)ras_size.Y, scale_factor, false, true));
								ren_task.Start();
								await ren_task.ContinueWith((antecedent) =>
								{
									status_t code = (status_t)ren_task.Result;
									if (code == status_t.S_ISOK)
									{
										UpdatePage(k, bitmap, ras_size, Page_Content_t.FULL_RESOLUTION, m_doczoom);
										m_docPages[k].PageRefresh();
										if (k == curr_page && scrollto)
											xaml_PageList.ScrollIntoView(m_docPages[k]);
									}
								}, TaskScheduler.FromCurrentSynchronizationContext());
							}
							catch (OutOfMemoryException e)
							{
								Console.WriteLine("Memory allocation failed page " + k + "\n");
								ShowMessage(NotifyType_t.MESS_ERROR, "Out of memory: " + e.Message);
							}
						}
					}
				}
			}
		}

		private bool Visible(FrameworkElement elem, FrameworkElement cont)
		{
			if (!elem.IsVisible)
				return false;
			Rect rect = new Rect(0.0, 0.0, cont.ActualWidth, cont.ActualHeight);
			Rect bounds = elem.TransformToAncestor(cont).TransformBounds(new Rect(0.0, 0.0, elem.ActualWidth, elem.ActualHeight));
			Rect bounds2 = new Rect(new Point(bounds.TopLeft.X, bounds.TopLeft.Y), new Point(bounds.BottomRight.X, bounds.BottomRight.Y - 5));
			return rect.Contains(bounds2.TopLeft) || rect.Contains(bounds2.BottomRight);
		}

		private void ReleasePages(int old_page, int new_page)
		{
			if (old_page == new_page) return;
			/* To keep from having memory issue reset the page back to
				the thumb if we are done rendering the thumbnails */
			for (int k = old_page - Constants.LOOK_AHEAD; k <= old_page + Constants.LOOK_AHEAD; k++)
			{
				if (k < new_page - Constants.LOOK_AHEAD || k > new_page + Constants.LOOK_AHEAD)
				{
					if (k >= 0 && k < m_num_pages)
					{
						SetThumb(k);
					}
				}
			}
		}

		/* Return this page from a full res image to the thumb image or only set
		   to thumb if it has not already been set */
		private void SetThumb(int page_num)
		{
			/* See what is there now */
			var doc = m_docPages[page_num];
			if (doc.Content == Page_Content_t.THUMBNAIL && doc.Zoom == m_doczoom) return;

			if (m_thumbnails.Count > page_num)
			{
				m_page_update = true;
				var thumb_page = m_thumbnails[page_num];
				thumb_page.Height = (int)(thumb_page.NativeHeight * m_doczoom);
				thumb_page.Width = (int)(thumb_page.NativeWidth * m_doczoom);
				thumb_page.Zoom = 1.0;
				m_docPages[page_num] = thumb_page;
				m_page_update = false;
			}
		}

		private void LinksToggle(object sender, RoutedEventArgs e)
		{

		}

		private void Search(object sender, RoutedEventArgs e)
		{

		}

		private void ZoomOut(object sender, RoutedEventArgs e)
		{
			m_doczoom = m_doczoom - Constants.ZOOM_STEP;
			if (m_doczoom < Constants.ZOOM_MIN)
				m_doczoom = Constants.ZOOM_MIN;
			xaml_ZoomSlider.Value = m_doczoom * 100.0;
			RenderRange(m_currpage, false);
		}

		private void ZoomIn(object sender, RoutedEventArgs e)
		{
			m_doczoom = m_doczoom + Constants.ZOOM_STEP;
			if (m_doczoom > Constants.ZOOM_MAX)
				m_doczoom = Constants.ZOOM_MAX;
			xaml_ZoomSlider.Value = m_doczoom * 100.0;
			RenderRange(m_currpage, false);
		}

		private void CancelSearchClick(object sender, RoutedEventArgs e)
		{

		}

		private void gsIO(object gsObject, String mess, int len)
		{
			m_gsoutput.Update(mess, len);
		}

		private void gsProgress(object gsObject, gsEventArgs asyncInformation)
		{
			if (asyncInformation.Completed)
			{
				xaml_DistillProgress.Value = 100;
				xaml_DistillGrid.Visibility = System.Windows.Visibility.Collapsed;
				if (asyncInformation.Params.result == GS_Result_t.gsFAILED)
				{
					switch (asyncInformation.Params.task)
					{
						case GS_Task_t.CREATE_XPS:
							ShowMessage(NotifyType_t.MESS_STATUS, "Ghostscript failed to create XPS");
							break;

						case GS_Task_t.PS_DISTILL:
							ShowMessage(NotifyType_t.MESS_STATUS, "Ghostscript failed to distill PS");
							break;

						case GS_Task_t.SAVE_RESULT:

							break;
					}
					return;
				}
				GSResult(asyncInformation.Params);
			}
			else
			{
				this.xaml_DistillProgress.Value = asyncInformation.Progress;
			}
		}

		/* GS Result*/
		public void GSResult(gsParams_t gs_result)
		{
			if (gs_result.result == GS_Result_t.gsCANCELLED)
			{
				xaml_DistillGrid.Visibility = System.Windows.Visibility.Collapsed;
				return;
			}
			switch (gs_result.task)
			{
				case GS_Task_t.CREATE_XPS:
					xaml_DistillGrid.Visibility = System.Windows.Visibility.Collapsed;
					PrintXPS(gs_result.outputfile);
					break;

				case GS_Task_t.PS_DISTILL:
					xaml_DistillGrid.Visibility = System.Windows.Visibility.Collapsed;
					OpenFile2(gs_result.outputfile);
					break;

				case GS_Task_t.SAVE_RESULT:
					break;
			}
		}

		/* Printing is achieved using xpswrite device in ghostscript and
		 * pushing that file through the XPS print queue */
		private void Print(object sender, RoutedEventArgs e)
		{
			if (!m_file_open)
				return;

			/* If file is already xps then gs need not do this */
			if (!m_isXPS)
			{
				xaml_DistillProgress.Value = 0;
				if (m_ghostscript.CreateXPS(m_currfile) == gsStatus.GS_BUSY)
				{
					ShowMessage(NotifyType_t.MESS_STATUS, "GS currently busy");
					return;
				}
				else
				{
					xaml_DistillGrid.Visibility = System.Windows.Visibility.Visible;
				}

			}
			PrintXPS(m_currfile);
		}

		private void PrintXPS(String file)
		{
			gsprint ghostprint = new gsprint();
			System.Windows.Controls.PrintDialog pDialog = ghostprint.GetPrintDialog();

			if (pDialog == null)
				return;

			XpsDocument xpsDocument = new XpsDocument(file, FileAccess.Read);
			FixedDocumentSequence fixedDocSeq = xpsDocument.GetFixedDocumentSequence();

			PrintQueue printQueue = pDialog.PrintQueue;

			m_ghostprint = ghostprint;
			xaml_PrintGrid.Visibility = System.Windows.Visibility.Visible;
			m_ghostprint.PrintUpdate += new gsprint.AsyncPrintCallBack(PrintProgress);

			xaml_PrintProgress.Value = 0;

			ghostprint.Print(printQueue, fixedDocSeq);
		}

		private void PrintProgress(object printHelper, gsPrintEventArgs asyncInformation)
		{
			if (asyncInformation.Completed)
			{
				xaml_PrintProgress.Value = 100;
				xaml_PrintGrid.Visibility = System.Windows.Visibility.Collapsed;
			}
			else
			{
				xaml_PrintProgress.Value = 100 * (double)asyncInformation.Page / (double)m_num_pages;
			}
		}

		private void CancelDistillClick(object sender, RoutedEventArgs e)
		{
			xaml_CancelDistill.IsEnabled = false;
			if (m_ghostscript != null)
				m_ghostscript.Cancel();
		}

		private void CancelPrintClick(object sender, RoutedEventArgs e)
		{
			m_ghostprint.CancelAsync();
		}

		private void ShowGSMessage(object sender, RoutedEventArgs e)
		{
			m_gsoutput.Show();
		}

		private void ConvertClick(object sender, RoutedEventArgs e)
		{
			if (m_convertwin == null)
			{
				m_convertwin = new Convert(m_num_pages);
				m_convertwin.Activate();
				m_convertwin.Show();
			}
		}

		private void GetPassword()
		{
			if (m_password == null)
			{
				m_password = new Password();
				m_password.PassUpdateMain += new Password.PassCallBackMain(PasswordReturn);
				m_password.Activate();
				m_password.Show();
			}
		}

		private void PasswordReturn(object sender)
		{
			if (mu_doc.ApplyPassword(m_password.xaml_Password.Password))
			{
				m_password.Close();
				m_password = null;
				StartViewer();
			}
			else
				ShowMessage(NotifyType_t.MESS_STATUS, "Password Incorrect");
		}

		private void ShowFooter(object sender, RoutedEventArgs e)
		{
			xaml_FooterControl.Visibility = System.Windows.Visibility.Visible;
		}

		private void HideFooter(object sender, RoutedEventArgs e)
		{
			xaml_FooterControl.Visibility = System.Windows.Visibility.Collapsed;
		}

		private void PageSelected(object sender, MouseButtonEventArgs e)
		{
			var item = ((FrameworkElement)e.OriginalSource).DataContext as DocPage;
			if (item != null)
			{
				if (item.PageNum < 0)
					return;
				m_currpage = item.PageNum;
				xaml_PageList.ScrollIntoView(m_docPages[item.PageNum]);
			}
		}

		private void ZoomReleased(object sender, MouseButtonEventArgs e)
		{
			if (m_init_done)
			{
				m_doczoom = xaml_ZoomSlider.Value / 100.0;
				RenderRange(m_currpage, false);
			}
		}

		/* If the zoom is not equalto 1 then set the zoom to 1 and scoll to this page */
		private void PageDoubleClick(object sender, MouseButtonEventArgs e)
		{
			if (m_doczoom != 1.0)
			{
				m_doczoom = 1.0;
				var item = ((FrameworkElement)e.OriginalSource).DataContext as DocPage;
				if (item != null)
				{
					m_currpage = item.PageNum;
					RenderRange(m_currpage, true);
				}
			}
		}
	}
}