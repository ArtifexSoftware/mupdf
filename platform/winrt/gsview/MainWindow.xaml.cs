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

enum PDFType_t
{
	PDFX,
	PDFA
}

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

/* Put all the PDF types first to make the switch statment shorter 
   Save_Type_t.PDF is the test */
public enum Save_Type_t
{
	PDF13,
	PDFA1_RGB,
	PDFA1_CMYK,
	PDFA2_RGB,
	PDFA2_CMYK,
	PDFX3_GRAY,
	PDFX3_CMYK,
	PDF,
	PCLXL,
	XPS,
	SVG,
	PCLBitmap,
	PNG,
	PWG,
	PNM,
	TEXT
}

public enum Extract_Type_t
{
	PDF,
	EPS,
	PS,
	SVG
}

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
	public const int DEFAULT_GS_RES = 300;
}


public static class DocumentTypes
{
	public const string PDF = "Portable Document Format";
	public const string PS = "PostScript";
	public const string XPS = "XPS";
	public const string EPS = "Encapsulated PostScript";
	public const string CBZ = "Comic Book Archive";
	public const string UNKNOWN = "Unknown";
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

	public struct searchResults_t
	{
		public String needle;
		public bool done;
		public int page_found;
		public List<Rect> rectangles;
		public int num_rects;
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
		List<RectList> m_text_list = null;
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
		String m_textcolor = "#402572AC";
		String m_linkcolor = "#40AC7225";
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
		BackgroundWorker m_textsearch = null;
		String m_document_type;
		Info m_infowindow;
		OutputIntent m_outputintents;
		Selection m_selection;
		private Point startPoint;
		private Rectangle rect;
		String m_prevsearch = null;

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
				m_linkset = new List<bool>();
				m_ghostscript = new ghostsharp();
				m_ghostscript.gsUpdateMain += new ghostsharp.gsCallBackMain(gsProgress);
				m_gsoutput = new gsOutput();
				m_gsoutput.Activate();
				m_outputintents = new OutputIntent();
				m_outputintents.Activate();
				m_ghostscript.gsIOUpdateMain += new ghostsharp.gsIOCallBackMain(gsIO);
				m_convertwin = null;
				m_selection = null;
			}
			catch (OutOfMemoryException e)
			{
				Console.WriteLine("Memory allocation failed at initialization\n");
				ShowMessage(NotifyType_t.MESS_ERROR, "Out of memory: " + e.Message);
			}
		}

		void Window_Closing(object sender, System.ComponentModel.CancelEventArgs e)
		{
			if (m_selection != null && m_selection.IsActive)
				m_selection.Close();
			m_gsoutput.RealWindowClosing();
			m_outputintents.RealWindowClosing();
		}

		void EnabletoPDF()
		{
			xaml_savepdf13.IsEnabled = true;
			xaml_savepdfa.IsEnabled = true;
			xaml_savepdfx3_cmyk.IsEnabled = true;
			xaml_savepdfx3_gray.IsEnabled = true;
			xaml_savepclxl.IsEnabled = true;
		}

		void DisabletoPDF()
		{
			xaml_savepdf13.IsEnabled = false;
			xaml_savepdfa.IsEnabled = false;
			xaml_savepdfx3_cmyk.IsEnabled = false;
			xaml_savepdfx3_gray.IsEnabled = false;
			xaml_savepclxl.IsEnabled = false;
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
			{
				m_text_list.Clear();
				m_text_list = null;
			}
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
			m_document_type = DocumentTypes.UNKNOWN;
			EnabletoPDF();
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

			if (m_infowindow != null && m_infowindow.IsActive)
				m_infowindow.Close();

			/* Check if gs is currently busy. If it is then don't allow a new
			 * file to be opened. They can cancel gs with the cancel button if
			 * they want */
			if (m_ghostscript.GetStatus() != gsStatus.GS_READY)
			{
				ShowMessage(NotifyType_t.MESS_STATUS, "GS busy. Cancel to open new file."); 
				return;
			}

			if (m_ghostprint != null && m_ghostprint.IsBusy())
			{
				ShowMessage(NotifyType_t.MESS_STATUS, "Let printing complete"); 
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
				/* We are doing this based on the extension but like should do
				 * it based upon the content */
				switch(extension.ToUpper())
				{
					case ".PS":
						m_document_type =  DocumentTypes.PS;
						break;
					case ".EPS":
						m_document_type =  DocumentTypes.EPS;
						break;
					case ".XPS":
						m_document_type =  DocumentTypes.XPS;
						break;
					case ".PDF":
						m_document_type =  DocumentTypes.PDF;
						break;
					case ".CBZ":
						m_document_type =  DocumentTypes.CBZ;
						break;
					default:
						m_document_type =  DocumentTypes.UNKNOWN;
						break;
				}
				if (extension.ToUpper() == ".PS" || extension.ToUpper() == ".EPS")
				{
					xaml_DistillProgress.Value = 0;
					if (m_ghostscript.DistillPS(dlg.FileName, Constants.DEFAULT_GS_RES) == gsStatus.GS_BUSY)
					{
						ShowMessage(NotifyType_t.MESS_STATUS, "GS currently busy");
						return;
					}
					xaml_DistillName.Text = "Distilling";
					xaml_CancelDistill.Visibility = System.Windows.Visibility.Visible;
					xaml_DistillName.FontWeight = FontWeights.Bold;
					xaml_DistillGrid.Visibility = System.Windows.Visibility.Visible;
					return;
				}
				/* Set if this is already xps for printing */
				if (extension.ToUpper() == ".XPS")
				{
					DisabletoPDF();
					m_isXPS = true;
				}
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
										if (m_docPages[k].TextBox != null)
											ScaleTextBox(k);
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
							ShowMessage(NotifyType_t.MESS_STATUS, "Ghostscript failed to convert document");
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
			if (gs_result.result == GS_Result_t.gsFAILED)
			{
				xaml_DistillGrid.Visibility = System.Windows.Visibility.Collapsed;
				ShowMessage(NotifyType_t.MESS_STATUS, "GS Failed Conversion");
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
					ShowMessage(NotifyType_t.MESS_STATUS, "GS Completed Conversion");
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
				if (m_ghostscript.CreateXPS(m_currfile, Constants.DEFAULT_GS_RES, m_num_pages) == gsStatus.GS_BUSY)
				{
					ShowMessage(NotifyType_t.MESS_STATUS, "GS currently busy");
					return;
				}
				else
				{
					/* Right now this is not possible to cancel due to the way 
					 * that gs is run for xpswrite from pdf */
					xaml_CancelDistill.Visibility = System.Windows.Visibility.Collapsed;
					xaml_DistillName.Text = "Convert to XPS";
					xaml_DistillName.FontWeight = FontWeights.Bold;
					xaml_DistillGrid.Visibility = System.Windows.Visibility.Visible;
				}
			} 
			else
				PrintXPS(m_currfile);
		}

		private void PrintXPS(String file)
		{
			gsprint ghostprint = new gsprint();
			System.Windows.Controls.PrintDialog pDialog = ghostprint.GetPrintDialog();

			if (pDialog == null)
				return;
			/* We have to create the XPS document on a different thread */
			XpsDocument xpsDocument = new XpsDocument(file, FileAccess.Read);
			FixedDocumentSequence fixedDocSeq = xpsDocument.GetFixedDocumentSequence();
			PrintQueue printQueue = pDialog.PrintQueue;

			m_ghostprint = ghostprint;
			xaml_PrintGrid.Visibility = System.Windows.Visibility.Visible;

			xaml_PrintProgress.Value = 0;

			ghostprint.Print(printQueue, fixedDocSeq);
		}

		private void PrintProgress(object printHelper, gsPrintEventArgs Information)
		{
			if (Information.Status != PrintStatus_t.PRINT_BUSY)
			{
				xaml_PrintProgress.Value = 100;
				xaml_PrintGrid.Visibility = System.Windows.Visibility.Collapsed;
			}
			else
			{
				xaml_PrintProgress.Value = 
					100.0 * (double) Information.Page / (double)m_num_pages;
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
			if (m_ghostscript.GetStatus() != gsStatus.GS_READY)
			{
				ShowMessage(NotifyType_t.MESS_STATUS, "GS busy");
				return;
			}

			if (m_convertwin == null || !m_convertwin.IsActive)
			{
				m_convertwin = new Convert(m_num_pages);
				m_convertwin.ConvertUpdateMain += new Convert.ConvertCallBackMain(ConvertReturn);
				m_convertwin.Activate();
				m_convertwin.Show();
			}
		}

		private void ConvertReturn(object sender)
		{
			if (m_ghostscript.GetStatus() != gsStatus.GS_READY)
			{
				ShowMessage(NotifyType_t.MESS_STATUS, "GS busy"); 
				return;
			}

			Device device = (Device)m_convertwin.xaml_DeviceList.SelectedItem;
			System.Collections.IList pages = m_convertwin.xaml_PageList.SelectedItems;
			System.Collections.IList pages_selected = null;
			String options = m_convertwin.xaml_options.Text;
			int resolution = 72;
			bool multi_page_needed = false;
			int first_page = -1;
			int last_page = -1;

			if (pages.Count == 0)
			{
				ShowMessage(NotifyType_t.MESS_STATUS, "No Pages Selected");
				return;
			}

			if (device == null)
			{
				ShowMessage(NotifyType_t.MESS_STATUS, "No Device Selected");
				return;
			}

			/* Get a filename */
			SaveFileDialog dlg = new SaveFileDialog();
			dlg.Filter = "All files (*.*)|*.*";
			dlg.FilterIndex = 1;
			if (dlg.ShowDialog() == System.Windows.Forms.DialogResult.OK)
			{
				if (!device.SupportsMultiPage && m_num_pages > 1)
					multi_page_needed = true;

				if (pages.Count != m_num_pages)
				{
					/* We may need to go through page by page. Determine if
					 * selection of pages is continuous.  This is done by 
					 * looking at the first one in the list and the last one
					 * in the list and checking the length */
					SelectPage lastpage = (SelectPage) pages[pages.Count -1];
					SelectPage firstpage = (SelectPage) pages[0];
					int temp = lastpage.Page - firstpage.Page + 1;
					if (temp == pages.Count)
					{
						/* Pages are contiguous.  Add first and last page 
						 * as command line option */
						options = options + " -dFirstPage=" + firstpage.Page + " -dLastPage=" + lastpage.Page;
						first_page = firstpage.Page;
						last_page = lastpage.Page;
					}
					else
					{
						/* Pages are not continguous.  We will do this page 
						 * by page.*/
						pages_selected = pages;
						multi_page_needed = true;  /* need to put in separate outputs */
					} 
				}
				xaml_DistillProgress.Value = 0;
				if (m_ghostscript.Convert(m_currfile, options,
					device.DeviceName, dlg.FileName, pages.Count, resolution,
					multi_page_needed, pages_selected, first_page, last_page,
					null, null) == gsStatus.GS_BUSY)
				{
					ShowMessage(NotifyType_t.MESS_STATUS, "GS busy");
					return;
				}
				xaml_DistillName.Text = "GS Converting Document";
				xaml_CancelDistill.Visibility = System.Windows.Visibility.Collapsed;
				xaml_DistillName.FontWeight = FontWeights.Bold;
				xaml_DistillGrid.Visibility = System.Windows.Visibility.Visible;
				m_convertwin.Close();
			}
			return;
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

		private void ShowInfo(object sender, RoutedEventArgs e)
		{
			String Message;

			if (m_file_open)
			{
				Message =
					"         File: " + m_currfile + "\n" +
					"Document Type: " + m_document_type + "\n" +
					"        Pages: " + m_num_pages + "\n" +
					" Current Page: " + (m_currpage + 1) + "\n";
				if (m_infowindow == null || !(m_infowindow.IsActive))
					m_infowindow = new Info();
				m_infowindow.xaml_TextInfo.Text = Message;
				m_infowindow.FontFamily = new FontFamily("Courier New");
				m_infowindow.Show();
			}
		}

		String CreatePDFXA(Save_Type_t type)
		{
			Byte[] Resource;
			String Profile;

			switch (type)
			{
				case Save_Type_t.PDFA1_CMYK:
				case Save_Type_t.PDFA2_CMYK:
					Resource = Properties.Resources.PDFA_def;
					Profile = m_outputintents.cmyk_icc;
					break;

				case Save_Type_t.PDFA1_RGB:
				case Save_Type_t.PDFA2_RGB:
					Resource = Properties.Resources.PDFA_def;
					Profile = m_outputintents.rgb_icc;
					break;

				case Save_Type_t.PDFX3_CMYK:
					Resource = Properties.Resources.PDFX_def;
					Profile = m_outputintents.cmyk_icc;
					break;

				case Save_Type_t.PDFX3_GRAY:
					Resource = Properties.Resources.PDFX_def;
					Profile = m_outputintents.gray_icc;
					break;

				default:
					return null;
			}

			String Profile_new = Profile.Replace("\\", "/");
			String result = System.Text.Encoding.UTF8.GetString(Resource);
			String pdfx_cust = result.Replace("ICCPROFILE", Profile_new);
			var out_file = System.IO.Path.GetTempFileName();
			System.IO.File.WriteAllText(out_file, pdfx_cust);
			return out_file;
		}

		private void SaveFile(Save_Type_t type)
		{
			if (!m_file_open)
				return;

			SaveFileDialog dlg = new SaveFileDialog();
			dlg.FilterIndex = 1;

			/* PDF output types */
			if (type <= Save_Type_t.PDF)
			{
				dlg.Filter = "PDF Files(*.pdf)|*.pdf";
				if (dlg.ShowDialog() == System.Windows.Forms.DialogResult.OK)
				{
					String options = null;
					bool use_gs = true;
					String init_file = CreatePDFXA(type);
					;
					switch (type)
					{
						case Save_Type_t.PDF:
							/* All done.  No need to use gs */
							System.IO.File.Copy(m_currfile, dlg.FileName, true);
							use_gs = false;
							break;
						case Save_Type_t.PDF13:
							options = "-dCompatibilityLevel=1.3";
							break;
						case Save_Type_t.PDFA1_CMYK:
							options = "-dPDFA=1 -dNOOUTERSAVE -dPDFACompatibilityPolicy=1 -sProcessColorModel=DeviceCMYK -dColorConversionStrategy=/CMYK -sOutputICCProfile=" + m_outputintents.cmyk_icc;
							break;
						case Save_Type_t.PDFA1_RGB:
							options = "-dPDFA=1 -dNOOUTERSAVE -dPDFACompatibilityPolicy=1 -sProcessColorModel=DeviceRGB -dColorConversionStrategy=/RGB -sOutputICCProfile=" + m_outputintents.rgb_icc;
							break;
						case Save_Type_t.PDFA2_CMYK:
							options = "-dPDFA=2 -dNOOUTERSAVE -dPDFACompatibilityPolicy=1 -sProcessColorModel=DeviceCMYK -dColorConversionStrategy=/CMYK -sOutputICCProfile=" + m_outputintents.cmyk_icc;
							break;
						case Save_Type_t.PDFA2_RGB:
							options = "-dPDFA=2 -dNOOUTERSAVE -dPDFACompatibilityPolicy=1 -sProcessColorModel=DeviceRGB -dColorConversionStrategy=/RGB -sOutputICCProfile=" + m_outputintents.rgb_icc;
							break;
						case Save_Type_t.PDFX3_CMYK:
							options = "-dPDFX -dNOOUTERSAVE -dPDFACompatibilityPolicy=1 -sProcessColorModel=DeviceCMYK -dColorConversionStrategy=/CMYK -sOutputICCProfile=" + m_outputintents.cmyk_icc;
							break;
						case Save_Type_t.PDFX3_GRAY:
							options = "-dPDFX -dNOOUTERSAVE -dPDFACompatibilityPolicy=1 -sProcessColorModel=DeviceGray -dColorConversionStrategy=/Gray -sOutputICCProfile=" + m_outputintents.cmyk_icc;
							break;

					}
					if (use_gs)
					{
						xaml_DistillProgress.Value = 0;
						if (m_ghostscript.Convert(m_currfile, options,
							Enum.GetName(typeof(gsDevice_t), gsDevice_t.pdfwrite),
							dlg.FileName, m_num_pages, 300, false, null, -1, -1,
							init_file, null) ==  gsStatus.GS_BUSY)
						{
							ShowMessage(NotifyType_t.MESS_STATUS, "GS busy");
							return;
						}
						xaml_DistillName.Text = "Creating PDF";
						xaml_CancelDistill.Visibility = System.Windows.Visibility.Collapsed;
						xaml_DistillName.FontWeight = FontWeights.Bold;
						xaml_DistillGrid.Visibility = System.Windows.Visibility.Visible;
					}
				}
			}
			else
			{
				/* Non PDF output */
				gsDevice_t Device = gsDevice_t.xpswrite;
				bool use_mupdf = true;
				switch (type)
				{
					case Save_Type_t.PCLBitmap:
						break;
					case Save_Type_t.PNG:
						break;
					case Save_Type_t.PWG:
						break;
					case Save_Type_t.SVG:
						break;
					case Save_Type_t.PCLXL:
						use_mupdf = false;
						dlg.Filter = "PCL-XL (*.bin)|*.bin";
						Device = gsDevice_t.pxlcolor;
						break;
					case Save_Type_t.TEXT:
						use_mupdf = false;
						dlg.Filter = "Text Files(*.txt)|*.txt";
						Device = gsDevice_t.txtwrite;
						break;
					case Save_Type_t.XPS:
						use_mupdf = false;
						dlg.Filter = "XPS Files(*.xps)|*.xps";
						break;
				}
				if (!use_mupdf)
				{
					if (dlg.ShowDialog() == System.Windows.Forms.DialogResult.OK)
					{
						if (m_ghostscript.Convert(m_currfile, "",
							Enum.GetName(typeof(gsDevice_t), Device),
							dlg.FileName, 1, 300, false, null, -1, -1,
							null, null) == gsStatus.GS_BUSY)
						{
							ShowMessage(NotifyType_t.MESS_STATUS, "GS busy");
							return;
						}
					}
				}
			}
		}

		private void SavePNG(object sender, RoutedEventArgs e)
		{
			SaveFile(Save_Type_t.PNG);
		}

		private void SavePWG(object sender, RoutedEventArgs e)
		{
			SaveFile(Save_Type_t.PWG);
		}

		private void SavePNM(object sender, RoutedEventArgs e)
		{
			SaveFile(Save_Type_t.PNM);
		}

		private void SaveSVG(object sender, RoutedEventArgs e)
		{
			SaveFile(Save_Type_t.SVG);
		}

		private void SavePCL(object sender, RoutedEventArgs e)
		{
			SaveFile(Save_Type_t.PCLBitmap);
		}

		private void SavePDF(object sender, RoutedEventArgs e)
		{
			SaveFile(Save_Type_t.PDF);
		}

		private void CopyPage(object sender, RoutedEventArgs e)
		{

		}

		private void PastePage(object sender, RoutedEventArgs e)
		{

		}

		private void SaveText(object sender, RoutedEventArgs e)
		{
			SaveFile(Save_Type_t.TEXT);
		}
		private void SavePDF13(object sender, RoutedEventArgs e)
		{
			SaveFile(Save_Type_t.PDF13);
		}
		private void SavePDFX3_Gray(object sender, RoutedEventArgs e)
		{
			if (m_outputintents.gray_icc == null)
			{
				ShowMessage(NotifyType_t.MESS_STATUS, "Set Gray Output Intent ICC Profile");
				return;
			}
			SaveFile(Save_Type_t.PDFX3_GRAY);
		}
		private void SavePDFX3_CMYK(object sender, RoutedEventArgs e)
		{
			if (m_outputintents.cmyk_icc == null)
			{
				ShowMessage(NotifyType_t.MESS_STATUS, "Set CMYK Output Intent ICC Profile");
				return;
			}
			SaveFile(Save_Type_t.PDFX3_CMYK);
		}
		private void SavePDFA1_RGB(object sender, RoutedEventArgs e)
		{
			if (m_outputintents.rgb_icc == null)
			{
				ShowMessage(NotifyType_t.MESS_STATUS, "Set RGB Output Intent ICC Profile");
				return;
			} 
			SaveFile(Save_Type_t.PDFA1_RGB);
		}

		private void SavePDFA1_CMYK(object sender, RoutedEventArgs e)
		{
			if (m_outputintents.cmyk_icc == null)
			{
				ShowMessage(NotifyType_t.MESS_STATUS, "Set CMYK Output Intent ICC Profile");
				return;
			} 
			SaveFile(Save_Type_t.PDFA1_CMYK);
		}

		private void SavePDFA2_RGB(object sender, RoutedEventArgs e)
		{
			if (m_outputintents.rgb_icc == null)
			{
				ShowMessage(NotifyType_t.MESS_STATUS, "Set RGB Output Intent ICC Profile");
				return;
			} 
			SaveFile(Save_Type_t.PDFA2_RGB);
		}

		private void SavePDFA2_CMYK(object sender, RoutedEventArgs e)
		{
			if (m_outputintents.cmyk_icc == null)
			{
				ShowMessage(NotifyType_t.MESS_STATUS, "Set CMYK Output Intent ICC Profile");
				return;
			} 
			SaveFile(Save_Type_t.PDFA2_CMYK);
		}

		private void SavePCLXL(object sender, RoutedEventArgs e)
		{
			SaveFile(Save_Type_t.PCLXL);
		}
		private void SaveXPS(object sender, RoutedEventArgs e)
		{
			SaveFile(Save_Type_t.XPS);
		}		
		private void Extract(Extract_Type_t type)
		{
			if (m_selection != null)
				return;

			m_selection = new Selection(m_currpage + 1, m_doczoom, type);
			m_selection.UpdateMain += new Selection.CallBackMain(SelectionMade);
			m_selection.Show();
			m_selection.xaml_Image.Source = m_docPages[m_currpage].BitMap;
			m_selection.xaml_Image.Height = m_docPages[m_currpage].Height;
			m_selection.xaml_Image.Width = m_docPages[m_currpage].Width;
		}

		async private void SelectionZoom(int page_num, double zoom)
		{
			Point ras_size;
			if (ComputePageSize(page_num, zoom, out ras_size) == status_t.S_ISOK)
			{
				try
				{
					Byte[] bitmap = new byte[(int)ras_size.X * (int)ras_size.Y * 4];

					Task<int> ren_task =
						new Task<int>(() => mu_doc.RenderPage(page_num, bitmap, (int)ras_size.X, (int)ras_size.Y, zoom, false, true));
					ren_task.Start();
					await ren_task.ContinueWith((antecedent) =>
					{
						status_t code = (status_t)ren_task.Result;
						if (code == status_t.S_ISOK)
						{
							if (m_selection != null)
							{
								int stride = (int) ras_size.X * 4;
								m_selection.xaml_Image.Source = BitmapSource.Create((int) ras_size.X, (int) ras_size.Y, 72, 72, PixelFormats.Pbgra32, BitmapPalettes.Halftone256, bitmap, stride);
								m_selection.xaml_Image.Height = (int)ras_size.Y;
								m_selection.xaml_Image.Width = (int)ras_size.X;
								m_selection.UpdateRect();
								m_selection.m_curr_state = SelectStatus_t.OK;
							}
						}
					}, TaskScheduler.FromCurrentSynchronizationContext());
				}
				catch (OutOfMemoryException e)
				{
					Console.WriteLine("Memory allocation failed page " + page_num + "\n");
					ShowMessage(NotifyType_t.MESS_ERROR, "Out of memory: " + e.Message);
				}
			}
		}
		private void SelectionMade(object gsObject, SelectEventArgs results)
		{
			switch (results.State)
			{
				case SelectStatus_t.CANCEL:
				case SelectStatus_t.CLOSE:
					m_selection = null;
					return;
				case SelectStatus_t.SELECT:
					/* Get the information we need */
					double zoom = results.ZoomFactor;
					Point start = results.TopLeft;
					Point size = results.Size;
					int page = results.PageNum;
					gsDevice_t Device = gsDevice_t.pdfwrite;

					start.X = start.X / zoom;
					start.Y = start.Y / zoom;
					size.X = size.X / zoom;
					size.Y = size.Y / zoom;

					/* Do the actual extraction */
					String options;
					SaveFileDialog dlg = new SaveFileDialog();
					dlg.FilterIndex = 1;

					/* Get us set up to do a fixed size */
					options = "-dFirstPage=" + page + " -dLastPage=" + page +
						" -dDEVICEWIDTHPOINTS=" + size.X + " -dDEVICEHEIGHTPOINTS=" +
						size.Y + " -dFIXEDMEDIA";

					/* Set up the translation */
					String init_string = "<</Install {-" + start.X + " -" +
						start.Y + " translate (testing) == flush}>> setpagedevice";

					switch (results.Type)
					{
						case Extract_Type_t.PDF:
							dlg.Filter = "PDF Files(*.pdf)|*.pdf";
							break;
						case Extract_Type_t.EPS:
							dlg.Filter = "EPS Files(*.eps)|*.eps";
							Device = gsDevice_t.eps2write;
							break;
						case Extract_Type_t.PS:
							dlg.Filter = "PostScript Files(*.ps)|*.ps";
							Device = gsDevice_t.ps2write;
							break;
						case Extract_Type_t.SVG:
							dlg.Filter = "SVG Files(*.svg)|*.svg";
							break;
					}
					if (dlg.ShowDialog() == System.Windows.Forms.DialogResult.OK)
					{
						if (m_ghostscript.Convert(m_currfile, options,
							Enum.GetName(typeof(gsDevice_t), Device),
							dlg.FileName, 1, 300, false, null, page, page,
							null, init_string) == gsStatus.GS_BUSY)
						{
							ShowMessage(NotifyType_t.MESS_STATUS, "GS busy");
							return;
						}
					}
					m_selection.Close();
					break;
				case SelectStatus_t.ZOOMIN:
					/* Render new page at this resolution and hand it off */
					SelectionZoom(results.PageNum - 1, results.ZoomFactor);
					break;
				case SelectStatus_t.ZOOMOUT:
					/* Render new page at this resolution and hand it off */
					SelectionZoom(results.PageNum - 1, results.ZoomFactor);
					break;
			}
		}

		private void ExtractPDF(object sender, RoutedEventArgs e)
		{
			Extract(Extract_Type_t.PDF);
		}
		private void ExtractEPS(object sender, RoutedEventArgs e)
		{
			Extract(Extract_Type_t.EPS);
		}
		private void ExtractPS(object sender, RoutedEventArgs e)
		{
			Extract(Extract_Type_t.PS);
		}
		private void ExtractSVG(object sender, RoutedEventArgs e)
		{
			Extract(Extract_Type_t.SVG);
		}
		private void OutputIntents(object sender, RoutedEventArgs e)
		{
			m_outputintents.Show();
		}

		/* Search related code */
		private void Search(object sender, RoutedEventArgs e)
		{
			if (!m_init_done || (m_textsearch != null && m_textsearch.IsBusy))
				return;

			m_textsearch = null; /* Start out fresh */
			if (xaml_SearchControl.Visibility == System.Windows.Visibility.Collapsed)
				xaml_SearchControl.Visibility = System.Windows.Visibility.Visible;
			else
			{
				xaml_SearchControl.Visibility = System.Windows.Visibility.Collapsed;
				ClearTextSearch();
			}
		}

		private void OnSearchBackClick(object sender, RoutedEventArgs e)
		{
			String textToFind = xaml_SearchText.Text;
			TextSearchSetUp(-1, textToFind);
		}

		private void OnSearchForwardClick(object sender, RoutedEventArgs e)
		{
			String textToFind = xaml_SearchText.Text;
			TextSearchSetUp(1, textToFind);
		}

		/* The thread that is actually doing the search work */
		void SearchWork(object sender, DoWorkEventArgs e)
		{
			BackgroundWorker worker = sender as BackgroundWorker;
			List<object> genericlist = e.Argument as List<object>;
			int direction = (int) genericlist[0];
			String needle = (String) genericlist[1];
			/* To make sure we get the next page or current page during search */
			int in_search = (int)genericlist[2];
			m_searchpage = m_currpage + direction * in_search;
			searchResults_t results = new searchResults_t();

			/* Break if we find something, get to the end (or start of doc) 
			 * or if we have a cancel occur */
			while (true)
			{
				int box_count = mu_doc.TextSearchPage(m_searchpage, needle);
				int percent;

				if (direction == 1)
					percent = (int)(100.0 * ((double)m_searchpage + 1) / (double)m_num_pages);
				else
					percent = 100 - (int)(100.0 * ((double)m_searchpage) / (double)m_num_pages);

				if (box_count > 0)
				{
					/* This page has something lets go ahead and extract and 
					 * signal to the UI thread and end this thread */
					results.done = false;
					results.num_rects = box_count;
					results.page_found = m_searchpage;
					results.rectangles = new List<Rect>();

					for (int kk = 0; kk < box_count; kk++ )
					{
						Point top_left;
						Size size;
						mu_doc.GetTextSearchItem(kk, out top_left, out size);
						var rect = new Rect(top_left, size);
						results.rectangles.Add(rect);
					}
					worker.ReportProgress(percent, results);
					break;
				}
				else
				{
					/* This page has nothing.  Lets go ahead and just update
					 * the progress bar */
					worker.ReportProgress(percent, null);
					if (percent >= 100)
					{
						results.done = true;
						results.needle = needle;
						break;
					}
					m_searchpage = m_searchpage + direction;
				}
				if (worker.CancellationPending == true)
				{
					e.Cancel = true;
					break;
				}
			}
			e.Result = results;
		}

		private void SearchProgressChanged(object sender, ProgressChangedEventArgs e)
		{
			if (e.UserState == null)
			{
				/* Nothing found */
				xaml_SearchProgress.Value = e.ProgressPercentage;
			} 
			else
			{
				m_text_list = new List<RectList>();
				/* found something go to page and show results */
				searchResults_t results = (searchResults_t)e.UserState;
				xaml_SearchProgress.Value = e.ProgressPercentage;
				m_currpage = results.page_found;
				/* Add in the rectangles */
				for (int kk = 0; kk < results.num_rects; kk++)
				{
					var rect_item = new RectList();
					rect_item.Scale = m_doczoom;
					rect_item.Color = m_textcolor;
					rect_item.Height = results.rectangles[kk].Height * m_doczoom;
					rect_item.Width = results.rectangles[kk].Width * m_doczoom;
					rect_item.X = results.rectangles[kk].X * m_doczoom;
					rect_item.Y = results.rectangles[kk].Y * m_doczoom;
					rect_item.Index = kk.ToString();
					m_text_list.Add(rect_item);
				}
				m_docPages[results.page_found].TextBox = m_text_list;
				m_docPages[results.page_found].PageRefresh();
				xaml_PageList.ScrollIntoView(m_docPages[results.page_found]);
			}
		}
		
		private void SearchCompleted(object sender, RunWorkerCompletedEventArgs e)
		{
			if (e.Cancelled == true)
			{
				xaml_SearchGrid.Visibility = System.Windows.Visibility.Collapsed;
				m_textsearch = null;
			}
			else
			{
				searchResults_t results = (searchResults_t) e.Result;
				if (results.done == true)
				{
					xaml_SearchGrid.Visibility = System.Windows.Visibility.Collapsed;
					m_textsearch = null;
					ShowMessage(NotifyType_t.MESS_STATUS, "End of document search for \"" + results.needle + "\"");
				}
			}
		}

		private void CancelSearchClick(object sender, RoutedEventArgs e)
		{
			if (m_textsearch != null && m_textsearch.IsBusy)
				m_textsearch.CancelAsync();
			xaml_SearchGrid.Visibility = System.Windows.Visibility.Collapsed;
			m_textsearch = null;
			ClearTextSearch();
		}

		private void ClearTextSearch()
		{
			for (int kk = 0; kk < m_num_pages; kk++)
			{
				var temp = m_docPages[kk].TextBox;
				if (temp != null)
				{
					m_docPages[kk].TextBox = null;
					m_docPages[kk].PageRefresh();
				}
			}
		}

		private void ScaleTextBox(int pagenum)
		{
			var temp = m_docPages[pagenum].TextBox;
			for (int kk = 0; kk < temp.Count; kk++)
			{
				var rect_item = temp[kk];
				double factor = m_doczoom / temp[kk].Scale;

				temp[kk].Height = temp[kk].Height * factor;
				temp[kk].Width = temp[kk].Width * factor;
				temp[kk].X = temp[kk].X * factor;
				temp[kk].Y = temp[kk].Y * factor;

				temp[kk].Scale = m_doczoom;
				temp[kk].PageRefresh();
			}
			m_docPages[pagenum].TextBox = temp;
		}

		private void TextSearchSetUp(int direction, String needle)
		{
			/* Create background task for performing text search. */
			try
			{
				int in_text_search = 0;

				if (m_textsearch != null && m_textsearch.IsBusy)
					return;

				if (m_textsearch != null)
				{
					in_text_search = 1;
					m_textsearch = null;
				}

				if (m_prevsearch != null && needle != m_prevsearch)
				{
					in_text_search = 0;
					ClearTextSearch();
				}

				if (m_textsearch == null)
				{
					m_prevsearch = needle;
					m_textsearch = new BackgroundWorker();
					m_textsearch.WorkerReportsProgress = true;
					m_textsearch.WorkerSupportsCancellation = true;
					var arguments = new List<object>();
					arguments.Add(direction);
					arguments.Add(needle);
					arguments.Add(in_text_search);
					m_textsearch.DoWork += new DoWorkEventHandler(SearchWork);
					m_textsearch.RunWorkerCompleted += new RunWorkerCompletedEventHandler(SearchCompleted);
					m_textsearch.ProgressChanged += new ProgressChangedEventHandler(SearchProgressChanged);
					xaml_SearchGrid.Visibility = System.Windows.Visibility.Visible;
					m_textsearch.RunWorkerAsync(arguments);
				}
			}
			catch (OutOfMemoryException e)
			{
				Console.WriteLine("Memory allocation failed during text search\n");
				ShowMessage(NotifyType_t.MESS_ERROR, "Out of memory: " + e.Message);
			}
		}
	}
}