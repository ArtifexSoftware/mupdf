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
using System.Runtime.InteropServices;
using Microsoft.Win32; /* For registry */

public enum AA_t
{
	HIGH = 8,
	MEDHIGH = 6,
	MED = 4,
	LOW = 2,
	NONE = 0
}

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

public enum textout_t
{
	HTML = 0,
	XML,
	TEXT
}

enum zoom_t
{
	NO_ZOOM,
	ZOOM_IN,
	ZOOM_OUT
}

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
	OLD_RESOLUTION,
	NOTSET
};

/* Put all the PDF types first to make the switch statment shorter 
   Save_Type_t.PDF is the test */
public enum Save_Type_t
{
	PDF13,
	LINEAR_PDF,
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
	TEXT,
	HTML,
	XML
}

public enum Extract_Type_t
{
	PDF,
	EPS,
	PS,
	SVG
}

/* C# has no defines.... */
static class Constants
{
	public const int SCROLL_STEPSIZE = 48;
	public const int INIT_LOOK_AHEAD = 2;  /* A + count on the pages to pre-render */
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
	public const int DISPATCH_TIME = 50;
	public const int SCROLL_STEP = 10;
	public const int SCROLL_EDGE_BUFFER = 90;
	public const int VERT_SCROLL_STEP = 48;
	public const int PAGE_MARGIN = 1;
}

public static class DocumentTypes
{
	public const string PDF = "Portable Document Format";
	public const string PS = "PostScript";
	public const string XPS = "XPS";
	public const string EPS = "Encapsulated PostScript";
	public const string CBZ = "Comic Book Archive";
	public const string PNG = "Portable Network Graphics Image";
	public const string JPG = "Joint Photographic Experts Group Image";
	public const string UNKNOWN = "Unknown";
}

namespace gsview
{
	/// <summary>
	/// Interaction logic for MainWindow.xaml
	/// </summary>
	/// 

	public struct pageprogress_t
	{
		public Byte[] bitmap;
		public BlocksText charlist;
		public int pagenum;
		public Point size;
		public Annotate_t annot;
	}

	public struct ContextMenu_t
	{
		public int page_num;
		public Point mouse_position;
	}

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

	public struct textSelectInfo_t
	{
		public int pagenum;
		public bool first_line_full;
		public bool last_line_full;
	}

	public static class ScrollBarExtensions
	{
		public static double GetThumbCenter(this System.Windows.Controls.Primitives.ScrollBar s)
		{
			double thumbLength = GetThumbLength(s);
			double trackLength = s.Maximum - s.Minimum;

			return thumbLength / 2 + s.Minimum + (s.Value - s.Minimum) *
				(trackLength - thumbLength) / trackLength;
		}

		public static void SetThumbCenter(this System.Windows.Controls.Primitives.ScrollBar s, double thumbCenter)
		{
			double thumbLength = GetThumbLength(s);
			double trackLength = s.Maximum - s.Minimum;

			if (thumbCenter >= s.Maximum - thumbLength / 2)
			{
				s.Value = s.Maximum;
			}
			else if (thumbCenter <= s.Minimum + thumbLength / 2)
			{
				s.Value = s.Minimum;
			}
			else if (thumbLength >= trackLength)
			{
				s.Value = s.Minimum;
			}
			else
			{
				s.Value = (int)(s.Minimum + trackLength *
					((thumbCenter - s.Minimum - thumbLength / 2)
					/ (trackLength - thumbLength)));
			}
		}

		public static double GetThumbLength(this System.Windows.Controls.Primitives.ScrollBar s)
		{
			double trackLength = s.Maximum - s.Minimum;
			return trackLength * s.ViewportSize /
				(trackLength + s.ViewportSize);
		}

		public static void SetThumbLength(this System.Windows.Controls.Primitives.ScrollBar s, double thumbLength)
		{
			double trackLength = s.Maximum - s.Minimum;

			if (thumbLength < 0)
			{
				s.ViewportSize = 0;
			}
			else if (thumbLength < trackLength)
			{
				s.ViewportSize = trackLength * thumbLength / (trackLength - thumbLength);
			}
			else
			{
				s.ViewportSize = double.MaxValue;
			}
		}
	}

	public partial class MainWindow : Window
	{
		mudocument mu_doc = null;
		public Pages m_docPages;
		List<textSelectInfo_t> m_textSelect;
		List<DocPage> m_thumbnails;
		List<List<RectList>> m_page_link_list = null;
		IList<RectList> m_text_list;
		public List<LinesText> m_lineptrs = null;
		public List<BlocksText> m_textptrs = null;
		List<Boolean> m_textset = null;
		private bool m_file_open;
		private int m_currpage;
		private int m_searchpage;
		private int m_num_pages;
		private bool m_init_done;
		private bool m_links_on;
		String m_textsearchcolor = "#4072AC25";
		String m_textselectcolor = "#402572AC";
		String m_regionselect = "#00FFFFFF";
		String m_blockcolor = "#00FFFFFF";
		//String m_regionselect = "#FFFF0000";  /* Debug */
		String m_linkcolor = "#40AC7225";
		private bool m_have_thumbs;
		double m_doczoom;
		ghostsharp m_ghostscript;
		String m_currfile;
		String m_origfile;
		private gsprint m_ghostprint = null;
		bool m_isXPS;
		gsOutput m_gsoutput;
		Convert m_convertwin;
		PageExtractSave m_extractwin;
		Password m_password = null;
		String m_currpassword = null;
		BackgroundWorker m_thumbworker = null;
		BackgroundWorker m_textsearch = null;
		BackgroundWorker m_linksearch = null;
		BackgroundWorker m_openfile = null;
		BackgroundWorker m_initrender = null;
		BackgroundWorker m_copytext = null;
		String m_document_type;
		Info m_infowindow;
		OutputIntent m_outputintents;
		Selection m_selection;
		String m_prevsearch = null;
		bool m_clipboardset;
		bool m_doscroll;
		bool m_intxtselect;
		bool m_textselected;
		System.Windows.Threading.DispatcherTimer m_dispatcherTimer = null;
		double m_lastY;
		double m_maxY;
		bool m_ignorescrollchange;
		double m_totalpageheight;
		AA_t m_AA;
		bool m_regstartup;
		int m_initpage;
		bool m_selectall;
		bool m_showannot;
		bool m_ScrolledChanged;

		public MainWindow()
		{
			InitializeComponent();
			this.Closing += new System.ComponentModel.CancelEventHandler(Window_Closing);
			m_file_open = false;
			m_regstartup = true;
			m_showannot = true;

			/* Allocations and set up */
			try
			{
				m_docPages = new Pages();
				m_thumbnails = new List<DocPage>();
				m_lineptrs = new List<LinesText>();
				m_textptrs = new List<BlocksText>();
				m_textset = new List<Boolean>();
				m_ghostscript = new ghostsharp();
				m_ghostscript.gsUpdateMain += new ghostsharp.gsCallBackMain(gsProgress);
				m_gsoutput = new gsOutput();
				m_gsoutput.Activate();
				m_outputintents = new OutputIntent();
				m_outputintents.Activate();
				m_ghostscript.gsIOUpdateMain += new ghostsharp.gsIOCallBackMain(gsIO);
				m_ghostscript.gsDLLProblemMain += new ghostsharp.gsDLLProblem(gsDLL);
				m_convertwin = null;
				m_extractwin = null;
				m_selection = null;
				xaml_ZoomSlider.AddHandler(MouseLeftButtonUpEvent, new MouseButtonEventHandler(ZoomReleased), true);
				xaml_PageList.AddHandler(Grid.DragOverEvent, new System.Windows.DragEventHandler(Grid_DragOver), true);
				xaml_PageList.AddHandler(Grid.DropEvent, new System.Windows.DragEventHandler(Grid_Drop), true);
				DimSelections();
				status_t result = CleanUp();

				string[] arguments = Environment.GetCommandLineArgs();
				if (arguments.Length > 1)
				{
					string filePath = arguments[1];
					ProcessFile(filePath);
				}
				else
				{
					if (m_regstartup)
						InitFromRegistry();
				}
			}
			catch (OutOfMemoryException e)
			{
				Console.WriteLine("Memory allocation failed at initialization\n");
				ShowMessage(NotifyType_t.MESS_ERROR, "Out of memory: " + e.Message);
			}
		}

		private void Grid_DragOver(object sender, System.Windows.DragEventArgs e)
		{
			if (e.Data.GetDataPresent(System.Windows.DataFormats.FileDrop))
			{
				e.Effects = System.Windows.DragDropEffects.All;
			}
			else
			{
				e.Effects = System.Windows.DragDropEffects.None;
			}
			e.Handled = false;
		}

		private void Grid_Drop(object sender, System.Windows.DragEventArgs e)
		{
			if (e.Data.GetDataPresent(System.Windows.DataFormats.FileDrop))
			{
				string[] docPath = (string[]) e.Data.GetData(System.Windows.DataFormats.FileDrop);
				ProcessFile(String.Join("",docPath));
			}
		}

		void CloseExtraWindows(bool shutdown)
		{
			if (m_selection != null)
				m_selection.Close();
			if (m_convertwin != null)
				m_convertwin.Close();
			if (m_extractwin != null)
				m_extractwin.Close();
			if (m_infowindow != null)
				m_infowindow.Close();
			if (shutdown)
			{
				if (m_gsoutput != null)
					m_gsoutput.RealWindowClosing();
				if (m_outputintents != null)
					m_outputintents.RealWindowClosing();
			}
			else
			{
				if (m_gsoutput != null)
					m_gsoutput.Hide();
				if (m_outputintents != null)
					m_outputintents.Hide();
			}
		}

		void Window_Closing(object sender, System.ComponentModel.CancelEventArgs e)
		{
			CloseExtraWindows(true);
		}

		/* Stuff not enabled when source is XPS */
		void EnabletoPDF()
		{
			xaml_savepdf.IsEnabled = true;
			xaml_linearize_pdf.IsEnabled = true;
			xaml_saveas.IsEnabled = true;
			xaml_Extract.IsEnabled = true;
			xaml_conversions.IsEnabled = true;
			xaml_extractselection.IsEnabled = true;
		}

		void DisabletoPDF()
		{
			xaml_savepdf.IsEnabled = false;
			xaml_linearize_pdf.IsEnabled = false;
			xaml_saveas.IsEnabled = false;
			xaml_Extract.IsEnabled = false;
			xaml_conversions.IsEnabled = false;
			xaml_extractselection.IsEnabled = false;
		}

		private void DimSelections()
		{
			xaml_currPage.Text = "";
			xaml_TotalPages.Text = "/ 0";
			xaml_Zoomsize.Text = "100";
			xaml_BackPage.Opacity = 0.5;
			xaml_Contents.Opacity = 0.5;
			xaml_currPage.Opacity = 0.5;
			xaml_currPage.IsEnabled = false;
			xaml_ForwardPage.Opacity = 0.5;
			xaml_Links.Opacity = 0.5;
			xaml_Print.Opacity = 0.5;
			xaml_SavePDF.Opacity = 0.5;
			xaml_Search.Opacity = 0.5;
			xaml_Thumbs.Opacity = 0.5;
			xaml_TotalPages.Opacity = 0.5;
			xaml_zoomIn.Opacity = 0.5;
			xaml_zoomOut.Opacity = 0.5;
			xaml_Zoomsize.Opacity = 0.5;
			xaml_ExpandFill.Opacity = 0.5;
			xaml_ContScrollFill.Opacity = 0.5;
			xaml_ActualSize.Opacity = 0.5;
			xaml_Zoomsize.IsEnabled = false;
			xaml_ZoomSlider.Opacity = 0.5;
			xaml_ZoomSlider.IsEnabled = false;
			xaml_saveas.IsEnabled = false;
			xaml_closefile.IsEnabled = false;
			xaml_showinfo.IsEnabled = false;
			xaml_extractselection.IsEnabled = false;
			xaml_conversions.IsEnabled = false;
			xaml_gsmessage.IsEnabled = false;
			xaml_print.IsEnabled = false;
			xaml_view.IsEnabled = false;
			xaml_edit.IsEnabled = false;
		}

		private status_t CleanUp()
		{
			m_init_done = false;
			this.Cursor = System.Windows.Input.Cursors.Arrow;
			/* Collapse this stuff since it is going to be released */
			xaml_ThumbGrid.Visibility = System.Windows.Visibility.Collapsed;
			xaml_ContentGrid.Visibility = System.Windows.Visibility.Collapsed;
			xaml_VerticalScroll.Visibility = System.Windows.Visibility.Collapsed;

			/* Clear out everything */
			if (m_docPages != null && m_docPages.Count > 0)
				m_docPages.Clear();
			if (m_textSelect != null)
				m_textSelect.Clear();
			if (m_textset != null)
				m_textset.Clear();
			if (m_lineptrs != null && m_lineptrs.Count > 0)
				m_lineptrs.Clear();
			if (m_thumbnails != null && m_thumbnails.Count > 0)
				m_thumbnails.Clear();
			if (m_textptrs != null && m_textptrs.Count > 0)
				m_textptrs.Clear();
			if (m_page_link_list != null && m_page_link_list.Count > 0)
			{
				m_page_link_list.Clear();
				m_page_link_list = null;
			}
			if (m_text_list != null && m_text_list.Count > 0)
			{
				m_text_list.Clear();
				m_text_list = null;
			}
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
			mu_doc.mupdfDLLProblemMain += new mudocument.mupdfDLLProblem(muDLL);
			status_t result = mu_doc.Initialize();
			mu_doc.mupdfUpdateMain += new mudocument.mupdfCallBackMain(mupdfUpdate);

			if (result != status_t.S_ISOK)
			{
				Console.WriteLine("Library allocation failed during clean up\n");
				ShowMessage(NotifyType_t.MESS_ERROR, "Library allocation failed!");
				return result;
			}

			m_have_thumbs = false;
			m_file_open = false;
			m_num_pages = -1;
			m_links_on = false;
			m_doczoom = 1.0;
			m_isXPS = false;
			//xaml_CancelThumb.IsEnabled = true;
			m_currpage = 0;
			m_ignorescrollchange = false;
			m_document_type = DocumentTypes.UNKNOWN;
			EnabletoPDF();
			m_clipboardset = false;
			m_doscroll = false;
			m_intxtselect = false;
			m_textselected = false;
			m_currpassword = null;
			CloseExtraWindows(false);
			ResetScroll();
			m_totalpageheight = 0;
			m_AA = GetAA();
			m_origfile = null;
			m_initpage = 0;
			xaml_Zoomsize.Text = "100";
			m_selectall = false;
			return result;
		}

		/* Initialize from registry */
		private void InitFromRegistry()
		{
			RegistryKey key = Registry.CurrentUser.CreateSubKey("Software");
			RegistryKey keyA = key.CreateSubKey("Artifex Software");
			RegistryKey keygs = keyA.CreateSubKey("GSview 6.0");
			String filepath = null;
			Int32 page;
			AA_t aa = AA_t.HIGH;

			try
			{
				filepath = (String)keygs.GetValue("File", null);
				aa = (AA_t)keygs.GetValue("AA");
				page = (Int32)keygs.GetValue("Page");
			}
			catch
			{
				return;
			}
			keygs.Close();
			keyA.Close();
			key.Close();

			SetAA(aa);
			m_AA = aa;

			if (filepath != null && File.Exists(filepath))
			{
				m_initpage = page;
				ProcessFile(filepath);
			}
			else
				m_initpage = 0;
		}

		private void SetRegistry()
		{
			if (m_currfile == null)
				return;

			RegistryKey key = Registry.CurrentUser.CreateSubKey("Software");
			RegistryKey keyA = key.CreateSubKey("Artifex Software");
			RegistryKey keygs = keyA.CreateSubKey("GSview 6.0");

			if (m_origfile != null && (m_document_type == DocumentTypes.PS ||
				m_document_type == DocumentTypes.EPS))
			{
				keygs.SetValue("File", m_origfile, RegistryValueKind.String);
			}
			else
			{
				keygs.SetValue("File", m_currfile, RegistryValueKind.String);
			}
			keygs.SetValue("Page", m_currpage, RegistryValueKind.DWord);
			Int32 aa_int = (Int32)m_AA;
			keygs.SetValue("AA", aa_int, RegistryValueKind.DWord);
			keygs.Close();
			keyA.Close();
			key.Close();
		}

		private void AppClosing(object sender, CancelEventArgs e)
		{
			if (m_init_done)
				SetRegistry();
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

		private void CloseCommand(object sender, ExecutedRoutedEventArgs e)
		{
			if (m_init_done)
				CloseDoc();
		}

		private void CloseDoc()
		{
			CleanUp();
		}

		/* Set the page with the new raster information */
		private void UpdatePage(int page_num, Byte[] bitmap, Point ras_size,
			Page_Content_t content, double zoom_in, AA_t AA)
		{
			DocPage doc_page = this.m_docPages[page_num];

			doc_page.Width = (int)ras_size.X;
			doc_page.Height = (int)ras_size.Y;

			doc_page.Content = content;
			doc_page.Zoom = zoom_in;

			int stride = doc_page.Width * 4;
			doc_page.BitMap = BitmapSource.Create(doc_page.Width, doc_page.Height, 
				72, 72, PixelFormats.Pbgra32, BitmapPalettes.Halftone256, bitmap, stride);
			doc_page.PageNum = page_num;
			doc_page.AA = AA;

			if (content == Page_Content_t.THUMBNAIL)
			{
				doc_page.Width = (int)(ras_size.X / Constants.SCALE_THUMB);
				doc_page.Height = (int)(ras_size.Y / Constants.SCALE_THUMB);
			}
		}

		private void OpenFileCommand(object sender, ExecutedRoutedEventArgs e)
		{
			OpenFile(sender, e);
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

			System.Windows.Forms.OpenFileDialog dlg = new System.Windows.Forms.OpenFileDialog();
			dlg.Filter = "Document Files(*.ps;*.eps;*.pdf;*.xps;*.oxps;*.cbz;*.png;*.jpg;*.jpeg)|*.ps;*.eps;*.pdf;*.xps;*.oxps;*.cbz;*.png;*.jpg;*.jpeg|All files (*.*)|*.*";
			dlg.FilterIndex = 1;
			if (dlg.ShowDialog() == System.Windows.Forms.DialogResult.OK)
				ProcessFile(dlg.FileName);
		}

		private void ProcessFile(String FileName)
		{
			if (m_file_open)
			{
				CloseDoc();
			}
			/* If we have a ps or eps file then launch the distiller first
			 * and then we will get a temp pdf file which will be opened by
			 * mupdf */
			string extension = System.IO.Path.GetExtension(FileName);
			/* We are doing this based on the extension but like should do
			 * it based upon the content */
			switch (extension.ToUpper())
			{
				case ".PS":
					m_document_type = DocumentTypes.PS;
					break;
				case ".EPS":
					m_document_type = DocumentTypes.EPS;
					break;
				case ".XPS":
				case ".OXPS":
					m_document_type = DocumentTypes.XPS;
					break;
				case ".PDF":
					m_document_type = DocumentTypes.PDF;
					break;
				case ".CBZ":
					m_document_type = DocumentTypes.CBZ;
					break;
				case ".PNG":
					m_document_type = DocumentTypes.PNG;
					break;
				case ".JPG":
					m_document_type = DocumentTypes.JPG;
					break;
				case ".JPEG":
					m_document_type = DocumentTypes.JPG;
					break;
				default:
					{
						ShowMessage(NotifyType_t.MESS_STATUS, "Unknown File Type");
						return;
					}
			}
			if (extension.ToUpper() == ".PS" || extension.ToUpper() == ".EPS")
			{
				xaml_DistillProgress.Value = 0;
				if (m_ghostscript.DistillPS(FileName, Constants.DEFAULT_GS_RES) == gsStatus.GS_BUSY)
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
			if (extension.ToUpper() == ".XPS" || extension.ToUpper() == ".OXPS")
				m_isXPS = true;
			OpenFile2(FileName);
		}

		private void OpenFile2(String File)
		{
			m_currfile = File;
			xaml_OpenProgressGrid.Visibility = System.Windows.Visibility.Visible;
			xaml_openfilestatus.Text = "Opening File";
		/* The file open can take a fair amount of time. So that we can show
			* an indeterminate progress bar while opening, go ahead an do this
			* on a separate thread */
			OpenFileBG();
		}

		private void OpenWork(object sender, DoWorkEventArgs e)
		{
			BackgroundWorker worker = sender as BackgroundWorker;

			status_t code = mu_doc.OpenFile(m_currfile);
			worker.ReportProgress(100, code);
		}

		private void OpenProgress(object sender, ProgressChangedEventArgs e)
		{
			status_t result = (status_t)(e.UserState);

			if (result == status_t.S_ISOK)
			{
				/* Check if we need a password */
				if (mu_doc.RequiresPassword())
				{
					xaml_OpenProgressGrid.Visibility = System.Windows.Visibility.Collapsed;
					GetPassword();
				}
				else
					StartViewer();
			}
			else
			{
				m_currfile = null;
			}
		}

		private void OpenFileBG()
		{
			try
			{
				m_openfile = new BackgroundWorker();
				m_openfile.WorkerReportsProgress = true;
				m_openfile.WorkerSupportsCancellation = false;
				m_openfile.DoWork += new DoWorkEventHandler(OpenWork);
				m_openfile.ProgressChanged += new ProgressChangedEventHandler(OpenProgress);
				m_openfile.RunWorkerAsync();
			}
			catch (OutOfMemoryException e)
			{
				Console.WriteLine("Memory allocation failed during opening\n");
				ShowMessage(NotifyType_t.MESS_ERROR, "Out of memory: " + e.Message);
			}
		}

		private void SetPageAnnot(int page_num, Annotate_t render_result)
		{
			if (m_docPages[page_num].Annotate == Annotate_t.UNKNOWN ||
				m_docPages[page_num].Annotate == Annotate_t.COMPUTING)
			{
				if (render_result == Annotate_t.NO_ANNOTATE)
					m_docPages[page_num].Annotate = Annotate_t.NO_ANNOTATE;
				else
				{
					if (m_showannot)
						m_docPages[page_num].Annotate = Annotate_t.ANNOTATE_VISIBLE;
					else
						m_docPages[page_num].Annotate = Annotate_t.ANNOTATE_HIDDEN;
				}
			}
			else
			{
				if (m_docPages[page_num].Annotate != Annotate_t.NO_ANNOTATE)
				{
					if (m_showannot)
						m_docPages[page_num].Annotate = Annotate_t.ANNOTATE_VISIBLE;
					else
						m_docPages[page_num].Annotate = Annotate_t.ANNOTATE_HIDDEN;
				}
			}
		}

		private void InitialRenderWork(object sender, DoWorkEventArgs e)
		{
			BackgroundWorker worker = sender as BackgroundWorker;
			int look_ahead = Math.Min(m_num_pages, Constants.INIT_LOOK_AHEAD);

			/* Do the first few full res pages */
			for (int k = 0; k < look_ahead; k++)
			{
				if (m_num_pages > k)
				{
					Point ras_size;
					double scale_factor = 1.0;
					Byte[] bitmap;
					BlocksText charlist;
					status_t code;
					Annotate_t annot;

					if (ComputePageSize(k, scale_factor, out ras_size) == status_t.S_ISOK)
					{
						try
						{
							bitmap = new byte[(int)ras_size.X * (int)ras_size.Y * 4];

							/* Synchronous call on our background thread */
							code = (status_t)mu_doc.RenderPage(k, bitmap, (int)ras_size.X,
								(int)ras_size.Y, scale_factor, false, true,
								!(m_textset[k]), out charlist, m_showannot, out annot);
						}
						catch (OutOfMemoryException em)
						{
							Console.WriteLine("Memory allocation failed init page " + k + em.Message + "\n");
							break;
						}
						/* create new page if we rendered ok. set ui value with 
						 * progress call back, pass page number, charlist and bitmap */
						if (code == status_t.S_ISOK)
						{
							pageprogress_t page_prog = new pageprogress_t();
							page_prog.bitmap = bitmap;
							page_prog.charlist = charlist;
							page_prog.pagenum = k;
							page_prog.size = ras_size;
							page_prog.annot = annot;
							worker.ReportProgress(100, page_prog);
						}
					}
				}
			}
		}

		private void InitialRenderProgressChanged(object sender, ProgressChangedEventArgs e)
		{
			pageprogress_t result = (pageprogress_t)(e.UserState);
			int k = result.pagenum;

			m_textset[k] = true;
			m_textptrs[k] = result.charlist;
			m_docPages[k].TextBlocks = result.charlist;
			UpdatePage(k, result.bitmap, result.size, Page_Content_t.FULL_RESOLUTION, 1.0, m_AA);
			m_docPages[k].NativeHeight = (int) result.size.Y;
			m_docPages[k].NativeWidth = (int)result.size.X;
			SetPageAnnot(k, result.annot);
		}

		private void InitialRenderCompleted(object sender, RunWorkerCompletedEventArgs e)
		{
			m_init_done = true;
			m_currpage = 0;
			RenderThumbs();
			m_file_open = true;
			xaml_BackPage.Opacity = 1;
			xaml_Contents.Opacity = 1;
			xaml_currPage.Opacity = 1;
			xaml_ForwardPage.Opacity = 1;
			xaml_Links.Opacity = 1;
			xaml_Print.Opacity = 1;
			xaml_SavePDF.Opacity = 1;
			xaml_Search.Opacity = 1;
			xaml_Thumbs.Opacity = 1;
			xaml_TotalPages.Opacity = 1;
			xaml_zoomIn.Opacity = 1;
			xaml_zoomOut.Opacity = 1;
			xaml_Zoomsize.Opacity = 1;
			xaml_ExpandFill.Opacity = 1;
			xaml_ContScrollFill.Opacity = 1;
			xaml_ActualSize.Opacity = 1;
			xaml_Zoomsize.IsEnabled = true;
			xaml_currPage.IsEnabled = true;
			xaml_TotalPages.Text = "/ " + m_num_pages.ToString();
			xaml_currPage.Text = "1";
			xaml_ZoomSlider.Opacity = 1.0;
			xaml_ZoomSlider.IsEnabled = true;
			xaml_closefile.IsEnabled = true;
			xaml_saveas.IsEnabled = true;
			xaml_showinfo.IsEnabled = true;
			xaml_extractselection.IsEnabled = true;
			xaml_conversions.IsEnabled = true;
			xaml_gsmessage.IsEnabled = true;
			xaml_print.IsEnabled = true;
			xaml_view.IsEnabled = true;
			xaml_edit.IsEnabled = true;
			if (m_isXPS)
				DisabletoPDF();
			xaml_OpenProgressGrid.Visibility = System.Windows.Visibility.Collapsed;
			xaml_VerticalScroll.Visibility = System.Windows.Visibility.Visible;
			xaml_VerticalScroll.Value = 0;
		}

		private void InitialRenderBG()
		{
			int look_ahead = Math.Min(Constants.INIT_LOOK_AHEAD, m_num_pages);
			m_currpage = 0;
			m_thumbnails.Capacity = m_num_pages;
			
			for (int k = 0; k < Constants.INIT_LOOK_AHEAD; k++)
			{
				m_docPages.Add(InitDocPage());
				m_docPages[k].PageNum = k;
				m_textptrs.Add(new BlocksText());
				m_lineptrs.Add(new LinesText());
				m_textset.Add(false);
			}
			var dummy = InitDocPage();
			for (int k = Constants.INIT_LOOK_AHEAD; k < m_num_pages; k++)
			{
				m_docPages.Add(dummy);
				m_textptrs.Add(new BlocksText());
				m_lineptrs.Add(new LinesText());
				m_textset.Add(false);
			}

			xaml_PageList.ItemsSource = m_docPages;

			try
			{
				m_initrender = new BackgroundWorker();
				m_initrender.WorkerReportsProgress = true;
				m_initrender.WorkerSupportsCancellation = false;
				m_initrender.DoWork += new DoWorkEventHandler(InitialRenderWork);
				m_initrender.RunWorkerCompleted += new RunWorkerCompletedEventHandler(InitialRenderCompleted);
				m_initrender.ProgressChanged += new ProgressChangedEventHandler(InitialRenderProgressChanged);
				m_initrender.RunWorkerAsync();
			}
			catch (OutOfMemoryException e)
			{
				Console.WriteLine("Memory allocation failed during initial render\n");
				ShowMessage(NotifyType_t.MESS_ERROR, "Out of memory: " + e.Message);
			}
		}
		private void StartViewer()
		{
			m_num_pages = mu_doc.GetPageCount();

			if (m_num_pages == 0)
			{
				xaml_OpenProgressGrid.Visibility = System.Windows.Visibility.Collapsed;
				CleanUp();
				ShowMessage(NotifyType_t.MESS_ERROR, m_currfile + " is corrupted");
			}
			else
			{
				xaml_openfilestatus.Text = "Initial Page Rendering";
				xaml_openfilestatus.UpdateLayout();
				InitialRenderBG();
			}
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
			doc_page.Content = Page_Content_t.NOTSET;
			doc_page.TextBox = null;
			doc_page.LinkBox = null;
			doc_page.SelHeight = 0;
			doc_page.SelWidth = 0;
			doc_page.SelX = 0;
			doc_page.SelY = 0;
			return doc_page;
		}

		#region Navigation
		private void OnBackPageClick(object sender, RoutedEventArgs e)
		{
			if (m_currpage == 0 || !m_init_done) return;
			m_ignorescrollchange = true;
			RenderRange(m_currpage - 1, true, zoom_t.NO_ZOOM, 0);
		}

		private void OnForwardPageClick(object sender, RoutedEventArgs e)
		{
			if (m_currpage == m_num_pages - 1 || !m_init_done) return;
			m_ignorescrollchange = true;
			RenderRange(m_currpage + 1, true, zoom_t.NO_ZOOM, 0);
		}

		private void PageEnterClicked(object sender, System.Windows.Input.KeyEventArgs e)
		{
			if (e.Key == Key.Return)
			{
				e.Handled = true;
				var desired_page = xaml_currPage.Text;
				try
				{
					int page = System.Convert.ToInt32(desired_page);
					if (page > 0 && page < (m_num_pages + 1))
					{
						m_ignorescrollchange = true;
						RenderRange(page - 1, true, zoom_t.NO_ZOOM, 0);
					}
				}
				catch (FormatException e1)
				{
					Console.WriteLine("String is not a sequence of digits.");
				}
				catch (OverflowException e2)
				{
					Console.WriteLine("The number cannot fit in an Int32.");
				}
			}
		}

		private void OnKeyDownHandler(object sender, System.Windows.Input.KeyEventArgs e)
		{
			switch (e.Key)
			{
				case Key.Left:
				case Key.PageUp:
					if (m_currpage == 0 || !m_init_done)
						return;
					m_ignorescrollchange = true;
					RenderRange(m_currpage - 1, true, zoom_t.NO_ZOOM, 0);
					e.Handled = true;
					break;

				case Key.Right:
				case Key.PageDown:
					if (m_currpage == m_num_pages - 1 || !m_init_done)
						return;
					m_ignorescrollchange = true;
					RenderRange(m_currpage + 1, true, zoom_t.NO_ZOOM, 0);
					e.Handled = true;
					break;

				case Key.Up:
					if (!m_init_done)
						return;
					e.Handled = true;
					OffsetScroll(-Constants.VERT_SCROLL_STEP * m_doczoom);
					break;

				case Key.Down:
					if (!m_init_done)
						return;
					e.Handled = true;
					OffsetScroll(Constants.VERT_SCROLL_STEP * m_doczoom);
					break;
			}
		}
		#endregion Navigation

		private void CancelLoadClick(object sender, RoutedEventArgs e)
		{
			/* Cancel during thumbnail loading. Deactivate the button 
			 * and cancel the thumbnail rendering */
			if (m_thumbworker != null)
				m_thumbworker.CancelAsync();
			//xaml_CancelThumb.IsEnabled = false;
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
				RenderRange(item.PageNum, true, zoom_t.NO_ZOOM, 0);
			}
		}

		private void ContentSelected(object sender, MouseButtonEventArgs e)
		{
			var item = ((FrameworkElement)e.OriginalSource).DataContext as ContentItem;
			if (item != null && item.Page < m_num_pages)
			{
				int page = m_docPages[item.Page].PageNum;
				if (page >= 0 && page < m_num_pages)
					RenderRange(page, true, zoom_t.NO_ZOOM, 0);
			}
		}

		/* We need to avoid rendering due to size changes */
		private void ListViewScrollChanged(object sender, ScrollChangedEventArgs e)
		{
			/* This makes sure we dont call render range a second time due to 
			 * page advances */
			int first_item = -1;
			int second_item = -1;
			//Console.WriteLine("***************************************/n");
			//Console.WriteLine("VerticalChange = " + e.VerticalChange + "/n");
			//Console.WriteLine("ExtentHeightChange = " + e.ExtentHeightChange + "/n");
			//Console.WriteLine("ExtentWidthChange = " + e.ExtentWidthChange + "/n");
			//Console.WriteLine("HorizontalChange = " + e.HorizontalChange + "/n");
			//Console.WriteLine("ViewportHeightChange = " + e.ViewportHeightChange + "/n");
			//Console.WriteLine("ViewportWidthChange = " + e.ViewportWidthChange + "/n");
			//Console.WriteLine("ExtentHeight = " + e.ExtentHeight + "/n");
			//Console.WriteLine("ViewportHeight = " + e.ViewportHeight + "/n");
			//Console.WriteLine("VerticalOffset = " + e.VerticalOffset + "/n");
			//Console.WriteLine("***************************************/n");
			if (m_ignorescrollchange == true)
			{
				m_ignorescrollchange = false;
				return;
			}
			if (!m_init_done)
				return;
			if (e.VerticalChange == 0)
				return;
			if (m_num_pages == 1)
				return;

			/* From current page go forward and backward checking if pages are
			 * visible */
			ScrollViewer viewer = FindScrollViewer(xaml_PageList);
			if (viewer != null)
			{
				double bottom = this.ActualHeight;
				/* first going forward */
				for (int kk = m_currpage + 1; kk < m_num_pages; kk++)
				{
					UIElement uiElement = (UIElement)xaml_PageList.ItemContainerGenerator.ContainerFromIndex(kk);
					double y_top = uiElement.TranslatePoint(new System.Windows.Point(0, 0), xaml_PageList).Y;
					double y_bottom = uiElement.TranslatePoint(new System.Windows.Point(0, m_docPages[kk].Height), xaml_PageList).Y;
					/* Test if this and all further pages are outside window */
					if (y_top > bottom)
						break;
					/* Test if page is not even yet in window */
					if (y_bottom > 0)
					{
						if (!(m_dispatcherTimer != null && m_dispatcherTimer.IsEnabled == true))
						{
							/* In this case grab the first one that we find */
							if (second_item == -1)
								second_item = kk;
						}
					}
				}

				/* and now going backward */
				for (int kk = m_currpage; kk > -1; kk--)
				{
					UIElement uiElement = (UIElement)xaml_PageList.ItemContainerGenerator.ContainerFromIndex(kk);
					double y_top = uiElement.TranslatePoint(new System.Windows.Point(0, 0), xaml_PageList).Y;
					double y_bottom = uiElement.TranslatePoint(new System.Windows.Point(0, m_docPages[kk].Height), xaml_PageList).Y;
					/* Test if this and all further pages are outside window */
					if (y_bottom < 0)
						break;
					if (y_top < bottom)
						if (!(m_dispatcherTimer != null && m_dispatcherTimer.IsEnabled == true))
							first_item = kk;
				}
				e.Handled = true;
				if (first_item != -1)
					second_item = first_item;
				/* Finish */
				if (m_ScrolledChanged)
				{
					m_ScrolledChanged = false;
				}
				else
				{
					/* We have to update the vertical scroll position */
					double perc = (e.VerticalOffset) / (e.ExtentHeight - e.ViewportHeight);
					xaml_VerticalScroll.Value = perc * xaml_VerticalScroll.Maximum;
				}
				if (second_item < 0)
					second_item = 0;
				RenderRange(second_item, false, zoom_t.NO_ZOOM, 0);
			}
		}

		/* ScrollIntoView will not scroll to top on its own.  If item is already
		 * in view it just sits there */
		private void ScrollPageToTop(int k, double offset, bool from_scroller)
		{
			if (m_num_pages == 1)
				return;
			/* Get access to the scrollviewer */
			ScrollViewer viewer = FindScrollViewer(xaml_PageList);
			if (viewer != null)
			{
				UIElement uiElement = (UIElement) xaml_PageList.ItemContainerGenerator.ContainerFromIndex(k);
				double y = uiElement.TranslatePoint(new System.Windows.Point(0, offset), xaml_PageList).Y;
				double curr_value = viewer.VerticalOffset;
				viewer.ScrollToVerticalOffset(curr_value + y);

				if (!from_scroller)
				{
					double perc = (double) k / (double) ( m_num_pages - 1);
					xaml_VerticalScroll.Value = perc * xaml_VerticalScroll.Maximum;
				}
			}
		}

		/* Scroll to offset */
		private void OffsetScroll(double offset)
		{
			if (m_num_pages == 1)
				return;
			/* Get access to the scrollviewer */
			ScrollViewer viewer = FindScrollViewer(xaml_PageList);
			if (viewer != null)
			{
				double curr_value = viewer.VerticalOffset;
				AdjustScrollPercent(offset / viewer.ScrollableHeight);
				viewer.ScrollToVerticalOffset(curr_value + offset);
			}
		}

		/* Scroll to offset */
		private void OffsetScrollPercent(double percent)
		{
			/* Get access to the scrollviewer */
			ScrollViewer viewer = FindScrollViewer(xaml_PageList);
			if (viewer != null)
			{
				double curr_value = viewer.VerticalOffset;
				if (curr_value < 0 || curr_value > viewer.MaxHeight)
					return;
				var extentheight = viewer.ExtentHeight - viewer.ViewportHeight;

				var pos = extentheight * percent;
				viewer.ScrollToVerticalOffset(pos);
			}
		}

		/* Render +/- the look ahead from where we are if blank page is present */
		async private void RenderRange(int new_page, bool scrollto, zoom_t newzoom, double zoom_offset)
		{
			/* Need to figure out what pages are going to be visible */
			double bottom = this.ActualHeight;
			bool done = false;
			int final_page = new_page;
			double count = -zoom_offset;
			int offset = -1;
			bool scrollbottom = false;

			if (newzoom != zoom_t.NO_ZOOM)
				offset = 0;

			if (m_thumbnails.Count < m_num_pages)
				final_page = final_page + 1;
			else
			{
				while (!done && final_page >= 0 && final_page < m_num_pages)
				{
					count = count + m_thumbnails[final_page].NativeHeight * m_doczoom;
					final_page = final_page + 1;
					if (final_page == m_num_pages || count > bottom)
						done = true;
				}
				/* We have zoomed out to a point where the offset will not stay
				 * in its current spot.  Figure out where we need to be */
				final_page = final_page - 1;
				if (newzoom == zoom_t.ZOOM_OUT && count < bottom)
				{
					int curr_page = new_page - 1;
					while (true)
					{
						if (curr_page < 0)
							break;
						count = count + m_thumbnails[curr_page].NativeHeight * m_doczoom;
						if (count > bottom)
							break;
						curr_page = curr_page - 1;
					}
					new_page = curr_page;
					if (new_page < 0)
						new_page = 0;
					scrollbottom = true;
				}
			}

			for (int k = new_page + offset; k <= final_page + 1; k++)
			{
				if (k >= 0 && k < m_num_pages)
				{
					/* Check if page is already rendered */
					var doc = m_docPages[k];
					if (doc.Content != Page_Content_t.FULL_RESOLUTION ||
						doc.Zoom != m_doczoom || m_AA != doc.AA ||
						(doc.Annotate == Annotate_t.UNKNOWN && m_showannot) ||
						(doc.Annotate == Annotate_t.ANNOTATE_VISIBLE && !m_showannot) ||
						(doc.Annotate == Annotate_t.ANNOTATE_HIDDEN && m_showannot))
					{
						Point ras_size;
						double scale_factor = m_doczoom;
						/* To avoid multiple page renderings on top of one 
						 * another with scroll changes mark this as being 
						 * full resolution */
						m_docPages[k].Content = Page_Content_t.FULL_RESOLUTION;
						/* Avoid launching another thread just because we don't 
						 * know the annotation condition for this page */
						m_docPages[k].Annotate = Annotate_t.COMPUTING;
						if (ComputePageSize(k, scale_factor, out ras_size) == status_t.S_ISOK)
						{
							try
							{
								Byte[] bitmap = new byte[(int)ras_size.X * (int)ras_size.Y * 4];
								BlocksText charlist = null;
								Annotate_t annot = Annotate_t.UNKNOWN;
								m_docPages[k].NativeWidth = (int)(ras_size.X / scale_factor);
								m_docPages[k].NativeHeight = (int)(ras_size.Y / scale_factor);

								Task<int> ren_task =
									new Task<int>(() => mu_doc.RenderPage(k, bitmap,
										(int)ras_size.X, (int)ras_size.Y, scale_factor,
										false, true, !(m_textset[k]), out charlist, m_showannot,
										out annot));
								ren_task.Start();
								await ren_task.ContinueWith((antecedent) =>
								{
									status_t code = (status_t)ren_task.Result;
									if (code == status_t.S_ISOK)
									{
										SetPageAnnot(k, annot);
										if (m_docPages[k].TextBox != null)
											ScaleTextBox(k);
										if (m_links_on && m_page_link_list != null)
										{
											m_docPages[k].LinkBox = m_page_link_list[k];
											if (m_docPages[k].LinkBox != null)
												ScaleLinkBox(k);
										}
										else
										{
											m_docPages[k].LinkBox = null;
										}
										if (!(m_textset[k]) && charlist != null)
										{
											m_textptrs[k] = charlist;
											if (scale_factor != 1.0)
												ScaleTextBlocks(k, scale_factor);
											m_docPages[k].TextBlocks = m_textptrs[k];
											m_textset[k] = true;
											if (m_selectall)
											{
												int num_blocks = m_docPages[k].TextBlocks.Count;
												for (int jj = 0; jj < num_blocks; jj++)
												{
													m_docPages[k].TextBlocks[jj].Color = m_textselectcolor;
												}
											}
										}
										else
										{
											/* We had to rerender due to scale */
											if (m_textptrs[k] != null)
											{
												ScaleTextBlocks(k, scale_factor);
												m_docPages[k].TextBlocks = m_textptrs[k];
											}
											if (m_lineptrs[k] != null)
											{
												ScaleTextLines(k, scale_factor);
												m_docPages[k].SelectedLines = m_lineptrs[k];
											}
										}
										/* This needs to be handled here to reduce 
										 * flashing effects */
										if (newzoom != zoom_t.NO_ZOOM && k == new_page)
										{
											m_ignorescrollchange = true;
											UpdatePageSizes();
											xaml_VerticalScroll.Maximum = m_totalpageheight * m_doczoom + 4 * m_num_pages;
											if (!scrollbottom)
												ScrollPageToTop(new_page, zoom_offset, false);
										}
										UpdatePage(k, bitmap, ras_size,
											Page_Content_t.FULL_RESOLUTION, m_doczoom, m_AA);
										if (k == new_page && scrollto && new_page != m_currpage)
										{
											m_doscroll = true;
											ScrollPageToTop(k, 0, false);
										}
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
					else
					{
						/* We did not have to render the page but we may need to
						 * scroll to it */
						if (k == new_page && scrollto && new_page != m_currpage)
						{
							m_ignorescrollchange = true;
							ScrollPageToTop(k, 0, false);
						}
					}
				}
			}
			/* Release old range and set new page */
			//ReleasePages(m_currpage, new_page - 1, final_page + 1);
			m_currpage = new_page;
			xaml_currPage.Text = (m_currpage + 1).ToString();
		}

		/* Avoids the next page jumping into view when touched by mouse. See xaml code */
		private void AvoidScrollIntoView(object sender, RequestBringIntoViewEventArgs e)
		{
			if (!m_doscroll)
				e.Handled = true;
			else
				m_doscroll = false;
		}

		private void ReleasePages(int old_page, int new_page, int final_page)
		{
			if (old_page == new_page) return;
			/* To keep from having memory issue reset the page back to
				the thumb if we are done rendering the thumbnails */
			for (int k = 0; k < m_num_pages; k++)
			{
				if (k < new_page || k > final_page)
				{
					if (k >= 0 && k < m_num_pages)
					{
						SetThumb(k);
					}
				}
			}
		}

		/* Return this page from a full res image to the thumb image */
		private void SetThumb(int page_num)
		{
			/* See what is there now */
			var doc_page = m_docPages[page_num];
			if (doc_page.Content == Page_Content_t.THUMBNAIL &&
				doc_page.Zoom == m_doczoom) return;

			if (m_thumbnails.Count > page_num)
			{
				doc_page.Content = Page_Content_t.THUMBNAIL;
				doc_page.Zoom = m_doczoom;

				doc_page.BitMap = m_thumbnails[page_num].BitMap;
				doc_page.Width = (int)(m_doczoom * doc_page.BitMap.PixelWidth / Constants.SCALE_THUMB);
				doc_page.Height = (int)(m_doczoom * doc_page.BitMap.PixelHeight / Constants.SCALE_THUMB);
				doc_page.PageNum = page_num;
				doc_page.LinkBox = null;
				doc_page.TextBox = null;
				/* No need to refresh unless it just occurs during other stuff
				 * we just want to make sure we can release the bitmaps */
				//doc_page.PageRefresh();
			}
		}

		private void gsDLL(object gsObject, String mess)
		{
			ShowMessage(NotifyType_t.MESS_STATUS, mess);
		}

		/* Catastrophic */
		private void muDLL(object gsObject, String mess)
		{
			ShowMessage(NotifyType_t.MESS_ERROR, mess);
			/* Disable even the ability to open a file */
			xaml_open.Opacity = 0.5;
			xaml_open.IsEnabled = false;
			xaml_file.Opacity = 0.5;
			xaml_file.IsEnabled = false;
			/* And to drag - drop or registry start up */
			xaml_PageList.RemoveHandler(Grid.DragOverEvent, new System.Windows.DragEventHandler(Grid_DragOver));
			xaml_PageList.RemoveHandler(Grid.DropEvent, new System.Windows.DragEventHandler(Grid_Drop));
			m_regstartup = false;
		}

		private void gsIO(object gsObject, String mess, int len)
		{
			m_gsoutput.Update(mess, len);
		}

		private void mupdfUpdate(object muObject, muPDFEventArgs asyncInformation)
		{
			if (asyncInformation.Completed)
			{
				xaml_MuPDFProgress.Value = 100;
				xaml_MuPDFGrid.Visibility = System.Windows.Visibility.Collapsed;
				if (asyncInformation.Params.result == GS_Result_t.gsFAILED)
				{
					ShowMessage(NotifyType_t.MESS_STATUS, "MuPDF failed to convert document");
				}
				MuPDFResult(asyncInformation.Params);
			}
			else
			{
				this.xaml_MuPDFProgress.Value = asyncInformation.Progress;
			}
		}

		/* MuPDF Result*/
		public void MuPDFResult(ConvertParams_t gs_result)
		{
			if (gs_result.result == GS_Result_t.gsCANCELLED)
			{
				xaml_MuPDFGrid.Visibility = System.Windows.Visibility.Collapsed;
				return;
			}
			if (gs_result.result == GS_Result_t.gsFAILED)
			{
				xaml_MuPDFGrid.Visibility = System.Windows.Visibility.Collapsed;
				ShowMessage(NotifyType_t.MESS_STATUS, "MuPDF Failed Conversion");
				return;
			}
			ShowMessage(NotifyType_t.MESS_STATUS, "MuPDF Completed Conversion");
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
					m_origfile = gs_result.inputfile;
					OpenFile2(gs_result.outputfile);
					break;

				case GS_Task_t.SAVE_RESULT:
					ShowMessage(NotifyType_t.MESS_STATUS, "GS Completed Conversion");
					break;
			}
		}

		private void PrintCommand(object sender, ExecutedRoutedEventArgs e)
		{
			Print(sender, e);
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
					100.0 * (double)Information.Page / (double)m_num_pages;
			}
		}

		private void CancelMuPDFClick(object sender, RoutedEventArgs e)
		{
			xaml_CancelMuPDF.IsEnabled = false;
			mu_doc.Cancel();
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
			Device device = (Device)m_convertwin.xaml_DeviceList.SelectedItem;
			if (device == null)
			{
				ShowMessage(NotifyType_t.MESS_STATUS, "No Device Selected");
				return;
			} 

			if (m_ghostscript.GetStatus() != gsStatus.GS_READY &&
				!device.MuPDFDevice)
			{
				ShowMessage(NotifyType_t.MESS_STATUS, "GS busy");
				return;
			}

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

			/* Get a filename */
			System.Windows.Forms.SaveFileDialog dlg = new System.Windows.Forms.SaveFileDialog();
			dlg.Filter = "All files (*.*)|*.*";
			dlg.FilterIndex = 1;
			if (dlg.ShowDialog() == System.Windows.Forms.DialogResult.OK)
			{
				if (device.MuPDFDevice)
				{
					/* Allow only one of these as a time */
					pages_selected = pages;
					var val = m_convertwin.xaml_resolution.Text;
					if (val.Length > 0)
					{
						bool isok = true;
						int num = resolution;
						try
						{
							num = System.Convert.ToInt32(val);
						}
						catch (FormatException e)
						{
							isok = false;
							Console.WriteLine("Input string is not a sequence of digits.");
						}
						catch (OverflowException e)
						{
							isok = false;
							Console.WriteLine("The number cannot fit in an Int32.");
						}
						if (isok && num > 0)
							resolution = num;
					}

					if (mu_doc.ConvertSave(device.DeviceType, dlg.FileName,
						pages.Count, pages_selected, resolution) == gsStatus.GS_BUSY)
					{
						ShowMessage(NotifyType_t.MESS_STATUS, "MuPDF conversion busy");
						return;
					}
					xaml_CancelMuPDF.Visibility = System.Windows.Visibility.Visible;
					xaml_MuPDFGrid.Visibility = System.Windows.Visibility.Visible;
				}
				else
				{
					if (!device.SupportsMultiPage && m_num_pages > 1)
						multi_page_needed = true;

					if (pages.Count != m_num_pages)
					{
						/* We may need to go through page by page. Determine if
						 * selection of pages is continuous.  This is done by 
						 * looking at the first one in the list and the last one
						 * in the list and checking the length */
						SelectPage lastpage = (SelectPage)pages[pages.Count - 1];
						SelectPage firstpage = (SelectPage)pages[0];
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
				}
				m_convertwin.Close();
			}
			return;
		}

		private void ExtractPages(object sender, RoutedEventArgs e)
		{
			if (!m_init_done || m_isXPS)
				return;

			if (m_extractwin == null || !m_extractwin.IsActive)
			{
				m_extractwin = new PageExtractSave(m_num_pages);
				m_extractwin.ExtractMain += new PageExtractSave.ExtractCallBackMain(ExtractReturn);
				m_extractwin.Activate();
				m_extractwin.Show();
			}
		}

		private void ExtractReturn(object sender)
		{
			if (m_extractwin.xaml_PageList.SelectedItems.Count == 0)
			{
				ShowMessage(NotifyType_t.MESS_STATUS, "No Pages Selected");
				return;
			}

			/* Go through the actual list not the selected items list. The 
			 * selected items list contains them in the order that the were
			 * selected not the order graphically shown */
			List<SelectPage> pages = new List<SelectPage>(m_extractwin.xaml_PageList.SelectedItems.Count);

			for (int kk = 0; kk < m_extractwin.xaml_PageList.Items.Count; kk++)
			{
				var item = (m_extractwin.xaml_PageList.ItemContainerGenerator.ContainerFromIndex(kk)) as System.Windows.Controls.ListViewItem;
				if (item.IsSelected == true)
				{
					pages.Add((SelectPage) m_extractwin.Pages[kk]);
				}
			}

			/* Get a filename */
			System.Windows.Forms.SaveFileDialog dlg = new System.Windows.Forms.SaveFileDialog();
			dlg.Filter = "All files (*.pdf)|*.pdf";
			dlg.FilterIndex = 1;
			if (dlg.ShowDialog() == System.Windows.Forms.DialogResult.OK)
			{
				mu_doc.PDFExtract(m_currfile, dlg.FileName, m_currpassword, m_currpassword != null,
					false, pages.Count, pages);
				m_extractwin.Close();
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
				m_currpassword = m_password.xaml_Password.Password;
				m_password.Close();
				m_password = null;
				xaml_OpenProgressGrid.Visibility = System.Windows.Visibility.Visible;
				xaml_openfilestatus.Text = "Opening File";
				StartViewer();
			}
			else
			{
				xaml_OpenProgressGrid.Visibility = System.Windows.Visibility.Collapsed;
				ShowMessage(NotifyType_t.MESS_STATUS, "Password Incorrect");
			}
		}

		private void ShowInfo(object sender, RoutedEventArgs e)
		{
			String Message;

			if (m_file_open)
			{
				String filename;

				if (m_origfile != null && (m_document_type == DocumentTypes.PS ||
					m_document_type == DocumentTypes.EPS))
					filename = m_origfile;
				else
					filename = m_currfile;
				
				Message =
					"         File: " + filename + "\n" +
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

		#region Zoom Control

		/* Find out where the current page is */
		private double ComputeOffsetZoomOut(double old_zoom)
		{
			double y = 0;
			ScrollViewer viewer = FindScrollViewer(xaml_PageList);
			if (viewer != null)
			{
				/* Look at the offset and where it falls relative to the top of our current page */
				UIElement uiElement = (UIElement)xaml_PageList.ItemContainerGenerator.ContainerFromIndex(m_currpage);
				y = viewer.TranslatePoint(new System.Windows.Point(0, 0), uiElement).Y;
			}
			return y * m_doczoom / old_zoom;
		}

		private double ComputeOffsetZoomIn(double old_zoom, out int new_page)
		{
			double y = 0;
			ScrollViewer viewer = FindScrollViewer(xaml_PageList);
			new_page = m_currpage;
			if (viewer != null)
			{
				/* Look at the offset and where it falls relative to the top of our current page */
				UIElement uiElement = (UIElement)xaml_PageList.ItemContainerGenerator.ContainerFromIndex(m_currpage);
				y = viewer.TranslatePoint(new System.Windows.Point(0, 0), uiElement).Y;

				/* If we are zoomed out, we can be on a page that is not on the top boundry. See if we can find one
				 * that is */
				if (y < 0)
				{
					new_page = m_currpage - 1;
					while (true)
					{
						if (new_page < 0)
						{
							new_page = 0;
							return 0;
						}
						uiElement = (UIElement)xaml_PageList.ItemContainerGenerator.ContainerFromIndex(new_page);
						y = viewer.TranslatePoint(new System.Windows.Point(0, 0), uiElement).Y;
						if (y >= 0)
						{
							return y * m_doczoom / old_zoom;
						}
						new_page = new_page - 1;
					}
				}
			}
			return y * m_doczoom / old_zoom;
		}

		private void ZoomOut(object sender, RoutedEventArgs e)
		{
			if (!m_init_done || m_doczoom <=  Constants.ZOOM_MIN)
				return;
			double old_zoom = m_doczoom;
			m_doczoom = m_doczoom - Constants.ZOOM_STEP;
			if (m_doczoom < Constants.ZOOM_MIN)
				m_doczoom = Constants.ZOOM_MIN;
			xaml_ZoomSlider.Value = m_doczoom * 100.0;
			double offset = ComputeOffsetZoomOut(old_zoom);
			RenderRange(m_currpage, false, zoom_t.ZOOM_OUT, offset);
		}

		private void ZoomIn(object sender, RoutedEventArgs e)
		{
			if (!m_init_done || m_doczoom >= Constants.ZOOM_MAX)
				return;
			double old_zoom = m_doczoom;
			m_doczoom = m_doczoom + Constants.ZOOM_STEP;
			if (m_doczoom > Constants.ZOOM_MAX)
				m_doczoom = Constants.ZOOM_MAX;
			xaml_ZoomSlider.Value = m_doczoom * 100.0;
			int newpage;
			double offset = ComputeOffsetZoomIn(old_zoom, out newpage);
			RenderRange(newpage, false, zoom_t.ZOOM_IN, offset);
		}

		private void ActualSize(object sender, RoutedEventArgs e)
		{
			if (!m_init_done)
				return;
			double old_zoom = m_doczoom;
			m_doczoom = 1.0;
			xaml_ZoomSlider.Value = m_doczoom * 100.0;
			if (old_zoom < 1.0)
			{
				int new_page;
				double offset = ComputeOffsetZoomIn(old_zoom, out new_page);
				RenderRange(new_page, false, zoom_t.ZOOM_IN, offset);
			}
			else if (old_zoom > 1.0)
			{
				double offset = ComputeOffsetZoomOut(old_zoom);
				RenderRange(m_currpage, false, zoom_t.ZOOM_OUT, offset);
			}
		}

		private void ContScrollFill(object sender, RoutedEventArgs e)
		{
			if (!m_init_done)
				return;
			/* Scale our pages based upon the size of scrollviewer */
			ScrollViewer viewer = FindScrollViewer(xaml_PageList);
			if (viewer == null)
				return;
			double width = viewer.ViewportWidth;
			double page_width = m_thumbnails[m_currpage].NativeWidth;
			double scale = width / page_width;
			if (scale < Constants.ZOOM_MIN)
				scale = Constants.ZOOM_MIN;
			if (scale > Constants.ZOOM_MAX)
				scale = Constants.ZOOM_MAX;
			if (m_doczoom == scale)
				return;
			double old_zoom = m_doczoom;
			m_doczoom = scale;
			xaml_ZoomSlider.Value = m_doczoom * 100.0;
			if (old_zoom > m_doczoom)
				RenderRange(m_currpage, true, zoom_t.ZOOM_OUT, 0);
			else
				RenderRange(m_currpage, true, zoom_t.ZOOM_IN, 0);
		}

		private void ExpandFill(object sender, RoutedEventArgs e)
		{
			if (!m_init_done)
				return;
			/* Scale our pages based upon the size of scrollviewer */
			ScrollViewer viewer = FindScrollViewer(xaml_PageList);
			if (viewer == null)
				return;
			double height = viewer.ViewportHeight;
			double width = viewer.ViewportWidth;
			double page_height = m_thumbnails[m_currpage].NativeHeight;
			double page_width = m_thumbnails[m_currpage].NativeWidth;
			double height_scale = height / page_height;
			double width_scale = width / page_width;
			double scale = Math.Min(height_scale, width_scale);
			if (scale < Constants.ZOOM_MIN)
				scale = Constants.ZOOM_MIN;
			if (scale > Constants.ZOOM_MAX)
				scale = Constants.ZOOM_MAX;
			if (m_doczoom == scale)
				return;
			double old_zoom = m_doczoom;
			m_doczoom = scale;
			xaml_ZoomSlider.Value = m_doczoom * 100.0;
			if (old_zoom > m_doczoom)
				RenderRange(m_currpage, true, zoom_t.ZOOM_OUT, 0);
			else
				RenderRange(m_currpage, true, zoom_t.ZOOM_IN, 0);
		}

		private void ShowFooter(object sender, RoutedEventArgs e)
		{
			xaml_FooterControl.Visibility = System.Windows.Visibility.Visible;
		}

		private void HideFooter(object sender, RoutedEventArgs e)
		{
			xaml_FooterControl.Visibility = System.Windows.Visibility.Collapsed;
		}

		private void ZoomReleased(object sender, MouseButtonEventArgs e)
		{
			if (m_init_done)
			{
				double zoom = xaml_ZoomSlider.Value / 100.0;
				if (zoom > Constants.ZOOM_MAX)
					zoom = Constants.ZOOM_MAX;
				if (zoom < Constants.ZOOM_MIN)
					zoom = Constants.ZOOM_MIN;
				double old_zoom = zoom;
				m_doczoom = zoom;
				if (old_zoom > m_doczoom)
				{
					double offset = ComputeOffsetZoomOut(old_zoom);
					RenderRange(m_currpage, false, zoom_t.ZOOM_OUT, offset);
				}
				else
				{
					int new_page;
					double offset = ComputeOffsetZoomIn(old_zoom, out new_page);
					RenderRange(new_page, false, zoom_t.ZOOM_IN, offset);
				}
			}
		}

		/* If the zoom is not equalto 1 then set the zoom to 1 and scoll to this page */
		private void PageDoubleClick(object sender, MouseButtonEventArgs e)
		{
			return; /* Disable this for now */
			if (m_doczoom != 1.0)
			{
				double old_zoom = m_doczoom; 
				m_doczoom = 1.0;
				xaml_Zoomsize.Text = "100";
				var item = ((FrameworkElement)e.OriginalSource).DataContext as DocPage;
				if (item != null)
				{
					if (old_zoom > m_doczoom)
					{
						double offset = ComputeOffsetZoomOut(old_zoom);
						RenderRange(m_currpage, false, zoom_t.ZOOM_OUT, offset);
					}
					else
					{
						int new_page;
						double offset = ComputeOffsetZoomIn(old_zoom, out new_page);
						RenderRange(new_page, false, zoom_t.ZOOM_IN, offset);
					}
				}
			}
		}

		private void ZoomEnterClicked(object sender, System.Windows.Input.KeyEventArgs e)
		{
			if (e.Key == Key.Return)
			{
				e.Handled = true;
				var desired_zoom = xaml_Zoomsize.Text;
				try
				{
					double zoom = (double)System.Convert.ToInt32(desired_zoom) / 100.0;
					if (zoom > Constants.ZOOM_MAX)
						zoom = Constants.ZOOM_MAX;
					if (zoom < Constants.ZOOM_MIN)
						zoom = Constants.ZOOM_MIN;
					double old_zoom = m_doczoom;
					m_doczoom = zoom;
					if (old_zoom > m_doczoom)
					{
						double offset = ComputeOffsetZoomOut(old_zoom);
						RenderRange(m_currpage, false, zoom_t.ZOOM_OUT, offset);
					}
					else
					{
						int new_page;
						double offset = ComputeOffsetZoomIn(old_zoom, out new_page);
						RenderRange(new_page, false, zoom_t.ZOOM_IN, offset);
					}
				}
				catch (FormatException e1)
				{
					Console.WriteLine("String is not a sequence of digits.");
				}
				catch (OverflowException e2)
				{
					Console.WriteLine("The number cannot fit in an Int32.");
				}
			}
		}

		/* Rescale the pages based upon the zoom value and the native size */
		private void UpdatePageSizes()
		{
			SetThumbwidth();
			for (int k = 0; k > m_num_pages; k++)
			{
				var thumbpage = m_thumbnails[k];
				var page = m_docPages[k];

				if (page.Zoom == m_doczoom)
					continue;
				int scale_zoom = (int)Math.Round((double)page.Height / (double)thumbpage.NativeHeight);
				if (scale_zoom != m_doczoom)
				{
					page.Height = (int)Math.Round(thumbpage.NativeHeight * m_doczoom);
					page.Width = (int)Math.Round(thumbpage.NativeWidth * m_doczoom);
				}
			}
		}
		#endregion Zoom Control

		#region Thumb Rendering
		void SetThumbInit(int page_num, Byte[] bitmap, Point ras_size, double zoom_in)
		{
			/* Three jobs. Store the thumb and possibly update the full page. Also
			 add to collection of pages.  Set up page geometry info (scale of
			 100 percent ) */

			DocPage doc_page = new DocPage();
			m_thumbnails.Add(doc_page);

			doc_page.Width = (int)ras_size.X;
			
			doc_page.Height = (int)ras_size.Y;
			doc_page.NativeWidth = (int)(ras_size.X / Constants.SCALE_THUMB);
			doc_page.NativeHeight = (int)(ras_size.Y / Constants.SCALE_THUMB);
			m_totalpageheight = m_totalpageheight + doc_page.NativeHeight;

			doc_page.Content = Page_Content_t.THUMBNAIL;
			doc_page.Zoom = zoom_in;
			int stride = doc_page.Width * 4;
			doc_page.BitMap = BitmapSource.Create(doc_page.Width, doc_page.Height, 
				72, 72, PixelFormats.Pbgra32, BitmapPalettes.Halftone256, bitmap, stride);
			doc_page.PageNum = page_num;

			/* Lets see if we need to set the main page */
			var doc = m_docPages[page_num];
			switch (doc.Content)
			{
				case Page_Content_t.FULL_RESOLUTION:
				case Page_Content_t.THUMBNAIL:
					return;
					
				case Page_Content_t.NOTSET:
					doc_page = InitDocPage();
					doc_page.Content = Page_Content_t.THUMBNAIL;
					doc_page.Zoom = zoom_in;
					doc_page.BitMap = m_thumbnails[page_num].BitMap;
					doc_page.Width = (int)(ras_size.X / Constants.SCALE_THUMB);
					doc_page.Height = (int)(ras_size.Y / Constants.SCALE_THUMB);
					doc_page.PageNum = page_num;
					this.m_docPages[page_num] = doc_page;
					break;

				case Page_Content_t.OLD_RESOLUTION:
					return;
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
						BlocksText charlist;
						Annotate_t annot;
						/* Synchronous call on our background thread */
						code = (status_t)mu_doc.RenderPage(k, bitmap, (int)ras_size.X,
							(int)ras_size.Y, scale_factor, false, false, false,
							out charlist, false, out annot);
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
			//xaml_CancelThumb.IsEnabled = true;
			xaml_ThumbList.Items.Refresh();
			xaml_VerticalScroll.Minimum = 0;
			xaml_VerticalScroll.Maximum = m_totalpageheight + 4 * m_num_pages;
			//thumbSize = (viewportSize/(maximum–minimum+viewportSize))×trackLength
			SetThumbwidth();
			//ScrollBarExtensions.SetThumbLength(xaml_VerticalScroll, 1);
		}

		private void ThumbsProgressChanged(object sender, ProgressChangedEventArgs e)
		{
			thumb_t thumb = (thumb_t)(e.UserState);

			xaml_ThumbProgress.Value = e.ProgressPercentage;
			SetThumbInit(thumb.page_num, thumb.bitmap, thumb.size, 1.0);
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
		#endregion Thumb Rendering

		#region Copy Paste
		/* Copy the current page as a bmp to the clipboard this is done at the 
		 * current resolution */
		private void CopyPage(object sender, RoutedEventArgs e)
		{
			if (!m_init_done)
				return;
			var curr_page = m_docPages[m_currpage];
			System.Windows.Clipboard.SetImage(curr_page.BitMap);
			m_clipboardset = true;
		}

		/* Paste the page to various types supported by the windows encoder class */
		private void PastePage(object sender, RoutedEventArgs e)
		{
			var menu = (System.Windows.Controls.MenuItem)sender;

			String tag = (String)menu.Tag;

			if (!m_clipboardset || !System.Windows.Clipboard.ContainsImage() ||
				!m_init_done)
				return;
			var bitmap = System.Windows.Clipboard.GetImage();

			BitmapEncoder encoder;
			System.Windows.Forms.SaveFileDialog dlg = new System.Windows.Forms.SaveFileDialog();
			dlg.FilterIndex = 1;

			switch (tag)
			{
				case "PNG":
					dlg.Filter = "PNG Files(*.png)|*.png";
					encoder = new PngBitmapEncoder();

					break;
				case "JPG":
					dlg.Filter = "JPEG Files(*.jpg)|*.jpg";
					encoder = new JpegBitmapEncoder();
					break;

				case "WDP":
					dlg.Filter = "HDP Files(*.wdp)|*.wdp";
					encoder = new WmpBitmapEncoder();
					break;

				case "TIF":
					dlg.Filter = "TIFF Files(*.tif)|*.tif";
					encoder = new TiffBitmapEncoder();
					break;

				case "BMP":
					dlg.Filter = "BMP Files(*.bmp)|*.bmp";
					encoder = new BmpBitmapEncoder();
					break;

				case "GIF":
					dlg.Filter = "GIF Files(*.gif)|*.gif";
					encoder = new GifBitmapEncoder();
					break;

				default:
					return;
			}

			encoder.Frames.Add(BitmapFrame.Create(bitmap));
			if (dlg.ShowDialog() == System.Windows.Forms.DialogResult.OK)
			{
				using (var stream = dlg.OpenFile())
					encoder.Save(stream);
			}
		}
		#endregion Copy Paste

		#region SaveAs
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

			System.Windows.Forms.SaveFileDialog dlg = new System.Windows.Forms.SaveFileDialog();
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

					switch (type)
					{
						case Save_Type_t.PDF:
							/* All done.  No need to use gs or mupdf */
							System.IO.File.Copy(m_currfile, dlg.FileName, true);
							use_gs = false;
							break;
						case Save_Type_t.LINEAR_PDF:
							mu_doc.PDFExtract(m_currfile, dlg.FileName, m_currpassword,
								m_currpassword != null, true, -1, null);
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
							init_file, null) == gsStatus.GS_BUSY)
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
				String Message = "";
				textout_t textout = textout_t.HTML;
				switch (type)
				{
					case Save_Type_t.HTML:
						dlg.Filter = "HTML (*.html)|*.html";
						Message = "HTML content written";
						break;
					case Save_Type_t.XML:
						dlg.Filter = "XML (*.xml)|*.xml";
						Message = "XML content written";
						textout = textout_t.XML;
						break;
					case Save_Type_t.TEXT:
						dlg.Filter = "Text (*.txt)|*.txt";
						Message = "Text content written";
						textout = textout_t.TEXT;
						break;
					case Save_Type_t.PCLXL:
						use_mupdf = false;
						dlg.Filter = "PCL-XL (*.bin)|*.bin";
						Device = gsDevice_t.pxlcolor;
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
				else
				{
					if (dlg.ShowDialog() == System.Windows.Forms.DialogResult.OK)
					{
						/* Write out first non null page then append the rest */
						int curr_page = 0;
						bool done = false;

						while (!done)
						{
							String output = null;
							output = mu_doc.GetText(curr_page, textout);
							if (output == null)
							{
								curr_page = curr_page + 1;
								if (curr_page == m_num_pages)
								{
									ShowMessage(NotifyType_t.MESS_STATUS, "No text found in file");
									return;
								}
							}
							else
							{
								System.IO.File.WriteAllText(dlg.FileName, output);
								done = true;
							}
						}
						curr_page = curr_page + 1;

						if (curr_page == m_num_pages)
						{
							ShowMessage(NotifyType_t.MESS_STATUS, Message);
							return;
						}
						done = false;
						while (!done)
						{
							String output = null;
							output = mu_doc.GetText(curr_page, textout);
							if (output != null)
							{
								System.IO.File.AppendAllText(dlg.FileName, output);
							}
							curr_page = curr_page + 1;
							if (curr_page == m_num_pages)
							{
								ShowMessage(NotifyType_t.MESS_STATUS, Message);
								return;
							}
						}
					}
				}
			}
		}

		private void SaveSVG(object sender, RoutedEventArgs e)
		{
			SaveFile(Save_Type_t.SVG);
		}

		private void SavePDF(object sender, RoutedEventArgs e)
		{
			SaveFile(Save_Type_t.PDF);
		}

		private void SaveText(object sender, RoutedEventArgs e)
		{
			SaveFile(Save_Type_t.TEXT);
		}

		private void SaveXML(object sender, RoutedEventArgs e)
		{
			SaveFile(Save_Type_t.XML);
		}

		private void SaveHTML(object sender, RoutedEventArgs e)
		{
			SaveFile(Save_Type_t.HTML);
		}

		private void Linearize(object sender, RoutedEventArgs e)
		{
			SaveFile(Save_Type_t.LINEAR_PDF);
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
		#endregion SaveAs

		#region Extract
		private void Extract(Extract_Type_t type)
		{
			if (m_selection != null || !m_init_done)
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
					BlocksText charlist;
					Annotate_t annot;

					Task<int> ren_task =
						new Task<int>(() => mu_doc.RenderPage(page_num, bitmap,
							(int)ras_size.X, (int)ras_size.Y, zoom, false, true,
							false, out charlist, true, out annot));
					ren_task.Start();
					await ren_task.ContinueWith((antecedent) =>
					{
						status_t code = (status_t)ren_task.Result;
						if (code == status_t.S_ISOK)
						{
							if (m_selection != null)
							{
								int stride = (int)ras_size.X * 4;
								m_selection.xaml_Image.Source = BitmapSource.Create((int)ras_size.X, (int)ras_size.Y, 72, 72, PixelFormats.Pbgra32, BitmapPalettes.Halftone256, bitmap, stride);
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
					System.Windows.Forms.SaveFileDialog dlg = new System.Windows.Forms.SaveFileDialog();
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
		private void OutputIntents(object sender, RoutedEventArgs e)
		{
			m_outputintents.Show();
		}
		#endregion Extract

		#region Search
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
				xaml_SearchGrid.Visibility = System.Windows.Visibility.Collapsed;
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
			int direction = (int)genericlist[0];
			String needle = (String)genericlist[1];
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

					for (int kk = 0; kk < box_count; kk++)
					{
						Point top_left;
						Size size;
						mu_doc.GetTextSearchItem(kk, out top_left, out size);
						var rect = new Rect(top_left, size);
						results.rectangles.Add(rect);
					}
					/* Reset global smart pointer once we have everything */
					mu_doc.ReleaseTextSearch();
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
					rect_item.Color = m_textsearchcolor;
					rect_item.Height = results.rectangles[kk].Height * m_doczoom;
					rect_item.Width = results.rectangles[kk].Width * m_doczoom;
					rect_item.X = results.rectangles[kk].X * m_doczoom;
					rect_item.Y = results.rectangles[kk].Y * m_doczoom;
					rect_item.Index = kk.ToString();
					m_text_list.Add(rect_item);
				}
				m_docPages[results.page_found].TextBox = m_text_list;
				m_doscroll = true;
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
				searchResults_t results = (searchResults_t)e.Result;
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
		#endregion Search

		#region Link
		private void LinksToggle(object sender, RoutedEventArgs e)
		{
			if (!m_init_done)
				return;

			m_links_on = !m_links_on;

			if (m_page_link_list == null)
			{
				if (m_linksearch != null && m_linksearch.IsBusy)
					return;

				m_page_link_list = new List<List<RectList>>();
				m_linksearch = new BackgroundWorker();
				m_linksearch.WorkerReportsProgress = false;
				m_linksearch.WorkerSupportsCancellation = true;
				m_linksearch.DoWork += new DoWorkEventHandler(LinkWork);
				m_linksearch.RunWorkerCompleted += new RunWorkerCompletedEventHandler(LinkCompleted);
				m_linksearch.RunWorkerAsync();
			}
			else
			{
				if (m_links_on)
					LinksOn();
				else
					LinksOff();
			}
		}

		private void LinkWork(object sender, DoWorkEventArgs e)
		{
			BackgroundWorker worker = sender as BackgroundWorker;

			for (int k = 0; k < m_num_pages; k++)
			{
				int box_count = mu_doc.GetLinksPage(k);
				List<RectList> links = new List<RectList>();
				if (box_count > 0)
				{
					for (int j = 0; j < box_count; j++)
					{
						Point top_left;
						Size size;
						String uri;
						int type;
						int topage;

						mu_doc.GetLinkItem(j, out top_left, out size, out uri,
							out topage, out type);
						var rectlist = new RectList();
						rectlist.Height = size.Height * m_doczoom;
						rectlist.Width = size.Width * m_doczoom;
						rectlist.X = top_left.X * m_doczoom;
						rectlist.Y = top_left.Y * m_doczoom;
						rectlist.Color = m_linkcolor;
						rectlist.Index = k.ToString() + "." + j.ToString();
						rectlist.PageNum = topage;
						rectlist.Scale = m_doczoom;
						if (uri != null)
							rectlist.Urilink = new Uri(uri);
						rectlist.Type = (Link_t)type;
						links.Add(rectlist);
					}
				}
				mu_doc.ReleaseLink();
				m_page_link_list.Add(links);

				if (worker.CancellationPending == true)
				{
					e.Cancel = true;
					break;
				}
			}
		}

		private void LinkCompleted(object sender, RunWorkerCompletedEventArgs e)
		{
			LinksOn();
		}

		private void ScaleLinkBox(int pagenum)
		{
			var temp = m_docPages[pagenum].LinkBox;
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
			m_docPages[pagenum].LinkBox = temp;
		}
		/* Merge these */
		private void ScaleTextLines(int pagenum, double scale_factor)
		{
			var temp = m_lineptrs[pagenum];
			for (int kk = 0; kk < temp.Count; kk++)
			{
				var rect_item = temp[kk];
				double factor = scale_factor / temp[kk].Scale;

				temp[kk].Height = temp[kk].Height * factor;
				temp[kk].Width = temp[kk].Width * factor;
				temp[kk].X = temp[kk].X * factor;
				temp[kk].Y = temp[kk].Y * factor;

				temp[kk].Scale = scale_factor;
			}
			m_lineptrs[pagenum] = temp;
		}

		private void ScaleTextBlocks(int pagenum, double scale_factor)
		{
			var temp = m_textptrs[pagenum];
			for (int kk = 0; kk < temp.Count; kk++)
			{
				var rect_item = temp[kk];
				double factor = scale_factor / temp[kk].Scale;

				temp[kk].Height = temp[kk].Height * factor;
				temp[kk].Width = temp[kk].Width * factor;
				temp[kk].X = temp[kk].X * factor;
				temp[kk].Y = temp[kk].Y * factor;

				temp[kk].Scale = scale_factor;
			}
			m_textptrs[pagenum] = temp;
		}

		private int GetVisibleRange()
		{
			/* Need to figure out what pages are going to be visible */
			double bottom = this.ActualHeight;
			bool done = false;
			int final_page = m_currpage;
			double count = 0;

			while (!done)
			{
				count = count + m_thumbnails[final_page].NativeHeight * m_doczoom;
				final_page = final_page + 1;
				if (final_page == m_num_pages || count > bottom)
					done = true;
			}
			return final_page;
		}

		/* Only visible pages */
		private void LinksOff()
		{
			int final_page = GetVisibleRange();
			for (int kk = m_currpage - 1; kk <= final_page + 1; kk++)
			{
				var temp = m_docPages[kk].LinkBox;
				if (temp != null)
				{
					m_docPages[kk].LinkBox = null;
				}
			}
		}

		/* Only visible pages */
		private void LinksOn()
		{
			int final_page = GetVisibleRange();
			for (int kk = m_currpage - 1; kk <= final_page + 1; kk++)
			{
				if (!(kk < 0 || kk > m_num_pages - 1))
				{
					var temp = m_docPages[kk].LinkBox;
					if (temp == null)
					{
						m_docPages[kk].LinkBox = m_page_link_list[kk];
					}
				}
			}
		}

		private void LinkClick(object sender, MouseButtonEventArgs e)
		{
			var item = (Rectangle)sender;

			if (item == null)
				return;

			String tag = (String)item.Tag;
			int page = 0;
			int index = 0;

			if (tag == null || tag.Length < 3 || !(tag.Contains('.')))
				return;

			String[] parts = tag.Split('.');
			try
			{
				page = System.Convert.ToInt32(parts[0]);
				index = System.Convert.ToInt32(parts[1]);

			}
			catch (FormatException e1)
			{
				Console.WriteLine("String is not a sequence of digits.");
			}
			catch (OverflowException e2)
			{
				Console.WriteLine("The number cannot fit in an Int32.");
			}

			if (index >= 0 && index < m_num_pages && page >= 0 && page < m_num_pages)
			{
				var link_list = m_page_link_list[page];
				var link = link_list[index];

				if (link.Type == Link_t.LINK_GOTO)
				{
					if (m_currpage != link.PageNum && link.PageNum >= 0 &&
						link.PageNum < m_num_pages)
						RenderRange(link.PageNum, true, zoom_t.NO_ZOOM, 0);
				}
				else if (link.Type == Link_t.LINK_URI)
					System.Diagnostics.Process.Start(link.Urilink.AbsoluteUri);
			}
		}
		#endregion Link

		#region TextSelection

		/* Change cursor if we are over text block */
		private void ExitTextBlock(object sender, System.Windows.Input.MouseEventArgs e)
		{
			this.Cursor = System.Windows.Input.Cursors.Arrow;
		}

		private void EnterTextBlock(object sender, System.Windows.Input.MouseEventArgs e)
		{
			this.Cursor = System.Windows.Input.Cursors.IBeam;
		}

		private void ClearSelections()
		{
			for (int kk = 0; kk < m_textSelect.Count; kk++)
			{
				m_lineptrs[m_textSelect[kk].pagenum].Clear();
				if (m_docPages[m_textSelect[kk].pagenum].SelectedLines != null)
					m_docPages[m_textSelect[kk].pagenum].SelectedLines.Clear();
			}
			m_textSelect.Clear();
			m_textselected = false;
			m_selectall = false;
			SetSelectAll(m_blockcolor);
		}

		private void InitTextSelection(DocPage page)
		{
			if (m_textSelect != null)
				ClearSelections();
			else
				m_textSelect = new List<textSelectInfo_t>();

			m_intxtselect = true;

			textSelectInfo_t selinfo = new textSelectInfo_t();
			selinfo.pagenum = page.PageNum;
			selinfo.first_line_full = false;
			selinfo.last_line_full = false;
			m_textSelect.Add(selinfo);
		}

		private void PageMouseDown(object sender, MouseButtonEventArgs e)
		{
			if (this.Cursor != System.Windows.Input.Cursors.IBeam)
				return;

			var page = ((FrameworkElement)e.Source).DataContext as DocPage;
			Canvas can = ((FrameworkElement)e.Source).Parent as Canvas;
			if (page == null || can == null)
				return;

			InitTextSelection(page);
			var posit = e.GetPosition(can);

			page.SelX = posit.X;
			page.SelY = posit.Y;
			page.SelAnchorX = posit.X;
			page.SelAnchorY = posit.Y;
			page.SelColor = m_regionselect;

			/* Create new holder for lines highlighted */
			m_lineptrs[page.PageNum] = new LinesText();
		}

		private void PageMouseMove(object sender, System.Windows.Input.MouseEventArgs e)
		{
			if (e.LeftButton == MouseButtonState.Released || m_intxtselect == false)
				return;

			var page = ((FrameworkElement)e.Source).DataContext as DocPage;
			Canvas can = ((FrameworkElement)e.Source).Parent as Canvas;
			if (page == null || can == null)
				return;
			if (page.PageNum < 0)
				return;
			/* Store the location of our most recent page in case we exit window */
			var pos = e.GetPosition(can);
			m_lastY = pos.Y;
			m_maxY = can.Height;
			/* Don't allow the listview to maintain control of the mouse, we need
			 * to detect if we leave the window */
			/* Make sure page is rendered */
			if (page.Content != Page_Content_t.FULL_RESOLUTION ||
				page.Zoom != m_doczoom)
			{
				RenderRange(page.PageNum, false, zoom_t.NO_ZOOM, 0);
			}

			UpdateSelection(pos, page);
		}

		/* Resize selection rect */
		private void UpdateSelection(System.Windows.Point pos, DocPage page)
		{
			bool new_page = true;
			TextLine start_line, end_line;
			double x = 0, y, w = 0, h;
			bool found_first = false;
			bool above_anchor = true;
			bool first_line_full = false;
			bool last_line_full = false;

			for (int kk = 0; kk < m_textSelect.Count; kk++)
				if (m_textSelect[kk].pagenum == page.PageNum)
					new_page = false;

			/* See if we have gone back to a previous page */
			if (!new_page && page.PageNum != m_textSelect[m_textSelect.Count - 1].pagenum)
			{
				DocPage curr_page = m_docPages[m_textSelect[m_textSelect.Count - 1].pagenum];
				curr_page.SelHeight = 0;
				curr_page.SelWidth = 0;
				m_textSelect.RemoveAt(m_textSelect.Count - 1);
				m_lineptrs[curr_page.PageNum].Clear();
				curr_page.SelectedLines.Clear();
			}
			if (new_page)
			{
				/* New page */
				page.SelX = pos.X;
				page.SelY = pos.Y;
				page.SelAnchorX = m_docPages[m_textSelect[m_textSelect.Count - 1].pagenum].SelAnchorX;
				if (m_textSelect[m_textSelect.Count - 1].pagenum > page.PageNum)
				{
					page.SelAnchorY = page.Height;
				}
				else
				{
					page.SelAnchorY = 0;
				}
				page.SelColor = m_regionselect;
				textSelectInfo_t info = new textSelectInfo_t();
				info.pagenum = page.PageNum;
				info.first_line_full = false;
				info.last_line_full = false;
				m_textSelect.Add(info);
				/* Create new holder for lines highlighted */
				m_lineptrs[page.PageNum] = new LinesText();
			}

			if (page.TextBlocks == null || page.TextBlocks.Count == 0)
				return;

			/* Width changes translate across the pages */
			for (int jj = 0; jj < m_textSelect.Count; jj++)
			{
				DocPage curr_page = m_docPages[m_textSelect[jj].pagenum];
				x = Math.Min(pos.X, curr_page.SelAnchorX);
				w = Math.Max(pos.X, curr_page.SelAnchorX) - x;
				curr_page.SelX = x;
				curr_page.SelWidth = w;
			}
			/* Height is just the current page */
			y = Math.Min(pos.Y, page.SelAnchorY);
			h = Math.Max(pos.Y, page.SelAnchorY) - y;

			/* Determine if we are going up or down */
			if (pos.Y > page.SelAnchorY)
				above_anchor = false;
			page.SelY = y;
			page.SelHeight = h;

			/* Clear out what we currently have */
			m_lineptrs[page.PageNum].Clear();

			/* Stuff already selected above us */
			if (m_textSelect.Count > 1)
				found_first = true;
			/* Moving backwards through pages */
			if (m_textSelect.Count > 1 && m_textSelect[m_textSelect.Count - 2].pagenum > page.PageNum)
				found_first = false;

			for (int jj = 0; jj < page.TextBlocks.Count; jj++)
			{
				/* Text blocks are already scaled. Lines are not */
				var intersect_blk = page.TextBlocks[jj].CheckIntersection(x, y, w, h);
				var lines = page.TextBlocks[jj].TextLines;

				if (intersect_blk == Intersection_t.FULL)
				{
					/* Just add all the lines for this block */
					for (int kk = 0; kk < lines.Count; kk++)
						m_lineptrs[page.PageNum].Add(lines[kk]);
					if (jj == 0)
					{
						first_line_full = true;
						found_first = true;
					}
					if (jj == page.TextBlocks.Count - 1)
						last_line_full = true;
				}
				else if (intersect_blk != Intersection_t.NONE)
				{
					/* Now go through the lines */
					for (int kk = 0; kk < lines.Count; kk++)
					{
						double scale = m_doczoom / lines[kk].Scale;
						//var intersect_line = lines[kk].CheckIntersection(x * scale, y * scale, w * scale, h * scale);
						var intersect_line = lines[kk].CheckIntersection(x / scale , y / scale , w / scale , h / scale);
						if (intersect_line == Intersection_t.FULL)
						{
							m_lineptrs[page.PageNum].Add(lines[kk]);
							found_first = true;
							if (jj == 0 && kk == 0)
								first_line_full = true;
							if (jj == page.TextBlocks.Count - 1 && 
								kk == lines.Count - 1)
								last_line_full = true;

						}
						else if (intersect_line == Intersection_t.PARTIAL)
						{
							double val;
							var lett = lines[kk].TextCharacters;

							/* Now go through the width. */
							if (found_first)
							{
								if (above_anchor)
									val = page.SelAnchorX;
								else
									val = pos.X;

								/* our second partial line */
								if (val > lines[kk].X * scale + lines[kk].Width * scale)
									m_lineptrs[page.PageNum].Add(lines[kk]);
								else
								{
									/* Use either anchor point or mouse pos */
									end_line = new TextLine();
									end_line.TextCharacters = new List<TextCharacter>();
									end_line.Height = 0;
									end_line.Scale = m_doczoom;
									for (int mm = 0; mm < lett.Count; mm++)
									{
										double letscale = m_doczoom / lett[mm].Scale;
										if (lett[mm].X * letscale < val)
										{
											/* Can set to special color for debug */
											end_line.Color = m_textselectcolor;
											/* special color for debug */
											//end_line.Color = "#4000FF00";
											end_line.Height = lines[kk].Height * scale;
											end_line.Width = lett[mm].X * letscale + lett[mm].Width * letscale - lines[kk].X * scale;
											end_line.Y = lines[kk].Y * scale;
											end_line.X = lines[kk].X * scale;
											end_line.TextCharacters.Add(lett[mm]);
										}
										else
											break;
									}
									if (end_line.Height != 0)
										m_lineptrs[page.PageNum].Add(end_line);
								}
							}
							else
							{
								if (!above_anchor)
									val = page.SelAnchorX;
								else
									val = pos.X;

								/* our first partial line */
								found_first = true;
								if (val < lines[kk].X * scale)
									m_lineptrs[page.PageNum].Add(lines[kk]);
								else
								{
									start_line = new TextLine();
									start_line.TextCharacters = new List<TextCharacter>();
									start_line.Height = 0;
									start_line.Scale = m_doczoom;
									/* Use either anchor point or mouse pos */
									bool highlight_done = false;
									for (int mm = 0; mm < lett.Count; mm++)
									{
										double letscale = m_doczoom / lett[mm].Scale;
										if (lett[mm].X * letscale + lett[mm].Width * letscale >= val)
										{
											/* In this case, we are done with the 
											 * highlight section as it only
											 * depends upon the first character
											 * we encounter and the line end. 
											 * But we must continue to add in 
											 * the selected characters */
											if (!highlight_done)
											{
												start_line.Color = m_textselectcolor;
												/* special color for debug */
												/* start_line.Color = "#40FF0000"; */
												start_line.Height = lines[kk].Height * scale;
												start_line.Width = lines[kk].X * scale + lines[kk].Width * scale - lett[mm].X * letscale;
												start_line.X = lett[mm].X * letscale;
												start_line.Y = lines[kk].Y * scale;
												highlight_done = true;
											}
											start_line.TextCharacters.Add(lett[mm]);
										}
									}
									if (start_line.Height > 0)
										m_lineptrs[page.PageNum].Add(start_line);
								}
							}
						}
					}
				}
			}
			var txtsel = m_textSelect[m_textSelect.Count - 1];
			txtsel.first_line_full = first_line_full;
			txtsel.last_line_full = last_line_full;
			m_textSelect[m_textSelect.Count - 1] = txtsel;

			/* Adjust for scale before assigning */
			var temp = m_lineptrs[page.PageNum];
			for (int kk = 0; kk < temp.Count; kk++)
			{
				var rect_item = temp[kk];
				double factor = m_doczoom / rect_item.Scale;

				temp[kk].Height = temp[kk].Height * factor;
				temp[kk].Width = temp[kk].Width * factor;
				temp[kk].X = temp[kk].X * factor;
				temp[kk].Y = temp[kk].Y * factor;

				temp[kk].Scale = m_doczoom;
			}
			page.SelectedLines = m_lineptrs[page.PageNum];
		}

		/* A fix for handling column cases TODO FIXME */
		private void UpdateSelectionCol(System.Windows.Point pos, DocPage page)
		{
			bool new_page = true;
			TextLine start_line, end_line;
			double x = 0, y, w = 0, h;
			bool found_first = false;
			bool above_anchor = true;
			bool first_line_full = false;
			bool last_line_full = false;

			for (int kk = 0; kk < m_textSelect.Count; kk++)
				if (m_textSelect[kk].pagenum == page.PageNum)
					new_page = false;

			/* See if we have gone back to a previous page */
			if (!new_page && page.PageNum != m_textSelect[m_textSelect.Count - 1].pagenum)
			{
				DocPage curr_page = m_docPages[m_textSelect[m_textSelect.Count - 1].pagenum];
				curr_page.SelHeight = 0;
				curr_page.SelWidth = 0;
				m_textSelect.RemoveAt(m_textSelect.Count - 1);
				m_lineptrs[curr_page.PageNum].Clear();
				curr_page.SelectedLines.Clear();
			}
			if (new_page)
			{
				/* New page */
				page.SelX = pos.X;
				page.SelY = pos.Y;
				page.SelAnchorX = m_docPages[m_textSelect[m_textSelect.Count - 1].pagenum].SelAnchorX;
				if (m_textSelect[m_textSelect.Count - 1].pagenum > page.PageNum)
				{
					page.SelAnchorY = page.Height;
				}
				else
				{
					page.SelAnchorY = 0;
				}
				page.SelColor = m_regionselect;
				textSelectInfo_t info = new textSelectInfo_t();
				info.pagenum = page.PageNum;
				info.first_line_full = false;
				info.last_line_full = false;
				m_textSelect.Add(info);
				/* Create new holder for lines highlighted */
				m_lineptrs[page.PageNum] = new LinesText();
			}

			if (page.TextBlocks == null || page.TextBlocks.Count == 0)
				return;

			/* Width changes translate across the pages */
			for (int jj = 0; jj < m_textSelect.Count; jj++)
			{
				DocPage curr_page = m_docPages[m_textSelect[jj].pagenum];
				x = Math.Min(pos.X, curr_page.SelAnchorX);
				w = Math.Max(pos.X, curr_page.SelAnchorX) - x;
				curr_page.SelX = x;
				curr_page.SelWidth = w;
			}
			/* Height is just the current page */
			y = Math.Min(pos.Y, page.SelAnchorY);
			h = Math.Max(pos.Y, page.SelAnchorY) - y;

			/* Determine if we are going up or down */
			if (pos.Y > page.SelAnchorY)
				above_anchor = false;
			page.SelY = y;
			page.SelHeight = h;

			/* Clear out what we currently have */
			m_lineptrs[page.PageNum].Clear();

			/* Stuff already selected above us */
			if (m_textSelect.Count > 1)
				found_first = true;
			/* Moving backwards through pages */
			if (m_textSelect.Count > 1 && m_textSelect[m_textSelect.Count - 2].pagenum > page.PageNum)
				found_first = false;

			/* To properly handle the multiple columns we have to find the last 
			 * line and make sure that all blocks between our first and last
			 * line are included. To do this we do an initial step through the
			 * blocks looking at our intersections */
			int first_block = -1;
			int last_block = -1;
			for (int jj = 0; jj < page.TextBlocks.Count; jj++ )
			{
				var intersect_blk = page.TextBlocks[jj].CheckIntersection(x, y, w, h);
				if (intersect_blk == Intersection_t.NONE && first_block != -1)
				{
					last_block = jj; /* NB: this is just past last block */
					break;
				}
				else if (intersect_blk != Intersection_t.NONE && first_block == -1)
					first_block = jj; /* NB: this is the first block */
			}
			if (first_block == -1)
				return;
			if (last_block == -1)
			{
				/* Only 1 block */
				last_block = first_block + 1;
			}

			for (int jj = first_block; jj < last_block; jj++)
			{
				/* Text blocks are already scaled. Lines are not */
				var intersect_blk = page.TextBlocks[jj].CheckIntersection(x, y, w, h);
				var lines = page.TextBlocks[jj].TextLines;

				if (jj == first_block || jj == last_block - 1)
				{
					/* Partial cases */
					if (intersect_blk == Intersection_t.FULL)
					{
						for (int kk = 0; kk < lines.Count; kk++)
							m_lineptrs[page.PageNum].Add(lines[kk]);
						if (jj == first_block)
						{
							first_line_full = true;
							found_first = true;
						}
						if (jj == last_block - 1)
						{
							last_line_full = true;
						}
					}
					else if (intersect_blk == Intersection_t.PARTIAL)
					{
						for (int kk = 0; kk < lines.Count; kk++)
						{
							double scale = m_doczoom / lines[kk].Scale;
							var intersect_line = lines[kk].CheckIntersection(x * scale, y * scale, w * scale, h * scale);
							if (intersect_line == Intersection_t.FULL)
							{
								m_lineptrs[page.PageNum].Add(lines[kk]);
								found_first = true;
								if (jj == 0 && kk == 0)
									first_line_full = true;
								if (jj == page.TextBlocks.Count - 1 &&
									kk == lines.Count - 1)
									last_line_full = true;

							}
							else if (intersect_line == Intersection_t.PARTIAL)
							{
								double val;
								var lett = lines[kk].TextCharacters;

								/* Now go through the width. */
								if (found_first)
								{
									if (above_anchor)
										val = page.SelAnchorX;
									else
										val = pos.X;

									/* our second partial line */
									if (val > lines[kk].X * scale + lines[kk].Width * scale)
										m_lineptrs[page.PageNum].Add(lines[kk]);
									else
									{
										/* Use either anchor point or mouse pos */
										end_line = new TextLine();
										end_line.TextCharacters = new List<TextCharacter>();
										end_line.Height = 0;
										end_line.Scale = m_doczoom;
										for (int mm = 0; mm < lett.Count; mm++)
										{
											double letscale = m_doczoom / lett[mm].Scale;
											if (lett[mm].X * letscale < val)
											{
												/* Can set to special color for debug */
												end_line.Color = m_textselectcolor;
												/* special color for debug */
												//end_line.Color = "#4000FF00";
												end_line.Height = lines[kk].Height * scale;
												end_line.Width = lett[mm].X * letscale + lett[mm].Width * letscale - lines[kk].X * scale;
												end_line.Y = lines[kk].Y * scale;
												end_line.X = lines[kk].X * scale;
												end_line.TextCharacters.Add(lett[mm]);
											}
											else
												break;
										}
										if (end_line.Height != 0)
											m_lineptrs[page.PageNum].Add(end_line);
									}
								}
								else
								{
									if (!above_anchor)
										val = page.SelAnchorX;
									else
										val = pos.X;

									/* our first partial line */
									found_first = true;
									if (val < lines[kk].X * scale)
										m_lineptrs[page.PageNum].Add(lines[kk]);
									else
									{
										start_line = new TextLine();
										start_line.TextCharacters = new List<TextCharacter>();
										start_line.Height = 0;
										start_line.Scale = m_doczoom;
										/* Use either anchor point or mouse pos */
										for (int mm = 0; mm < lett.Count; mm++)
										{
											double letscale = m_doczoom / lett[mm].Scale;
											if (lett[mm].X * letscale + lett[mm].Width * letscale >= val)
											{
												start_line.Color = m_textselectcolor;
												/* special color for debug */
												//start_line.Color = "#40FF0000";
												start_line.Height = lines[kk].Height * scale;
												start_line.Width = lines[kk].X * scale + lines[kk].Width * scale - lett[mm].X * letscale;
												start_line.X = lett[mm].X * letscale;
												start_line.Y = lines[kk].Y * scale;
												start_line.TextCharacters.Add(lett[mm]);
												break;
											}
										}
										if (start_line.Height > 0)
											m_lineptrs[page.PageNum].Add(start_line);
									}
								}
							}
						}
					}
				}
				else
				{
					/* Add all the lines for the blocks between the first and last */
					for (int kk = 0; kk < lines.Count; kk++)
						m_lineptrs[page.PageNum].Add(lines[kk]);
				}
			}

			var txtsel = m_textSelect[m_textSelect.Count - 1];
			txtsel.first_line_full = first_line_full;
			txtsel.last_line_full = last_line_full;
			m_textSelect[m_textSelect.Count - 1] = txtsel;

			/* Adjust for scale before assigning */
			var temp = m_lineptrs[page.PageNum];
			for (int kk = 0; kk < temp.Count; kk++)
			{
				var rect_item = temp[kk];
				double factor = m_doczoom / rect_item.Scale;

				temp[kk].Height = temp[kk].Height * factor;
				temp[kk].Width = temp[kk].Width * factor;
				temp[kk].X = temp[kk].X * factor;
				temp[kk].Y = temp[kk].Y * factor;

				temp[kk].Scale = m_doczoom;
			}
			page.SelectedLines = m_lineptrs[page.PageNum];
		}

		private void CheckIfSelected()
		{
			m_textselected = false;

			if (m_selectall)
			{
				SetSelectAll(m_blockcolor);
				m_selectall = false;
			}
			/* Check if anything was selected */
			for (int kk = 0; kk < m_lineptrs.Count; kk++)
			{
				if (m_lineptrs[kk].Count > 0)
				{
					m_textselected = true;
					break;
				}
			}
		}

		/* Rect should be removed */
		private void PageLeftClickUp(object sender, MouseButtonEventArgs e)
		{
			m_intxtselect = false;
			CheckIfSelected();
		}

		private void StepScroll(int stepsize)
		{
			ScrollViewer viewer = FindScrollViewer(xaml_PageList);
			if (viewer != null)
			{
				var scrollpos = viewer.VerticalOffset;
				viewer.ScrollToVerticalOffset(scrollpos + stepsize);
			}
		}

		private void ResetScroll()
		{
			ScrollViewer viewer = FindScrollViewer(xaml_PageList);
			if (viewer != null)
				viewer.ScrollToVerticalOffset(0);
		}

		/* Recursive call to find the scroll viewer */
		private ScrollViewer FindScrollViewer(DependencyObject d)
		{
			if (d is ScrollViewer)
				return d as ScrollViewer;

			for (int i = 0; i < VisualTreeHelper.GetChildrenCount(d); i++)
			{
				var sw = FindScrollViewer(VisualTreeHelper.GetChild(d, i));
				if (sw != null) return sw;
			}
			return null;
		}

		/* Only worry about cases where we are moving and left button is down */
		private void ListPreviewMouseMove(object sender, System.Windows.Input.MouseEventArgs e)
		{
			var relPoint = e.GetPosition(xaml_PageList);
			var absPoint = this.PointToScreen(relPoint);
			/* Console.Write("abs Y position = " + absPoint.Y + "\n");
			Console.Write("rel Y position = " + relPoint.Y + "\n");
			Console.Write("Height is = " + (this.Top + this.Height) + "\n"); */

			if (xaml_PageList.IsMouseCaptured == true)
			{
				if (!m_intxtselect)
				{
					xaml_PageList.ReleaseMouseCapture();
					e.Handled = true;
					return;
				}

				if (relPoint.Y < Constants.SCROLL_EDGE_BUFFER ||
					absPoint.Y > (this.Top + this.Height - Constants.SCROLL_EDGE_BUFFER))
				{
					if (m_dispatcherTimer == null)
					{
						m_dispatcherTimer = new System.Windows.Threading.DispatcherTimer();
						m_dispatcherTimer.Tick += new EventHandler(dispatcherTimerTick);
						m_dispatcherTimer.Interval = new TimeSpan(0, 0, 0, 0, Constants.DISPATCH_TIME);
					}
					if (m_dispatcherTimer.IsEnabled == false)
						m_dispatcherTimer.Start();
					e.Handled = true;
				}

				/* This is not desirable, but the scrollviewer behaves badly
				 * when it has captured the mouse and we move beyond the
				 * range. So we wont allow it */
				if (relPoint.Y < 0 ||
					absPoint.Y > (this.Top + this.Height) - Constants.SCROLL_EDGE_BUFFER / 2.0)
				{
					xaml_PageList.ReleaseMouseCapture();
					e.Handled = true;
					if (m_dispatcherTimer != null && m_dispatcherTimer.IsEnabled == true)
						m_dispatcherTimer.Stop();
					return;
				}
			}
		}

		private void ListPreviewMouseLeftButtonDown(object sender, MouseButtonEventArgs e)
		{
			if (m_dispatcherTimer != null && m_dispatcherTimer.IsEnabled)
			{
				m_dispatcherTimer.Stop();
			}
		}

		private void ListMouseLeave(object sender, System.Windows.Input.MouseEventArgs e)
		{
			if (m_dispatcherTimer != null && m_dispatcherTimer.IsEnabled)
			{
				m_dispatcherTimer.Stop();
			}
			if (xaml_PageList.IsMouseCaptured == true)
				xaml_PageList.ReleaseMouseCapture();
		}

		/* Get mouse position, update selection accordingly */
		private void dispatcherTimerTick(object sender, EventArgs e)
		{
			var position = this.PointToScreen(Mouse.GetPosition(xaml_PageList));
			/* Console.Write("Y position = " + position.Y + "\n");
			Console.Write("Top position = " + this.Top + "\n");
			Console.Write("Bottom position = " + (this.Top + this.Height) + "\n"); */
			DocPage page;
			int page_num;

			if (!xaml_PageList.IsMouseCaptured)
			{
				//Console.Write("Lost capture\n");
				return;
			}
			/*else
			{
				Console.Write("Have capture\n");
			} */
			/* Get our most recent page */
			var pageinfo = m_textSelect[m_textSelect.Count - 1];
			page_num = pageinfo.pagenum;

			/* Scrolling up */
			if (position.Y > this.Top + this.Height - Constants.SCROLL_EDGE_BUFFER)
			{
				/* See if we have the last line for this page */
				if (pageinfo.last_line_full)
				{
					page_num = page_num + 1;
					m_lastY = 0;
					if (page_num >= m_num_pages)
						return;
				}
				page = m_docPages[page_num];
				StepScroll(Constants.SCROLL_STEP);
				/* Set position for proper selection update */
				m_lastY = m_lastY + Constants.SCROLL_STEP;
				if (m_lastY > m_maxY)
					m_lastY = m_maxY;
				position.Y = m_lastY;
				UpdateSelection(position, page);
			}
			else if (position.Y < this.Top + Constants.SCROLL_EDGE_BUFFER)
			{
				/* See if we have the first line for this page */
				if (pageinfo.first_line_full)
				{
					if (page_num <= 0)
						return;
					page_num = page_num - 1;
					m_lastY = m_docPages[page_num].Height;
				}
				page = m_docPages[page_num];
				StepScroll(-Constants.SCROLL_STEP);
				/* Set position for proper selection update */
				m_lastY = m_lastY - Constants.SCROLL_STEP;
				if (m_lastY < 0)
					m_lastY = 0;
				position.Y = m_lastY;
				UpdateSelection(position, page);
			}
		}

		private void ListPreviewLeftButtonUp(object sender, MouseButtonEventArgs e)
		{
			if (m_dispatcherTimer != null && m_dispatcherTimer.IsEnabled)
			{
				m_dispatcherTimer.Stop();
			}
		}

		private void ShowContextMenu(object sender, MouseButtonEventArgs e)
		{
			if (this.Cursor != System.Windows.Input.Cursors.IBeam)
				return;

			var contextmenu = new System.Windows.Controls.ContextMenu();
			Canvas can = ((FrameworkElement)e.Source).Parent as Canvas;
			var page = ((FrameworkElement)e.Source).DataContext as DocPage;
			if (can == null || page == null)
				return;

			var posit = e.GetPosition(can);
			ContextMenu_t info = new ContextMenu_t();
			info.mouse_position = posit;
			info.page_num = page.PageNum;
			can.ContextMenu = contextmenu;

			if (m_textselected || m_selectall)
			{
				var m1 = new System.Windows.Controls.MenuItem();
				m1.Header = "Copy";

				/* amazing what I have to do here to get the icon out of the
				 * resources into something that wpf can use */
				var iconres = Properties.Resources.copy;
				var bitmap = iconres.ToBitmap();
				using (MemoryStream memory = new MemoryStream())
				{
					bitmap.Save(memory, System.Drawing.Imaging.ImageFormat.Png);
					memory.Position = 0;
					BitmapImage bitmapImage = new BitmapImage();
					bitmapImage.BeginInit();
					bitmapImage.StreamSource = memory;
					bitmapImage.CacheOption = BitmapCacheOption.OnLoad;
					bitmapImage.EndInit();
					Image iconImage = new Image();
					iconImage.Source = bitmapImage;
					m1.Icon = iconImage;
					m1.Click += cntxMenuCopy;
					contextmenu.Items.Add(m1);
				}

				var m6 = new System.Windows.Controls.MenuItem();
				m6.Header = "Deselect All";
				m6.Click += cntxMenuDeselectAll;
				contextmenu.Items.Add(m6);

				/* Below to be enabled when we add annotations */
				/*
				var ma1 = new System.Windows.Controls.MenuItem();
				ma1.Header = "Highlight";
				ma1.Click += cntxMenuHighlight;
				contextmenu.Items.Add(ma1);

				var ma2 = new System.Windows.Controls.MenuItem();
				ma2.Header = "Underline";
				ma2.Click += cntxMenuUnderline;
				contextmenu.Items.Add(ma2);

				var ma3 = new System.Windows.Controls.MenuItem();
				ma3.Header = "Strikeout";
				ma3.Click += cntxMenuStrike;
				contextmenu.Items.Add(ma3);*/

			}
			var m2 = new System.Windows.Controls.MenuItem();
			m2.Header = "Select Line";
			m2.Click += cntxMenuSelectLine;
			m2.Tag = info;
			contextmenu.Items.Add(m2); 
				
			var m3 = new System.Windows.Controls.MenuItem();
			m3.Header = "Select Block";
			m3.Click += cntxMenuSelectBlock;
			m3.Tag = info;
			contextmenu.Items.Add(m3);

			var m4 = new System.Windows.Controls.MenuItem();
			m4.Header = "Select Page";
			m4.Click += cntxMenuSelectPage;
			m4.Tag = info;
			contextmenu.Items.Add(m4);

			var m5 = new System.Windows.Controls.MenuItem();
			m5.Header = "Select All";
			m5.Click += cntxMenuSelectAll;
			contextmenu.Items.Add(m5);
		}

		private void CopyTextDone(object sender, RunWorkerCompletedEventArgs e)
		{
			String result = (String) e.Result;
			xaml_CopyTextProgress.Visibility = System.Windows.Visibility.Collapsed;
			xaml_CopyTextProgress.Value = 0;

			try
			{
				System.Windows.Clipboard.SetText(result);
			}
			catch
			{
				return;
			}
		}

		private void CopyTextWork(object sender, DoWorkEventArgs e)
		{
			String output = null;
			String fullstring = null;
			BackgroundWorker worker = sender as BackgroundWorker;

			for (int k = 0; k < m_num_pages; k++)
			{
				output = mu_doc.GetText(k, textout_t.TEXT);
				if (output != null)
					fullstring = fullstring + output;

				double percent = 100 * (double)(k + 1) / (double)m_num_pages;
				worker.ReportProgress((int)percent, output);

				if (worker.CancellationPending == true)
				{
					e.Cancel = true;
					break;
				}
			}
			e.Result = fullstring;
		}

		private void CopyTextProgress(object sender, ProgressChangedEventArgs e)
		{
			String output = (String)(e.UserState);
			xaml_CopyTextProgress.Value = e.ProgressPercentage;
		}

		private void cntxMenuCopy(object sender, RoutedEventArgs e)
		{
			if (m_selectall)
			{
				/* Start a thread to go through and copy the pages to the 
				 * clipboard */
				m_copytext = new BackgroundWorker();
				m_copytext.WorkerReportsProgress = true;
				m_copytext.WorkerSupportsCancellation = true;
				m_copytext.DoWork += new DoWorkEventHandler(CopyTextWork);
				m_copytext.RunWorkerCompleted += new RunWorkerCompletedEventHandler(CopyTextDone);
				m_copytext.ProgressChanged += new ProgressChangedEventHandler(CopyTextProgress);
				xaml_CopyTextProgress.Visibility = System.Windows.Visibility.Visible;
				m_copytext.RunWorkerAsync();
				return;
			}

			/* Go through and get each line of text */
			String result = null;

			for (int kk = 0; kk < m_textSelect.Count; kk++)
			{
				var lines = m_lineptrs[m_textSelect[kk].pagenum];
				for (int jj = 0; jj < lines.Count; jj++)
				{
					var text = lines[jj].TextCharacters;
					for (int mm = 0; mm < text.Count; mm++)
					{
						result += text[mm].character;
					}
					result += "\r\n";
				}
			}
			System.Windows.Clipboard.SetText(result);
		}

		private void cntxMenuSelectLine(object sender, RoutedEventArgs e)
		{
			var mi = sender as System.Windows.Controls.MenuItem;
			ContextMenu_t info = (ContextMenu_t)mi.Tag;
			var page = m_docPages[info.page_num];

			InitTextSelection(page);

			page.SelX = 0;
			page.SelY = info.mouse_position.Y - 1;
			page.SelAnchorX = 0;
			page.SelAnchorY = info.mouse_position.Y - 1;
			page.SelColor = m_regionselect;

			/* Create new holder for lines highlighted */
			m_lineptrs[page.PageNum] = new LinesText();

			Point pos = new Point();
			pos.X = page.Width;
			pos.Y += info.mouse_position.Y + 1;

			UpdateSelection(pos, page);
			CheckIfSelected();
		}

		/* This one requires its own special handling TODO FIXME */
		private void cntxMenuSelectBlock(object sender, RoutedEventArgs e)
		{
			var mi = sender as System.Windows.Controls.MenuItem;
			ContextMenu_t info = (ContextMenu_t)mi.Tag;
			var page = m_docPages[info.page_num];
			bool found = false;
			int jj;

			InitTextSelection(page);

			/* Find the block that we are in */
			for (jj = 0; jj < page.TextBlocks.Count; jj++)
			{
				var intersect_blk = page.TextBlocks[jj].CheckIntersection(info.mouse_position.X, info.mouse_position.Y, 1, 1);
				if (intersect_blk != Intersection_t.NONE)
				{
					found = true;
					break;
				}
			}
			if (found)
			{
				page.SelX = page.TextBlocks[jj].X;
				page.SelY = page.TextBlocks[jj].Y;
				page.SelAnchorX = page.TextBlocks[jj].X;
				page.SelAnchorY = page.TextBlocks[jj].Y;
				page.SelColor = m_regionselect;

				/* Create new holder for lines highlighted */
				m_lineptrs[page.PageNum] = new LinesText();

				Point pos = new Point();
				pos.X = page.TextBlocks[jj].X + page.TextBlocks[jj].Width;
				pos.Y = page.TextBlocks[jj].Y + page.TextBlocks[jj].Height;

				UpdateSelection(pos, page);
				CheckIfSelected();
			}
			else
				m_textselected = false;
		}

		private void SelectFullPage(int page_num)
		{
			var page = m_docPages[page_num];

			InitTextSelection(page);

			page.SelX = 0;
			page.SelY = 0;
			page.SelAnchorX = 0;
			page.SelAnchorY = 0;
			page.SelColor = m_regionselect;

			/* Create new holder for lines highlighted */
			m_lineptrs[page.PageNum] = new LinesText();

			Point pos = new Point();
			pos.X = page.Width;
			pos.Y = page.Height;

			UpdateSelection(pos, page);
		}

		private void cntxMenuSelectPage(object sender, RoutedEventArgs e)
		{
			var mi = sender as System.Windows.Controls.MenuItem;
			ContextMenu_t info = (ContextMenu_t)mi.Tag;

			SelectFullPage(info.page_num);
			CheckIfSelected();
		}

		private void cntxMenuSelectAll(object sender, RoutedEventArgs e)
		{
			var mi = sender as System.Windows.Controls.MenuItem;
			if (m_textSelect != null)
				ClearSelections();
			else
				m_textSelect = new List<textSelectInfo_t>();

			m_selectall = true;
			SetSelectAll(m_textselectcolor);
		}

		private void SetSelectAll(String color)
		{
			if (!m_init_done)
				return;

			for (int kk = 0; kk < m_num_pages; kk++)
			{
				if (m_docPages[kk] != null && m_docPages[kk].TextBlocks != null)
				{
					int num_blocks = m_docPages[kk].TextBlocks.Count;
					for (int jj = 0; jj < num_blocks; jj++)
						m_docPages[kk].TextBlocks[jj].Color = color;
				}
			}
		}

		private void cntxMenuDeselectAll(object sender, RoutedEventArgs e)
		{
			ClearSelections();
		}

		private void SelectAllCommand(object sender, ExecutedRoutedEventArgs e)
		{
			if (m_init_done)
				cntxMenuSelectAll(sender, e);
		}

		private void CopyCommand(object sender, ExecutedRoutedEventArgs e)
		{
			if (m_init_done)
				cntxMenuCopy(sender, e);
		}

		private void CancelCopyText(object sender, RoutedEventArgs e)
		{
			if (m_copytext != null && m_copytext.IsBusy)
				m_copytext.CancelAsync();
		}

		/* To add with annotation support */
		/*
		private void cntxMenuHighlight(object sender, RoutedEventArgs e)
		{
		
		}

		private void cntxMenuUnderline(object sender, RoutedEventArgs e)
		{

		}

		private void cntxMenuStrike(object sender, RoutedEventArgs e)
		{

		}
		*/
		#endregion TextSelection

		private void OnAboutClick(object sender, RoutedEventArgs e)
		{
			String muversion;
			About about = new About(this);
			var desc_static = about.Description;
			String desc;

			/* Get our gs and mupdf version numbers to add to the description */
			mu_doc.GetVersion(out muversion);
			if (muversion == null)
				desc = desc_static + "\nMuPDF DLL: Not Found";
			else
			{
				if (mu_doc.is64bit)
				{
					desc = desc_static + "\nUsing MuPDF Version " + muversion + " 64 bit\n";
				} 
				else
				{
					desc = desc_static + "\nUsing MuPDF Version " + muversion + " 32 bit\n";
				}
			}
			String gs_vers = m_ghostscript.GetVersion();
			if (gs_vers == null)
				desc = desc + "\nGhostscript DLL: Not Found";
			else
				if (mu_doc.is64bit)
				{
					desc = desc + "\nGhostscript DLL: " + gs_vers + " 64 bit\n";
				}
				else
				{
					desc = desc + "\nGhostscript DLL: " + gs_vers + " 64 bit\n";
				}
			about.description.Text = desc;
			about.ShowDialog();
		}

		private void HelpCommand(object sender, ExecutedRoutedEventArgs e)
		{
			OnHelpClick(sender, e);
		}

		private void OnHelpClick(object sender, RoutedEventArgs e)
		{

		}

		private void CloseFile(object sender, RoutedEventArgs e)
		{
			CleanUp();
			DimSelections();
		}

		private double GetTotalHeightZoom()
		{
			return m_totalpageheight * m_doczoom + (m_num_pages - 1) * Constants.PAGE_MARGIN;
		}

		private double GetTotalHeightNoZoom()
		{
			return m_totalpageheight + (m_num_pages - 1) * Constants.PAGE_MARGIN;
		}

		private double GetViewPortSize()
		{
			ScrollViewer viewer = FindScrollViewer(xaml_PageList);
			return viewer.ViewportHeight;
		}

		private void SetThumbwidth()
		{
			double percent = GetViewPortSize() / GetTotalHeightZoom();
			double range = xaml_VerticalScroll.Maximum - xaml_VerticalScroll.Minimum;
			xaml_VerticalScroll.SetThumbLength(percent * range);
		}

		private void AdjustScrollPercent(double percent)
		{
			double curr_value = xaml_VerticalScroll.Value;
			double range = xaml_VerticalScroll.Maximum;
			double step = range * percent;

			xaml_VerticalScroll.Value = curr_value + step;
		}

		/* Due to the scroll bar on the scroll viewer being wonky on its updating during zooming
		 * we have to do this ourselves */
		private void VerticalScroll(object sender, System.Windows.Controls.Primitives.ScrollEventArgs e)
		{
			var mi = sender as System.Windows.Controls.Primitives.ScrollBar;
			ScrollViewer viewer = FindScrollViewer(xaml_PageList);
			if (viewer == null || mi == null)
				return;

			m_ScrolledChanged = true;

			if (e.ScrollEventType == System.Windows.Controls.Primitives.ScrollEventType.ThumbTrack)
			{
				OffsetScrollPercent(mi.Value / mi.Maximum);
				e.Handled = true;
			}
			else if (e.ScrollEventType == System.Windows.Controls.Primitives.ScrollEventType.First)
			{
				mi.Value = 0;
				viewer.ScrollToTop();
			}
			else if (e.ScrollEventType == System.Windows.Controls.Primitives.ScrollEventType.Last)
			{
				mi.Value = mi.Maximum;
				viewer.ScrollToBottom();
			}
			else if (e.ScrollEventType == System.Windows.Controls.Primitives.ScrollEventType.SmallDecrement)
			{
				OffsetScroll(-Constants.VERT_SCROLL_STEP * m_doczoom);
			}
			else if (e.ScrollEventType == System.Windows.Controls.Primitives.ScrollEventType.SmallIncrement)
			{
				OffsetScroll(Constants.VERT_SCROLL_STEP * m_doczoom);
			}
			else if (e.ScrollEventType == System.Windows.Controls.Primitives.ScrollEventType.LargeDecrement)
			{
				if (m_currpage == 0)
				{
					mi.Value = 0;
					viewer.ScrollToTop();
				}
				else
					OnBackPageClick(null, null);
			}
			else if (e.ScrollEventType == System.Windows.Controls.Primitives.ScrollEventType.LargeIncrement)
			{
				if (m_currpage == m_num_pages - 1)
				{
					mi.Value = mi.Maximum;
					viewer.ScrollToBottom();
				}
				else
					OnForwardPageClick(null, null);
			}
			else if (e.ScrollEventType == System.Windows.Controls.Primitives.ScrollEventType.ThumbPosition)
			{
				OffsetScrollPercent(e.NewValue / mi.Maximum);
			}
		}

		private void OnAAChecked(object sender, RoutedEventArgs e)
		{
			var control = sender as System.Windows.Controls.Control;
			string Name = control.Name;

			/* It would be nice to uncheck all and then recheck the one
			 * that we want to avoid the repeated code below, but that puts
			 * us in a infinite recursion with the call from the xaml Checked
			 * call */

			switch (Name)
			{
				case "xaml_AA_High":
					m_AA = AA_t.HIGH;
					if (xaml_AA_MedHigh != null)
						xaml_AA_MedHigh.IsChecked = false;
					if (xaml_AA_Med != null)
						xaml_AA_Med.IsChecked = false;
					if (xaml_AA_Low != null)
						xaml_AA_Low.IsChecked = false;
					if (xaml_AA_None != null)
						xaml_AA_None.IsChecked = false;
					break;
				case "xaml_AA_MedHigh":
					m_AA = AA_t.MEDHIGH;
					if (xaml_AA_High != null)
						xaml_AA_High.IsChecked = false;
					if (xaml_AA_Med != null)
						xaml_AA_Med.IsChecked = false;
					if (xaml_AA_Low != null)
						xaml_AA_Low.IsChecked = false;
					if (xaml_AA_None != null)
						xaml_AA_None.IsChecked = false;
					break;
				case "xaml_AA_Med":
					m_AA = AA_t.MED;
					if (xaml_AA_High != null)
						xaml_AA_High.IsChecked = false;
					if (xaml_AA_MedHigh != null)
						xaml_AA_MedHigh.IsChecked = false;
					if (xaml_AA_Low != null)
						xaml_AA_Low.IsChecked = false;
					if (xaml_AA_None != null)
						xaml_AA_None.IsChecked = false;
					break;
				case "xaml_AA_Low":
					m_AA = AA_t.LOW;
					if (xaml_AA_High != null)
						xaml_AA_High.IsChecked = false;
					if (xaml_AA_MedHigh != null)
						xaml_AA_MedHigh.IsChecked = false;
					if (xaml_AA_Med != null)
						xaml_AA_Med.IsChecked = false;
					if (xaml_AA_None != null)
						xaml_AA_None.IsChecked = false;
					break;
				case "xaml_AA_None":
					m_AA = AA_t.NONE;
					if (xaml_AA_High != null)
						xaml_AA_High.IsChecked = false;
					if (xaml_AA_MedHigh != null)
						xaml_AA_MedHigh.IsChecked = false;
					if (xaml_AA_Med != null)
						xaml_AA_Med.IsChecked = false;
					if (xaml_AA_Low != null)
						xaml_AA_Low.IsChecked = false;
					break;
			}
			if (mu_doc != null)
				mu_doc.SetAA(m_AA);
			if (m_init_done)
				RenderRange(m_currpage, false, zoom_t.NO_ZOOM, 0);
		}

		private AA_t GetAA()
		{
			if (xaml_AA_High.IsChecked)
				return AA_t.HIGH;
			else if (xaml_AA_MedHigh.IsChecked)
				return AA_t.MEDHIGH;
			else if (xaml_AA_Med.IsChecked)
				return AA_t.MED;
			else if (xaml_AA_Low.IsChecked)
				return AA_t.LOW;
			else
				return AA_t.NONE;
		}

		private void SetAA(AA_t aa)
		{
			xaml_AA_High.IsChecked = false;
			xaml_AA_MedHigh.IsChecked = false;
			xaml_AA_Med.IsChecked = false;
			xaml_AA_Low.IsChecked = false;
			xaml_AA_None.IsChecked = false;

			switch (aa)
			{
				case AA_t.HIGH:
					xaml_AA_High.IsChecked = true;
					break;
				case AA_t.MEDHIGH:
					xaml_AA_MedHigh.IsChecked = true;
					break;
				case AA_t.MED:
					xaml_AA_High.IsChecked = true;
					break;
				case AA_t.LOW:
					xaml_AA_High.IsChecked = true;
					break;
				case AA_t.NONE:
					xaml_AA_High.IsChecked = true;
					break;
			}
		}

		private void AnnotationOn(object sender, RoutedEventArgs e)
		{
			if (!m_init_done)
				return;
			m_showannot = true;
			RenderRange(m_currpage, false, zoom_t.NO_ZOOM, 0);
		}

		private void AnnotationOff(object sender, RoutedEventArgs e)
		{
			if (!m_init_done)
				return;
			m_showannot = false;
			RenderRange(m_currpage, false, zoom_t.NO_ZOOM, 0);
		}
	}
}