using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Shapes;
using System.Printing;
using System.Drawing.Printing;
using System.Runtime.InteropServices;
using System.Windows.Interop;
using System.Text.RegularExpressions;

namespace gsview
{
	/// <summary>
	/// Interaction logic for PrintControl.xaml
	/// </summary>
	/// 

	static class NATIVEWIN
	{
		public const int IDOK = 1;
		public const int IDCANCEL = 2;
		public const int DM_OUT_BUFFER = 2;
		public const int DM_IN_BUFFER = 8;
		public const int DM_IN_PROMPT = 4;
		public const int DM_ORIENTATION = 1;
		public const int DM_PAPERSIZE = 2;
		public const int DM_PAPERLENGTH = 4;
		public const int DM_WIDTH = 8;
		public const int DMORIENT_PORTRAIT = 1;
		public const int DMORIENT_LANDSCAPE = 2;
	}

	public enum PrintPages_t
	{
		RANGE = 2,
		CURRENT = 1,
		ALL = 0
	}

	public enum PageSubset_t
	{
		ALL = 0,
		ODD = 1,
		EVEN = 2
	}

	public enum PageScale_t
	{
		NONE = 0,
		FIT = 1,
	}

	public enum Units_t
	{
		INCHES = 0,
		CM = 1
	}

	public class PrintDiagEventArgs : EventArgs
	{
		public int m_page;

		public PrintDiagEventArgs(int page)
		{
			m_page = page;
		}
	}

	public class PrintRanges
	{
		public List<bool> ToPrint;
		public bool HasEvens;
		public bool HasOdds;
		public int NumberPages;

		public PrintRanges(int number_pages)
		{
			ToPrint = new List<bool>(number_pages);
			NumberPages = 0;
			HasEvens = false;
			HasOdds = false;
		}

		public void InitRange(Match match)
		{
			NumberPages = 0;
			HasEvens = false;
			HasOdds = false;

			for (int k = 0; k < ToPrint.Count; k++)
			{
				if (CheckValue(match, k))
				{
					NumberPages = NumberPages + 1;
					ToPrint[k] = true;
					if ((k+1) % 2 != 0)
						HasOdds = true;
					else
						HasEvens = true;
				}
				else
					ToPrint[k] = false;
			}
		}

		private bool CheckValue(Match match, int k)
		{
			return false;
		}
	}

	public partial class PrintControl : Window
	{
		private LocalPrintServer m_printServer;
		public PrintQueue m_selectedPrinter = null;
		String m_status;
		PrintPages_t m_pages_setting;
		PageSubset_t m_page_subset;
		public double m_page_scale;
		Units_t m_units;
		int m_numpages;
		int m_currpage;
		PrintCapabilities m_printcap;
		public PageSettings m_pagedetails;
		TranslateTransform m_trans_pap;
		TranslateTransform m_trans_doc;
		double m_doc_height;
		double m_doc_width;
		public bool m_isrotated;
		PrintRanges m_range_pages;
		public int m_numcopies;
		bool m_initdone;
		bool m_is64bit;

		/* Callback to main to get preview images */
		internal delegate bool PrintDiagCallBackPreview(object gsObject, PrintDiagEventArgs info);
		internal event PrintDiagCallBackPreview PrintDiagUpdatePreview;
		/* Callback to perform printing */
		internal delegate void PrintDiagCallBackPrint(object gsObject);
		internal event PrintDiagCallBackPrint PrintDiagPrint;
		/* Callback to report problems */
		internal delegate void PrintDLLProblem(object gsObject, String mess);
		internal event PrintDLLProblem PrintDLLProblemMain;

		/* Helper for displaying the custom printer dialog settings */
		#region DLLInterface
		[DllImport("gsprint64.dll", EntryPoint = "ShowPropertiesDialog", CharSet = CharSet.Ansi,
			CallingConvention = CallingConvention.StdCall)]
		private static extern int ShowPropertiesDialog64(IntPtr hwnd, IntPtr printername, bool show_diag );
		[DllImport("gsprint32.dll", EntryPoint = "ShowPropertiesDialog", CharSet = CharSet.Ansi,
			CallingConvention = CallingConvention.StdCall)]
		private static extern int ShowPropertiesDialog32(IntPtr hwnd, IntPtr printername, bool show_diag);

		#endregion DLLInterface

		#region DLLErrorCatch
		/* In case the DLL is not found we need to wrap the methods up with
		 * a try/catch.  Also select 32 or 64 bit DLL at this time.  This 
		 * C# code is compiled as ANYCPU type */
		private int tc_ShowPropertiesDialog(IntPtr hwnd, IntPtr printername, bool show_prop)
		{
			int code;

			try
			{
				if (m_is64bit)
					code = ShowPropertiesDialog64(hwnd, printername, show_prop);
				else
					code = ShowPropertiesDialog32(hwnd, printername, show_prop);
			}
			catch (DllNotFoundException)
			{
				/* DLL not found */
				String output = "DllNotFoundException: gsprint DLL not found";
				PrintDLLProblemMain(this, output);
				return -1;
			}
			catch (BadImageFormatException)
			{
				/* Using 32 bit with 64 or vice versa */
				String output = "BadImageFormatException: Incorrect gsprint DLL";
				PrintDLLProblemMain(this, output);
				return -1;
			}
			return code;
		}
		#endregion DLLErrorCatch

		/* Populate the printers */
		private void InitPrinterList()
		{
			PrintQueueCollection printQueuesOnLocalServer = 
				m_printServer.GetPrintQueues(new[] {EnumeratedPrintQueueTypes.Local, EnumeratedPrintQueueTypes.Connections});

			this.xaml_selPrinter.ItemsSource = printQueuesOnLocalServer;
			if (m_selectedPrinter != null)
			{
				foreach (PrintQueue pq in printQueuesOnLocalServer)
				{
					if (pq.FullName == m_selectedPrinter.FullName)
					{
						this.xaml_selPrinter.SelectedItem = pq;
						break;
					}
				}
			}
		}

		/* Initialize */
		public PrintControl(int num_pages, int curr_page)
		{
			PrinterSettings ps = new PrinterSettings();

			this.Closing += new System.ComponentModel.CancelEventHandler(FakeWindowClosing); 
			InitializeComponent();
			m_printServer = new LocalPrintServer();
			m_selectedPrinter = LocalPrintServer.GetDefaultPrintQueue();
			InitPrinterList();
			ps.PrinterName = m_selectedPrinter.FullName;
			m_pagedetails = ps.DefaultPageSettings;


			xaml_rbAll.IsChecked = true;
			m_pages_setting = PrintPages_t.ALL;
			m_page_subset = PageSubset_t.ALL;
			xaml_Subset.SelectedIndex = (int) m_page_subset;

			xaml_autofit.IsChecked = false;

			xaml_inches.IsChecked = true;
			m_units = Units_t.INCHES;

			m_currpage = curr_page;
			m_numpages = num_pages;
			xaml_pagecount.Text = "1/" + num_pages;
			xaml_pageslider.Maximum = num_pages - 1;

			m_printcap = m_selectedPrinter.GetPrintCapabilities();

			m_trans_pap = new TranslateTransform(0, 0);
			m_trans_doc = new TranslateTransform(0, 0);
			m_isrotated = false;

			/* Data range case */
			m_range_pages = new PrintRanges(m_numpages);
			m_page_scale = 1.0;

			m_numcopies = 1;
			m_initdone = false;
			m_is64bit = Environment.Is64BitOperatingSystem &&
				Environment.Is64BitProcess;
		}

		void FakeWindowClosing(object sender, System.ComponentModel.CancelEventArgs e)
		{
			e.Cancel = true;
			this.Hide();
		}

		public void RealWindowClosing()
		{
			this.Closing -= new System.ComponentModel.CancelEventHandler(FakeWindowClosing);
			this.Close();
		}

		/* Displays and updates the custom printer dialog settings. One can
		 * either do this with pinvoke of the various commands in winspool or
		 * go ahead and handle it in our own dll, which is what I decided to
		 * do. */
		private void ShowProperties(object sender, RoutedEventArgs e)
		{
			PrinterChanged(true);
		}

		private void PrinterChanged(bool show_prop)
		{
			if (m_selectedPrinter != null)
			{
				var ptrNameGC = new GCHandle();
				var temp = System.Text.Encoding.UTF8.GetBytes(m_selectedPrinter.FullName.ToCharArray());
				ptrNameGC = GCHandle.Alloc(temp, GCHandleType.Pinned);
				int res = tc_ShowPropertiesDialog(new WindowInteropHelper(this).Handle, ptrNameGC.AddrOfPinnedObject(), show_prop);
				ptrNameGC.Free();
				if (res >= 0)
				{
					PrinterSettings ps = new PrinterSettings();
					ps.PrinterName = m_selectedPrinter.FullName;
					m_pagedetails = ps.DefaultPageSettings;
					UpdateView();
				}
			} 
		}

		/* Printer selection changed */
		private void selPrinterChanged(object sender, SelectionChangedEventArgs e)
		{
			m_selectedPrinter = this.xaml_selPrinter.SelectedItem as PrintQueue;
			GetPrinterStatus();
			if (m_initdone)
				PrinterChanged(false);
		}

		/* Printer Status */
		private void GetPrinterStatus()
		{
			if (m_selectedPrinter.IsBusy) 
				m_status = "Busy";
			else if (m_selectedPrinter.IsNotAvailable)
				m_status = "Not Available";
			else if (m_selectedPrinter.IsOffline)
				m_status = "Offline";
			else if (m_selectedPrinter.IsOutOfMemory)
				m_status = "Out Of Memory";
			else if (m_selectedPrinter.IsOutOfPaper)
				m_status = "Out Of Paper";
			else if (m_selectedPrinter.IsOutputBinFull)
				m_status = "Output Bin Full";
			else if (m_selectedPrinter.IsPaperJammed)
				m_status = "Paper Jam";
			else if (m_selectedPrinter.IsPaused)
				m_status = "Paused";
			else if (m_selectedPrinter.IsPendingDeletion)
				m_status = "Paused";
			else if (m_selectedPrinter.IsPrinting)
				m_status = "Printing";
			else if (m_selectedPrinter.IsProcessing)
				m_status = "Processing";
			else if (m_selectedPrinter.IsWaiting)
				m_status = "Waiting";
			else if (m_selectedPrinter.IsWarmingUp)
				m_status = "Warming Up";
			else
				m_status = "Ready";
			xaml_Status.Text = m_status;
		}

		private void Subset_SelectionChanged(object sender, SelectionChangedEventArgs e)
		{
			/* On current page, only All is allowed */
			m_page_subset = (PageSubset_t) xaml_Subset.SelectedIndex;
			if (m_pages_setting == PrintPages_t.CURRENT && 
				m_page_subset != PageSubset_t.ALL) 
				xaml_Subset.SelectedIndex = (int) PageSubset_t.ALL;

			/* Only one page, can't use even */
			if (m_pages_setting == PrintPages_t.ALL && 
				m_page_subset == PageSubset_t.EVEN &&
				m_numpages == 1)
				xaml_Subset.SelectedIndex = (int)PageSubset_t.ALL;
		}

		private void AllPages(object sender, RoutedEventArgs e)
		{
			xaml_invalid.Visibility = System.Windows.Visibility.Collapsed;
			xaml_pageslider.Maximum = m_numpages - 1;
			xaml_pageslider.Value = m_currpage;
			xaml_pagecount.Text = (m_currpage + 1) + "/" + m_numpages;
			m_pages_setting = PrintPages_t.ALL;
		}

		private void CurrentPage(object sender, RoutedEventArgs e)
		{
			xaml_invalid.Visibility = System.Windows.Visibility.Collapsed;
			m_pages_setting = PrintPages_t.CURRENT;
			xaml_pagecount.Text = "1/1";
			xaml_pageslider.Maximum = 0;
			xaml_pageslider.Value = 0;
			PrintDiagEventArgs info = new PrintDiagEventArgs(m_currpage);
			PrintDiagUpdatePreview(this, info);
		}

		private void PageRange(object sender, RoutedEventArgs e)
		{
			xaml_invalid.Visibility = System.Windows.Visibility.Collapsed;
			m_pages_setting = PrintPages_t.RANGE;
		}

		private void UpdateScaleInfo()
		{
			/*
			if (m_page_scale_type == PageScale_t.NONE)
			{
				double temp_width_doc = Math.Truncate(m_doc_width * 100.0) / 100.0;
				double temp_height_doc = Math.Truncate(m_doc_height * 100.0) / 100.0;
				double temp_width_page = m_pagedetails.Bounds.Width / 100;
				double temp_height_page = m_pagedetails.Bounds.Height / 100;

				if (m_units == Units_t.CM)
				{
					temp_height_doc = (Math.Truncate(temp_height_doc * 2.54 * 100) / 100.0);
					temp_width_doc = (Math.Truncate(temp_width_doc * 2.54 * 100) / 100.0);
					temp_height_page = (Math.Truncate(temp_height_page * 2.54 * 100) / 100.0);
					temp_width_page = (Math.Truncate(temp_width_page * 2.54 * 100) / 100.0);
				}
				xaml_pagesize.Text = "Paper:\t\t" + temp_width_page + " x " + temp_height_page;
				xaml_docsize.Text = "Document:\t" + temp_width_doc + " x " + temp_height_doc; ;
				xaml_pagesize.Visibility = System.Windows.Visibility.Visible;
				xaml_docsize.Visibility = System.Windows.Visibility.Visible;
			}
			else
			{
				xaml_pagesize.Visibility = System.Windows.Visibility.Collapsed;
				xaml_docsize.Visibility = System.Windows.Visibility.Collapsed;
			}
			 * */
		}

		private void Inches(object sender, RoutedEventArgs e)
		{
			m_units = Units_t.INCHES;
			UpdateUnits();
			UpdateScaleInfo();
		}

		private void Centimeters(object sender, RoutedEventArgs e)
		{
			m_units = Units_t.CM;
			UpdateUnits();
			UpdateScaleInfo();
		}

		public void SetImage(BitmapSource image_in, double doc_height_in, 
							double doc_width_in)
		{
			xaml_PreviewImageRect.Visibility = System.Windows.Visibility.Collapsed;
			xaml_PreviewGrayRect.Visibility = System.Windows.Visibility.Collapsed;
			xaml_PreviewPaper.Visibility = System.Windows.Visibility.Collapsed;

			m_doc_width = doc_width_in;
			m_doc_height = doc_height_in;
			xaml_ImagePreview.ImageSource = image_in;
			xaml_ImagePreviewClip.ImageSource = image_in;

			UpdateView();
		}

		private void UpdateView()
		{
			/* For our display we compute the page size as well as the paper size */
			/* The max length sets our scaling of each component */
			/* We then determine if any additional scaling is needed or translation
			 * based upon the settings of m_page_scale_type as well as the autofit
			 * and scale setting */
			double page_height = m_pagedetails.Bounds.Height;
			double page_width = m_pagedetails.Bounds.Width;
			double doc_height = m_doc_height * 100;
			double doc_width = m_doc_width * 100;
			bool autofit = (xaml_autofit.IsChecked == true);
			bool center;
			/* bool center = (xaml_center.IsChecked == true); */
			double scale_height;
			double scale_width;
			double max_scale;
			double doc_offset_x = 0;
			double doc_offset_y = 0;
			double pap_offset_x = 0;
			double pap_offset_y = 0;
			Rect clip_rect;

			center = autofit; /* I may separate these later */
			m_page_scale = 1.0;
			m_isrotated = false;
			if (autofit && 
				((m_pagedetails.Bounds.Height > m_pagedetails.Bounds.Width && doc_height < doc_width) ||
				(m_pagedetails.Bounds.Height < m_pagedetails.Bounds.Width && doc_height > doc_width)))
			{
				page_width = m_pagedetails.Bounds.Height;
				page_height = m_pagedetails.Bounds.Width;
				m_isrotated = true;
			}

			/* Scale page data if needed. */

			if (xaml_autofit.IsChecked == true)
			{
				scale_height = page_height / doc_height;
				scale_width = page_width / doc_width;
				max_scale = Math.Min(scale_height, scale_width);

				/* Adjust the doc size to fit in the page */
				doc_height = doc_height * max_scale;
				doc_width = doc_width * max_scale;
				m_page_scale = max_scale;
			}

			/* Now figure out our preview scaling to ensure everything fits
			 * in the display window */
			double max_height = Math.Max(doc_height, page_height);
			double max_width = Math.Max(doc_width, page_width);
			double max_length = Math.Max(max_height, max_width);
			double previewscale = (double)Constants.MAX_PRINT_PREVIEW_LENGTH / max_length;

			/* Adjust size of everything */
			doc_height = doc_height * previewscale;
			doc_width = doc_width * previewscale;
			page_height = page_height * previewscale;
			page_width = page_width * previewscale;

			xaml_PreviewImageRect.Visibility = System.Windows.Visibility.Collapsed;
			xaml_PreviewGrayRect.Visibility = System.Windows.Visibility.Collapsed;
			xaml_PreviewPaper.Visibility = System.Windows.Visibility.Collapsed;

			/* Compute any offsets if needed due to centering */
			if (center)
			{
				if (doc_height > page_height)
					pap_offset_y = (doc_height - page_height) / 2.0;
				else
					doc_offset_y = (page_height - doc_height) / 2.0;
				if (doc_width > page_width)
					pap_offset_x = (doc_width - page_width) / 2.0;
				else
					doc_offset_x = (page_width - doc_width) / 2.0;
			}

			double offset_y = 0;
			
			if (!autofit)
				offset_y = doc_height - page_height;

			/* See if the paper needs to translate */
			if (page_height < doc_height)
				m_trans_pap = new TranslateTransform(pap_offset_x, pap_offset_y + offset_y);
			else
				m_trans_pap = new TranslateTransform(pap_offset_x, pap_offset_y);

			/* See if the doc needs to translate */
			if (page_height > doc_height)
				m_trans_doc = new TranslateTransform(doc_offset_x, doc_offset_y - offset_y);
			else
				m_trans_doc = new TranslateTransform(doc_offset_x, doc_offset_y);

			/* Page black outer rect */
			xaml_PreviewPaperOuterRect.RenderTransform = m_trans_pap;
			xaml_PreviewPaperOuterRect.Height = page_height;
			xaml_PreviewPaperOuterRect.Width = page_width;
			xaml_PreviewPaperOuterRect.Visibility = System.Windows.Visibility.Visible;

			/* Paper white fill */
			xaml_PreviewPaper.RenderTransform = m_trans_pap;
			xaml_PreviewPaper.Height = page_height;
			xaml_PreviewPaper.Width = page_width;
			xaml_PreviewPaper.Visibility = System.Windows.Visibility.Visible;

			/* The image */
			xaml_PreviewImageRect.RenderTransform = m_trans_doc;
			xaml_PreviewImageRect.Height = doc_height;
			xaml_PreviewImageRect.Width = doc_width;
			xaml_PreviewImageRect.Visibility = System.Windows.Visibility.Visible;

			/* The gray fill (not visible) */
			xaml_PreviewGrayRect.RenderTransform = m_trans_doc;
			xaml_PreviewGrayRect.Height = doc_height;
			xaml_PreviewGrayRect.Width = doc_width;
			xaml_PreviewGrayRect.Visibility = System.Windows.Visibility.Visible;

			/* The visible portion */
			xaml_PreviewImageRectClip.RenderTransform = m_trans_doc;
			xaml_PreviewImageRectClip.Height = doc_height;
			xaml_PreviewImageRectClip.Width = doc_width;
			clip_rect = new Rect(pap_offset_x, pap_offset_y + offset_y, page_width, page_height);
			xaml_ImagePreviewClipGeom.Rect = clip_rect;
			xaml_PreviewImageRectClip.Visibility = System.Windows.Visibility.Visible;
			UpdateSizes();
			UpdateScaleInfo();
			m_initdone = true;
		}

		private void PageSelect_DragCompleted(object sender, MouseButtonEventArgs e)
		{
			if (m_pages_setting == PrintPages_t.CURRENT)
				return;

			/* Get the current page view */
			int page = (int) xaml_pageslider.Value;
			PrintDiagEventArgs info = new PrintDiagEventArgs(page);
			PrintDiagUpdatePreview(this, info);
			page = page + 1;
			xaml_pagecount.Text = page + "/" + m_numpages;
		}

		private void AdjustPageSize()
		{
			m_printcap = m_selectedPrinter.GetPrintCapabilities();
		}

		private void UpdateSizes()
		{
			xaml_TopArrowCanvas.RenderTransform = new TranslateTransform(m_trans_pap.X, 0);
			xaml_topsize.X2 = xaml_PreviewPaper.Width;
			xaml_toprighttoparrow.X1 = xaml_PreviewPaper.Width - 7;
			xaml_toprighttoparrow.X2 = xaml_PreviewPaper.Width;
			xaml_toprightbottomarrow.X1 = xaml_PreviewPaper.Width - 7;
			xaml_toprightbottomarrow.X2 = xaml_PreviewPaper.Width;

			xaml_LeftArrowCanvas.RenderTransform = new TranslateTransform(0, m_trans_pap.Y);
			xaml_leftsize.Y2 = xaml_PreviewPaper.Height;
			xaml_leftbottomleft.Y1 = xaml_PreviewPaper.Height - 7;
			xaml_leftbottomleft.Y2 = xaml_PreviewPaper.Height;
			xaml_leftbottomright.Y1 = xaml_PreviewPaper.Height - 7;
			xaml_leftbottomright.Y2 = xaml_PreviewPaper.Height;

			xaml_LeftArrowCanvas.Visibility = System.Windows.Visibility.Visible;
			xaml_TopArrowCanvas.Visibility = System.Windows.Visibility.Visible;

			UpdateUnits();
		}

		private void UpdateUnits()
		{

			double valHeight = m_pagedetails.Bounds.Height;
			double valWidth = m_pagedetails.Bounds.Width;

			if (m_units == Units_t.INCHES)
			{
				if (m_isrotated)
				{
					xaml_topsizevalue.Text = (Math.Truncate(valHeight) / 100.0).ToString();
					xaml_leftsizevalue.Text = (Math.Truncate(valWidth) / 100.0).ToString();
				}
				else
				{
					xaml_leftsizevalue.Text = (Math.Truncate(valHeight) / 100.0).ToString();
					xaml_topsizevalue.Text = (Math.Truncate(valWidth) / 100.0).ToString();
				}
			}
			else
			{
				if (m_isrotated)
				{
					xaml_topsizevalue.Text = (Math.Truncate(valHeight * 2.54) / 100.0).ToString();
					xaml_leftsizevalue.Text = (Math.Truncate(valWidth * 2.54) / 100.0).ToString();
				}
				else
				{
					xaml_leftsizevalue.Text = (Math.Truncate(valHeight * 2.54) / 100.0).ToString();
					xaml_topsizevalue.Text = (Math.Truncate(valWidth * 2.54) / 100.0).ToString();
				}
			}
		}

		private void PageNumberEnter(object sender, KeyEventArgs e)
		{
			if (e.Key == Key.Return)
			{
				e.Handled = true;
				string desired_page = xaml_pagerange.Text;

				Regex rangePattern = new Regex(@"^\s*\d+\s*(\-\s*\d+\s*)?(\,\s*\d+\s*(\-\s*\d+\s*)?)*$");

				Match m = rangePattern.Match(desired_page);
				if (!m.Success)
					xaml_invalid.Visibility = System.Windows.Visibility.Visible;
				else
				{
					xaml_invalid.Visibility = System.Windows.Visibility.Collapsed;
				}
			}
		}

		private void ClickOK(object sender, RoutedEventArgs e)
		{
			PrintDiagPrint(this);
			this.Hide();
		}

		private void ClickCancel(object sender, RoutedEventArgs e)
		{
			this.Hide();
		}

		private void xaml_Copies_ValueChanged(object sender, RoutedPropertyChangedEventArgs<double> e)
		{
			m_numcopies = (int) e.NewValue;
		}

		private void AutoFit_Checked(object sender, RoutedEventArgs e)
		{
			UpdateView();
		}

		private void AutoFit_Unchecked(object sender, RoutedEventArgs e)
		{
			UpdateView();
		}
	}
}
