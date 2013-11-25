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
using System.Windows.Navigation;
using System.Windows.Shapes;
using System.Windows.Forms;
using mupdfwinrt;
using System.Threading.Tasks;
using System.Runtime.InteropServices.WindowsRuntime;


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
	public Point size;
	public double scale_factor;
} ;

/* C# has no defines.... */
static class Constants
{
	public const int LOOK_AHEAD = 2;  /* A +/- count on the pages to pre-render */
	public const int THUMB_PREADD = 10;
	public const double MIN_SCALE = 0.5;
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
}

namespace gsview
{
	/// <summary>
	/// Interaction logic for MainWindow.xaml
	/// </summary>
	public partial class MainWindow : Window
	{
		public Pages m_docPages;
		List<DocPage> m_thumbnails;
		List<List<RectList>> m_page_link_list;
		int m_contents_size;
		int m_content_item;
		List<bool> m_linkset;
		List<RectList> m_text_list;
		private int m_rectlist_page;
		private List<ContentEntry> m_content_list;
		mudocument mu_doc;
		private bool m_file_open;
		private int m_currpage;
		private int m_searchpage;
		private int m_num_pages;
		private int m_slider_min;
		private int m_slider_max;
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

		public MainWindow()
		{
			InitializeComponent();
			m_file_open = false;
		}

		private void CloseDoc()
		{



		}

		private void OpenFile(object sender, RoutedEventArgs e)
		{
			OpenFileDialog dlg = new OpenFileDialog();
			dlg.Filter = "Xps Documents (*.xps)|*.xps";
			dlg.FilterIndex = 1;
			if (dlg.ShowDialog() == System.Windows.Forms.DialogResult.OK)
			{
				if (m_file_open)
				{
					CloseDoc();
				}
				try
				{
					OpenDocument(dlg.FileName);
				}
				catch (UnauthorizedAccessException)
				{
					System.Windows.MessageBox.Show(
						String.Format("Unable to access {0}", dlg.FileName));
					return;
				}
			}
		}

		private async void OpenDocument(String filename)
		{

			string target = ".";
			char[] anyOf = target.ToCharArray();
			var index = filename.LastIndexOfAny(anyOf);
			string extension = filename.Substring(index + 1);

			int result = await mu_doc.OpenFileAsync(filename, extension);
			/* Check if we need password */
			if (mu_doc.RequiresPassword())
			{
				//SetView(view_t.VIEW_PASSWORD);
				return;
			}
			else
				InitialRender();
		}
	}
}
