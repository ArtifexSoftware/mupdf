using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
//using System.Threading.Tasks;
using System.ComponentModel;
using System.Windows.Media.Imaging;
using System.Collections.ObjectModel;
using System.Windows.Media;

namespace gsview
{
	public enum Annotate_t
	{
		UNKNOWN,
		COMPUTING,
		NO_ANNOTATE,
		HAS_ANNOTATE,
		ANNOTATE_VISIBLE,
		ANNOTATE_HIDDEN
	}

	public class DocPage : INotifyPropertyChanged
	{
		private LinesText m_lines;
		private BlocksText m_blocks;
		private int height;
		private int width;
		private int nativeheight;
		private int nativewidth;
		private double zoom;
		private Annotate_t annotate;
		private BitmapSource bitmap;
		private IList<RectList> textbox;
		private List<RectList> linkbox;
		private Page_Content_t content;
		private String pagename;
		private int pagenum;
		private double sely;
		private double selx;
		private double selheight;
		private double selwidth;
		private String selcolor;
		private double sel_anchorx;
		private double sel_anchory;

		public double SelAnchorX
		{
			get { return sel_anchorx; }
			set { sel_anchorx = value; }
		}

		public double SelAnchorY
		{
			get { return sel_anchory; }
			set { sel_anchory = value; }
		}

		public double SelY
		{
			get { return sely; }
			set
			{
				sely = value;
				OnPropertyChanged("SelY");
			}
		}

		public double SelX
		{
			get { return selx; }
			set
			{
				selx = value;
				OnPropertyChanged("SelX");
			}
		}

		public double SelHeight
		{
			get { return selheight; }
			set
			{
				selheight = value;
				OnPropertyChanged("SelHeight");
			}
		}

		public double SelWidth
		{
			get { return selwidth; }
			set
			{
				selwidth = value;
				OnPropertyChanged("SelWidth");
			}
		}

		public String SelColor
		{
			get { return selcolor; }
			set
			{
				selcolor = value;
				OnPropertyChanged("SelColor");
			}
		}

		public int Height
		{
			get { return height; }
			set 
			{ 
				height = value;
				OnPropertyChanged("Height");
			}
		}

		public int Width
		{
			get { return width; }
			set
			{
				width = value;
				OnPropertyChanged("Width");
			}
		}

		public int NativeHeight
		{
			get { return nativewidth; }
			set { nativewidth = value; }
		}

		public int NativeWidth
		{
			get { return nativeheight; }
			set { nativeheight = value; }
		}

		public Annotate_t Annotate
		{
			get { return annotate; }
			set { annotate = value; }
		}

		public double Zoom
		{
			get { return zoom; }
			set { zoom = value; }
		}

		public BitmapSource BitMap
		{
			get { return bitmap; }
			set
			{
				bitmap = value;
				OnPropertyChanged("BitMap");
			}
		}

		public IList<RectList> TextBox
		{
			get { return textbox; }
			set
			{
				textbox = value;
				OnPropertyChanged("TextBox");
			}
		}

		public List<RectList> LinkBox
		{
			get { return linkbox; }
			set
			{
				linkbox = value;
				OnPropertyChanged("LinkBox");
			}
		}

		public BlocksText TextBlocks
		{
			get { return m_blocks; }
			set
			{
				m_blocks = value;
				OnPropertyChanged("TextBlocks");
			}
		}

		public LinesText SelectedLines
		{
			get { return m_lines; }
			set
			{
				m_lines = value;
				OnPropertyChanged("SelectedLines");
			}
		}

		public Page_Content_t Content
		{
			get { return content; }
			set { content = value; }
		}

		public String PageName
		{
			get { return pagename; }
			set { pagename = value; }
		}

		public int PageNum
		{
			get { return pagenum; }
			set { pagenum = value; }
		}

		public AA_t AA
		{
			get;
			set;
		}

		public event PropertyChangedEventHandler PropertyChanged;

		// Create the OnPropertyChanged method to raise the event 
		protected void OnPropertyChanged(string name)
		{
			PropertyChangedEventHandler handler = PropertyChanged;
			if (handler != null)
			{
				handler(this, new PropertyChangedEventArgs(name));
			}
		}

		public DocPage()
		{
			this.Height = 0;
			this.Width = 0;
			this.NativeHeight = 0;
			this.NativeWidth = 0;
			this.Zoom = 0;
			this.BitMap = null;
			this.TextBox = null;
			this.LinkBox = null;
			this.Content = Page_Content_t.NOTSET;
			this.PageNum = -1;
			this.PageName = "";
			this.TextBlocks = null;
			this.AA = AA_t.HIGH;
		}

		public DocPage(int Height, int Width, double Zoom, BitmapSource BitMap,
							List<RectList> TextBox, List<RectList> LinkBox,
							Page_Content_t Content, int PageNum, BlocksText TextBlocks,
							AA_t AA)
		{
			this.Height = Height;
			this.Width = Width;
			this.Zoom = Zoom;
			this.BitMap = BitMap;
			this.TextBox = TextBox;
			this.LinkBox = LinkBox;
			this.Content = Content;
			this.PageNum = PageNum;
			this.PageName = ("Page " + (PageNum + 1));
			this.TextBlocks = TextBlocks;
			this.AA = AA;
		}
	};
	public class Pages : ObservableCollection<DocPage>
	{
		public Pages()
			: base()
		{
		}
	}
}
