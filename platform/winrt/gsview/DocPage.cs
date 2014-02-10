using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.ComponentModel;
using System.Windows.Media.Imaging;
using System.Collections.ObjectModel;
using System.Windows.Media;

namespace gsview
{
	public class DocPage : INotifyPropertyChanged
	{
		public int Height
		{
			get;
			internal set;
		}

		public int Width
		{
			get;
			internal set;
		}


		public int NativeHeight
		{
			get;
			set;
		}

		public int NativeWidth
		{
			get;
			set;
		}

		public double Zoom
		{
			get;
			set;
		}

		public BitmapSource BitMap
		{
			get;
			set;
		}

		public List<RectList> TextBox
		{
			get;
			set;
		}

		public List<RectList> LinkBox
		{
			get;
			set;
		}

		public Page_Content_t Content
		{
			get;
			set;
		}

		public String PageName
		{
			get;
			set;
		}

		public int PageNum
		{
			get;
			set;
		}

		public event PropertyChangedEventHandler PropertyChanged;

		public void PageRefresh()
		{
			if (PropertyChanged != null)
			{
				PropertyChanged(this, new PropertyChangedEventArgs("BitMap"));
				PropertyChanged(this, new PropertyChangedEventArgs("Height"));
				PropertyChanged(this, new PropertyChangedEventArgs("Width"));
				PropertyChanged(this, new PropertyChangedEventArgs("TextBox"));
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
		}

		public DocPage(int Height, int Width, double Zoom, BitmapSource BitMap,
							List<RectList> TextBox, List<RectList> LinkBox,
							Page_Content_t Content, int PageNum)
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
