using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.ComponentModel;
using System.Windows.Media.Imaging;
using System.Collections.ObjectModel;
using System.Windows.Media;

namespace winphone
{
	public class DocumentPage : INotifyPropertyChanged
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

		public double Zoom
		{
			get;
			set;
		}

		public WriteableBitmap Image
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
				PropertyChanged(this, new PropertyChangedEventArgs("Image"));
				PropertyChanged(this, new PropertyChangedEventArgs("Height"));
				PropertyChanged(this, new PropertyChangedEventArgs("Width"));
				PropertyChanged(this, new PropertyChangedEventArgs("TextBox"));
			}
		}

		public DocumentPage(int Height, int Width, double Zoom, WriteableBitmap Image,
							List<RectList> TextBox, List<RectList> LinkBox,
							Page_Content_t Content, int PageNum)
		{
			this.Height = Height;
			this.Width = Width;
			this.Zoom = Zoom;
			this.Image = Image;
			this.TextBox = TextBox;
			this.LinkBox = LinkBox;
			this.Content = Content;
			this.PageNum = PageNum;
			this.PageName = ("Page " + (PageNum + 1));
		}
	};
	public class Pages : ObservableCollection<DocumentPage>
	{
		public Pages()
			: base()
		{
		}
	}
}
