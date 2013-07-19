using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.ComponentModel;
using System.Windows.Media.Imaging;
using System.Collections.ObjectModel;

namespace winphone
{
	public class DocumentPage
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

		public float Zoom
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

		public DocumentPage(int Height, int Width, float Zoom, WriteableBitmap Image,
							List<RectList> TextBox, List<RectList> LinkBox,
							Page_Content_t Content)
		{
			this.Height = Height;
			this.Width = Width;
			this.Zoom = Zoom;
			this.Image = Image;
			this.TextBox = TextBox;
			this.LinkBox = LinkBox;
			this.Content = Content;
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
