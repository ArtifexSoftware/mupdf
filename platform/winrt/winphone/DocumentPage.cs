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

		public String PageNum
		{
			get;
			set;
		}

		public MatrixTransform TransformMatrix
		{
			get;
			set;
		}

		public DocumentPage(int Height, int Width, float Zoom, WriteableBitmap Image,
							List<RectList> TextBox, List<RectList> LinkBox,
							Page_Content_t Content, String PageNum)
		{
			this.Height = Height;
			this.Width = Width;
			this.Zoom = Zoom;
			this.Image = Image;
			this.TextBox = TextBox;
			this.LinkBox = LinkBox;
			this.Content = Content;
			this.PageNum = PageNum;
			this.TransformMatrix = new MatrixTransform();
		}
	};
	public class Pages : ObservableCollection<DocumentPage>
	{
		public Pages()
			: base()
		{
		}
	}

	/*public class PanoPageItems : ObservableCollection<PanoramaItem>
	{
		public PanoPageItems()
			: base()
		{
		}
	}*/
}
