using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
//using System.Threading.Tasks;
using System.ComponentModel;
using System.Collections.ObjectModel;

namespace gsview
{
	public enum Intersection_t
	{
		NONE,
		PARTIAL,
		FULL
	};

	public class TextLine : INotifyPropertyChanged
	{
		public List<TextCharacter> TextCharacters;
		double height;
		double width;
		double x;
		double y;
		double scale;
		String color;
		int page_number;

		/* Determine intersection case of line with selection rectangle */
		public Intersection_t CheckIntersection(double rect_x, double rect_y, double rect_w, double rect_h)
		{
			if (rect_h == 0 || rect_y > y + height || rect_y + rect_h < y)
				return Intersection_t.NONE;
			
			if (rect_y <= y && y + height <= rect_y + rect_h)
				return Intersection_t.FULL;

			return Intersection_t.PARTIAL;
		}

		public double Height
		{
			get { return height; }
			set
			{
				height = value;
				OnPropertyChanged("Height");
			}
		}

		public double Width
		{
			get { return width; }
			set
			{
				width = value;
				OnPropertyChanged("Width");
			}
		}

		public double X
		{
			get { return x; }
			set
			{
				x = value;
				OnPropertyChanged("X");
			}
		}

		public double Y
		{
			get { return y; }
			set
			{
				y = value;
				OnPropertyChanged("Y");
			}
		}
		public double Scale
		{
			get { return scale; }
			set { scale = value;}
		}

		public int PageNumber
		{
			get { return page_number; }
			set { page_number = value;  }
		}

		public String Color
		{
			get { return color; }
			set
			{
				color = value;
				//OnPropertyChanged("Color");
			}
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
	}

	public class LinesText : ObservableCollection<TextLine>
	{
		public LinesText()
			: base()
		{
		}
	}
}
