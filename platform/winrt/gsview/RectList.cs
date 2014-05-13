using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.ComponentModel;

namespace gsview
{
	public enum Link_t
	{
		LINK_GOTO,
		LINK_URI,
		TEXTBOX,
		NOT_SET
	};

	public class RectList : INotifyPropertyChanged
	{
		public String Character
		{
			get;
			set;
		}

		public String Index
		{
			get;
			set;
		}

		public String Color
		{
			get;
			set;
		}

		public double Height
		{
			get;
			set;
		}

		public double Width
		{
			get;
			set;
		}

		public double X
		{
			get;
			set;
		}

		public double Y
		{
			get;
			set;
		}

		public double Scale
		{
			get;
			set;
		}

		public Link_t Type
		{
			get;
			set;
		}

		public int PageNum
		{
			get;
			set;
		}

		public Uri Urilink
		{
			get;
			set;
		}

		public event PropertyChangedEventHandler PropertyChanged;

		public void PageRefresh()
		{
			if (PropertyChanged != null)
			{
				PropertyChanged(this, new PropertyChangedEventArgs("X"));
				PropertyChanged(this, new PropertyChangedEventArgs("Height"));
				PropertyChanged(this, new PropertyChangedEventArgs("Width"));
				PropertyChanged(this, new PropertyChangedEventArgs("Y"));
				PropertyChanged(this, new PropertyChangedEventArgs("Color"));
			}
		}
	}
}
