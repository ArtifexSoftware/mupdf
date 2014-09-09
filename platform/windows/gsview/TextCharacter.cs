using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
//using System.Threading.Tasks;
using System.ComponentModel;

namespace gsview
{
	public class TextCharacter
	{
		public String character;

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

		public String Color
		{
			get;
			set;
		}

		/* Here we only worry about intersection in the x direction TODO */
		public Intersection_t CheckIntersection(double rect_x, double rect_y, double rect_w, double rect_h)
		{
			if (rect_w == 0 || rect_x > X + Width  || rect_x + rect_w < X)
				return Intersection_t.NONE;

			if (rect_x <= X && X + Width <= rect_x + rect_w)
				return Intersection_t.FULL;

			return Intersection_t.PARTIAL;
		}


		//public event PropertyChangedEventHandler PropertyChanged;

		/*
		public void CharRefresh()
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
		 * */
	}
}
