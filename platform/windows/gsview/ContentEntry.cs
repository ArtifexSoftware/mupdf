using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace gsview
{
	public class ContentEntry
	{
		public String Name
		{
			get;
			set;
		}

		public int PageNum
		{
			get;
			set;
		}

		public ContentEntry(String Name, int PageNum)
		{
			this.Name = Name;
			this.PageNum = PageNum;
		}
	};
}

