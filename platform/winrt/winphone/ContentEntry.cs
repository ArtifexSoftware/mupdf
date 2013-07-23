using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace winphone
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
