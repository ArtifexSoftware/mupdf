using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
//using System.Threading.Tasks;
using System.ComponentModel;

namespace gsview
{
	class ContentItem : INotifyPropertyChanged
	{

		public int Page
		{
			get;
			internal set;
		}

		public String StringMargin
		{
			get;
			internal set;
		}

		public ContentItem()
		{
			StringMargin = "";
			Page = 0;
		}

		public event PropertyChangedEventHandler PropertyChanged;

		public void ContentRefresh()
		{
			if (PropertyChanged != null)
			{
				PropertyChanged(this, new PropertyChangedEventArgs("StringMargin"));
				PropertyChanged(this, new PropertyChangedEventArgs("Page"));
			}
		}
	}
}
