using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.ComponentModel;

namespace gsview
{
	class gsIO : INotifyPropertyChanged
	{
			public String gsIOString
			{
				get;
				set;
			}

			public event PropertyChangedEventHandler PropertyChanged;

			public void PageRefresh()
			{
				if (PropertyChanged != null)
				{
					PropertyChanged(this, new PropertyChangedEventArgs("gsIOString"));
				}
			}

			public gsIO()
			{
				this.gsIOString = "";
			}
	}
}
