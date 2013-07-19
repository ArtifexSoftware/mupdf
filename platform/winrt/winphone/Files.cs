using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Media.Imaging;
using System.Collections.ObjectModel;

namespace winphone
{
	public class Files
	{
		public int Type
		{
			get;
			set;
		}

		public BitmapImage Icon
		{
			get;
			set;
		}

		public String Name
		{
			get;
			set;
		}

		public Files(int Type, BitmapImage Icon, String Name)
		{
			this.Name = Name;
			this.Icon = Icon;
			this.Type = Type;
		}
	};

	public class FileList : ObservableCollection<Files>
	{
		public FileList()
			: base()
		{
		}
	}
}
