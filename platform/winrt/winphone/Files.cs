using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Media.Imaging;
using System.Collections.ObjectModel;
using System.Windows.Media;

namespace winphone
{
	public class Files
	{
		public int Type
		{
			get;
			set;
		}

		public SolidColorBrush CurrColor
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
			this.CurrColor = new SolidColorBrush(Colors.White);
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
