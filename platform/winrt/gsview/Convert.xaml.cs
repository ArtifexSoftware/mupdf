using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Shapes;
using System.ComponentModel;
using System.Collections.ObjectModel;
using System.Text.RegularExpressions;

namespace gsview
{
	public class Device : INotifyPropertyChanged
	{
		public String DeviceName
		{
			get;
			internal set;
		}

		public gsDevice_t DeviceType
		{
			get;
			internal set;
		}

		public bool SupportsMultiPage
		{
			get;
			internal set;
		}

		public bool MuPDFDevice
		{
			get;
			internal set;
		}

		public event PropertyChangedEventHandler PropertyChanged;

		public void PageRefresh()
		{
			if (PropertyChanged != null)
			{
				PropertyChanged(this, new PropertyChangedEventArgs("DeviceName"));
			}
		}

		public Device()
		{
			this.DeviceName = "";
		}
	};

	public class SelectPage : INotifyPropertyChanged
	{
		public int Page
		{
			get;
			internal set;
		}

		public int PageString
		{
			get;
			internal set;
		}

		public event PropertyChangedEventHandler PropertyChanged;

		public void PageRefresh()
		{
			if (PropertyChanged != null)
			{
				PropertyChanged(this, new PropertyChangedEventArgs("Page"));
				PropertyChanged(this, new PropertyChangedEventArgs("PageString"));
			}
		}
	};

	/// <summary>
	/// Interaction logic for Convert.xaml
	/// </summary>
	public partial class Convert : Window
	{
		List<Device> GSDevices;
		List<SelectPage> ConvertPages;

		/* Callback to Main */
		internal delegate void ConvertCallBackMain(object gsObject);
		internal event ConvertCallBackMain ConvertUpdateMain;

		public Convert(int num_pages)
		{
			InitializeComponent();
			GSDevices = new List<Device>();
			ConvertPages = new List<SelectPage>();
			SetDeviceList();
			SetPageList(num_pages);
			xaml_DeviceList.ItemsSource = GSDevices;
			xaml_PageList.ItemsSource = ConvertPages;
		}

		public void SetDeviceList()
		{
			foreach (gsDevice_t device in Enum.GetValues(typeof(gsDevice_t)))
			{
				Device device_t = new Device();
				device_t.DeviceName = Enum.GetName(typeof(gsDevice_t), device);
				device_t.DeviceType = device;
				if (device > gsDevice_t.psdrgb)
					device_t.SupportsMultiPage = true;
				else
					device_t.SupportsMultiPage = false;
				if (device < gsDevice_t.bmp16)
					device_t.MuPDFDevice = true;
				else
					device_t.MuPDFDevice = false;
				GSDevices.Add(device_t);
			}
		}

		public void SetPageList(int num_pages)
		{
			for (int k = 1; k < num_pages + 1; k++ )
			{
				SelectPage Spage = new SelectPage();
				Spage.Page = k;
				Spage.PageString = k;
				ConvertPages.Add(Spage);
			}
		}

		private void ConvertClick(object sender, RoutedEventArgs e)
		{
			ConvertUpdateMain(this);
		}

		private void ConvertCancel(object sender, RoutedEventArgs e)
		{
			this.Close();
		}

		private void HelpConvert(object sender, RoutedEventArgs e)
		{

		}

		private void AllPages(object sender, RoutedEventArgs e)
		{
			xaml_PageList.SelectAll();
		}

		private void EvenPages(object sender, RoutedEventArgs e)
		{
			/* First check if any are selected */
			var item = xaml_PageList.SelectedItem;

			/* If none are selected then get all the evens. otherwise just get
			 * all the evens of the pages that have been selected */
			if (item == null)
			{
				/* Turn on the evens */
				for (int kk = 1; kk < ConvertPages.Count; kk = kk + 2)
					(xaml_PageList.ItemContainerGenerator.ContainerFromIndex(kk) as ListViewItem).IsSelected = true;
			}
			else
			{
				/* Turn off any odds */
				for (int kk = 0; kk < ConvertPages.Count; kk = kk + 2)
					(xaml_PageList.ItemContainerGenerator.ContainerFromIndex(kk) as ListViewItem).IsSelected = false;
			}
		}

		private void OddPages(object sender, RoutedEventArgs e)
		{
			/* First check if any are selected */
			var item = xaml_PageList.SelectedItem;

			/* If none are selected then get all the odds. otherwise just get
				all the odds of the pages that have been selected */
			if (item == null)
			{
				/* Turn on the odds */
				for (int kk = 0; kk < ConvertPages.Count; kk = kk + 2)
					(xaml_PageList.ItemContainerGenerator.ContainerFromIndex(kk) as ListViewItem).IsSelected = true;
			}
			else
			{
				/* Turn off any evens */
				for (int kk = 1; kk < ConvertPages.Count; kk = kk + 2)
					(xaml_PageList.ItemContainerGenerator.ContainerFromIndex(kk) as ListViewItem).IsSelected = false;
			}
		}

		/* Allow only numbers */
		private void PreviewInput(object sender, TextCompositionEventArgs e)
		{
			e.Handled = !IsTextAllowed(e.Text);
		}

		private static bool IsTextAllowed(string text)
		{
			Regex regex = new Regex("[^0-9]+");
			return !regex.IsMatch(text);
		}
	}
}
