using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Navigation;
using Microsoft.Phone.Controls;
using Microsoft.Phone.Shell;
using System.IO.IsolatedStorage;
using System.Windows.Media.Imaging;

namespace winphone
{
	public partial class FilesPage : PhoneApplicationPage
	{
		FileList m_local;
		FileList m_skyDrive;
		FileList m_sdCard;
		BitmapImage bmp;
		String m_filename;

		public FilesPage()
		{
			InitializeComponent();

			m_local = new FileList();
			m_skyDrive = new FileList();
			m_sdCard = new FileList();

			var uri = new System.Uri("ms-appx:///Assets/logo_33x33.png");

			bmp = new BitmapImage(uri);
			bmp.CreateOptions = BitmapCreateOptions.BackgroundCreation;
			bmp.ImageOpened += (sender, e) =>
			{
				int zz = 1;
			};

			//bmp = new BitmapImage(uri);
			/* Load in the list of files */

			int temp = bmp.DecodePixelHeight;
			
			PopulateLocal();

			/* Assign data binding */
			this.xaml_Local.ItemsSource = m_local;
			this.xaml_SkyDrive.ItemsSource = m_skyDrive;
			this.xaml_SDCard.ItemsSource = m_sdCard;
		}

		private void PopulateLocal()
		{
			/* Empty out the existing list if it exists */
			if (m_local.Count > 0)
				m_local.Clear();
			using (var store = IsolatedStorageFile.GetUserStoreForApplication())
			{
				var names = store.GetFileNames();
				for (int k = 0; k < names.Length; k++)
				{
					Files file = new Files(0, bmp, names[k]);
					m_local.Add(file);
				}
			}
		}

		//img.Source = ImageFromRelativePath(this, "Assets/Images/back.png");

		private static BitmapImage ImageFromRelativePath(FrameworkElement parent, string path)
		{
			var uri = new Uri("ms-appx://Assets/Images/logo_33x33.png");
			BitmapImage bmp = new BitmapImage();
			bmp.UriSource = uri;
			return bmp;
		}

		private void LocalSelectionChanged(object sender, SelectionChangedEventArgs e)
		{
			if (xaml_Local.SelectedItem == null)
				return;

			var curr_item = (Files) xaml_Local.SelectedItem;
			m_filename = curr_item.Name;
			xaml_Local.SelectedItem = null;

			string targetPageUri = "/MainPage.xaml?method={0}";
			NavigationService.Navigate(new Uri(targetPageUri, UriKind.Relative));
		}

		/* This is used to communicate the file name that was selected to the MainPage */
		protected override void OnNavigatedFrom(NavigationEventArgs e)
		{
			base.OnNavigatedFrom(e);
			if (e.Content is MainPage)
			{
				(e.Content as MainPage).ReceivedData = m_filename;
			}
		}
	}
}