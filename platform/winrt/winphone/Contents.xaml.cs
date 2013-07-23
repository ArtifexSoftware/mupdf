using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Navigation;
using Microsoft.Phone.Controls;
using Microsoft.Phone.Shell;
using mupdfwinrt;

namespace winphone
{
	public partial class Contents : PhoneApplicationPage
	{
		public mudocument mu_doc;
		public int num_items;
		public List<ContentEntry> ContentEntries; 

		public Contents()
		{
			InitializeComponent();
			/* Move the contents to a local structure for binding to the xaml ui */
			for (int k = 0; k < num_items; k++)
			{
				ContentItem item = mu_doc.GetContent(k);
				ContentEntry entry = new ContentEntry(item.StringMargin, item.Page);
				ContentEntries.Add(entry);
			}
			this.xaml_Contents.ItemsSource = ContentEntries;
		}

		private void ContentPicked(object sender, SelectionChangedEventArgs e)
		{
			if (xaml_Contents.SelectedItem == null)
				return;

			/* Back to main page */
			var curr_item = (ContentEntry)xaml_Contents.SelectedItem;
			(App.Current as App).appContentItem = curr_item.PageNum;
			string targetPageUri = "/MainPage.xaml?method={0}";
			NavigationService.Navigate(new Uri(targetPageUri, UriKind.Relative));
		}

		protected override void OnNavigatedTo(System.Windows.Navigation.NavigationEventArgs e)
		{
			base.OnNavigatedTo(e);
			mu_doc = (App.Current as App).appMainDoc;
			num_items = (App.Current as App).appContentItem;
		}
	}
}