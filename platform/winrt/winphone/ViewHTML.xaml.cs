using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Navigation;
using Microsoft.Phone.Controls;
using Microsoft.Phone.Shell;

namespace winphone
{
	public partial class ViewHTML : PhoneApplicationPage
	{
		public String HTML_String;

		private void ViewHTML_OnLoaded(object sender, RoutedEventArgs e)
		{
			xaml_viewhtml.NavigateToString(HTML_String);
		}

		public ViewHTML()
		{
			InitializeComponent();
			SupportedOrientations = SupportedPageOrientation.Portrait | SupportedPageOrientation.Landscape;
			xaml_viewhtml.Loaded += ViewHTML_OnLoaded;
		}

		protected override void OnNavigatedTo(System.Windows.Navigation.NavigationEventArgs e)
		{
			base.OnNavigatedTo(e);
			HTML_String = (App.Current as App).appHTML_String;
		}

	}
}