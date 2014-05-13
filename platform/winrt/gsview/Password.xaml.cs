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

namespace gsview
{
	/// <summary>
	/// Interaction logic for Password.xaml
	/// </summary>
	public partial class Password : Window
	{
		/* Callback to Main */
		internal delegate void PassCallBackMain(object gsObject);
		internal event PassCallBackMain PassUpdateMain;

		public Password()
		{
			InitializeComponent();
		}

		private void PasswordCheck(object sender, RoutedEventArgs e)
		{
			PassUpdateMain(this);
		}
	}
}
