using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
//using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Shapes;
using System.Windows.Forms;

namespace gsview
{
	public enum OutputIntent_t
	{
		GRAY,
		RGB,
		CMYK
	}

	/// <summary>
	/// Interaction logic for OutputIntent.xaml
	/// </summary>
	public partial class OutputIntent : Window
	{
		public String gray_icc;
		public String rgb_icc;
		public String cmyk_icc;

		public OutputIntent()
		{
			InitializeComponent();
			this.Closing += new System.ComponentModel.CancelEventHandler(FakeWindowClosing);
			gray_icc = null;
			rgb_icc = null;
			cmyk_icc = null;
		}

		void FakeWindowClosing(object sender, System.ComponentModel.CancelEventArgs e)
		{
			e.Cancel = true;
			this.Hide();
		}

		public void RealWindowClosing()
		{
			this.Closing -= new System.ComponentModel.CancelEventHandler(FakeWindowClosing);
			this.Close();
		}
		
		/* No error checking in here yet for making sure the profiles are of
		 * the right type and are valid */
		private void SelectGray(object sender, RoutedEventArgs e)
		{
			SetIntent(OutputIntent_t.GRAY);
		}

		private void SelectRGB(object sender, RoutedEventArgs e)
		{
			SetIntent(OutputIntent_t.RGB);
		}

		private void SelectCMYK(object sender, RoutedEventArgs e)
		{
			SetIntent(OutputIntent_t.CMYK);
		}

		private void SetIntent(OutputIntent_t intent)
		{
			OpenFileDialog dlg = new OpenFileDialog();
			dlg.Filter = "ICC Profile Files(*.icc;*.icm)|*.icc;*.icm";
			dlg.FilterIndex = 1;
			if (dlg.ShowDialog() == System.Windows.Forms.DialogResult.OK)
			{
				switch(intent)
				{
					case OutputIntent_t.GRAY:
						gray_icc = dlg.FileName;
						this.xaml_gray.Text = gray_icc;
						this.xaml_gray.BorderBrush = new SolidColorBrush(Colors.Green);
						break;
					case OutputIntent_t.RGB:
						rgb_icc = dlg.FileName;
						this.xaml_rgb.Text = rgb_icc;
						this.xaml_rgb.BorderBrush = new SolidColorBrush(Colors.Green);
						break;
					case OutputIntent_t.CMYK:
						cmyk_icc = dlg.FileName;
						this.xaml_cmyk.Text = cmyk_icc;
						this.xaml_cmyk.BorderBrush = new SolidColorBrush(Colors.Green);
						break;
				}
			}
		}

		private void ClickOK(object sender, RoutedEventArgs e)
		{
			this.Hide();
		}
	}
}
