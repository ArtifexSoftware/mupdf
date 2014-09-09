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

namespace gsview
{
	public partial class PageExtractSave : Window
	{
		public List<SelectPage> Pages;
		SelectPage selectedpage = null;
		int dropafterposition;
		bool putattop = false;

		/* Callback to Main */
		internal delegate void ExtractCallBackMain(object gsObject);
		internal event ExtractCallBackMain ExtractMain;

		public PageExtractSave(int num_pages)
		{
			InitializeComponent();
			Pages = new List<SelectPage>();
			SetPageList(num_pages);
			xaml_PageList.ItemsSource = Pages;
		}

		private void AllPages(object sender, RoutedEventArgs e)
		{
			xaml_PageList.SelectAll();
		}

		public void SetPageList(int num_pages)
		{
			for (int k = 1; k < num_pages + 1; k++)
			{
				SelectPage Spage = new SelectPage();
				Spage.Page = k;
				Spage.PageString = k;
				Pages.Add(Spage);
			}
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
				for (int kk = 1; kk < Pages.Count; kk = kk + 2)
					(xaml_PageList.ItemContainerGenerator.ContainerFromIndex(kk) as ListViewItem).IsSelected = true;
			}
			else
			{
				/* Turn off any odds */
				for (int kk = 0; kk < Pages.Count; kk = kk + 2)
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
				for (int kk = 0; kk < Pages.Count; kk = kk + 2)
					(xaml_PageList.ItemContainerGenerator.ContainerFromIndex(kk) as ListViewItem).IsSelected = true;
			}
			else
			{
				/* Turn off any evens */
				for (int kk = 1; kk < Pages.Count; kk = kk + 2)
					(xaml_PageList.ItemContainerGenerator.ContainerFromIndex(kk) as ListViewItem).IsSelected = false;
			}
		}

		private void ExtractPages(object sender, RoutedEventArgs e)
		{
			ExtractMain(this);
		}

		private void ExtractLeftButtonDown(object sender, MouseButtonEventArgs e)
		{
			int index = GetCurrentIndex();
			if (index > -1 && index < Pages.Count)
				selectedpage = Pages[index];
		}

		private void ExtractLeftButtonUp(object sender, MouseButtonEventArgs e)
		{
			/* Check if we have something selected */
			if (selectedpage == null)
			{
				Cursor = Cursors.Arrow;
				return;
			}

			Point posit = e.GetPosition(xaml_PageList);
			dropafterposition = GetCurrentIndex();
			putattop = false;

			if (dropafterposition < 0)
			{
				/* Check if we are above or below */
				if (posit.Y < 0)
					putattop = true;
				else
					dropafterposition = xaml_PageList.Items.Count - 1;
			}
			Cursor = Cursors.Arrow;
			MoveItem();
			selectedpage = null;
		}

		private void MoveItem()
		{
			if (putattop)
			{
				Pages.Remove(selectedpage);
				Pages.Insert(0, selectedpage);
			}
			else
			{
				Pages.Remove(selectedpage);
				Pages.Insert(dropafterposition, selectedpage);
			}
			xaml_PageList.Items.Refresh();
		}

		private void ExtractMouseMove(object sender, MouseEventArgs e)
		{
			if (Mouse.LeftButton == MouseButtonState.Pressed)
				Cursor = Cursors.Hand;
		}

		private void ExtractMouseLeave(object sender, MouseEventArgs e)
		{
			Cursor = Cursors.Arrow;
		}

		private void RightButtonDown(object sender, MouseButtonEventArgs e)
		{
			var contextmenu = new System.Windows.Controls.ContextMenu();
			this.ContextMenu = contextmenu;

			var m1 = new System.Windows.Controls.MenuItem();
			m1.Header = "Delete";
			m1.Click += cntxDeleteItem;
			contextmenu.Items.Add(m1);
		}

		/* Delete all selected items */
		private void cntxDeleteItem(object sender, RoutedEventArgs e)
		{
			/* Go backwards */
			var temp = xaml_PageList.SelectedItems;
			int max = temp.Count; ;
			for (int i = 0; i < max; i++)
			{
				var item = temp[i];
				Pages.Remove((SelectPage)item);
			}
			xaml_PageList.Items.Refresh();
		}

		int GetCurrentIndex()
		{
			int index = -1;
			for (int i = 0; i < this.xaml_PageList.Items.Count; ++i)
			{
				ListViewItem item = GetListViewItem(i);
				if (item.IsMouseOver)
				{
					index = i;
					break;
				}
			}
			return index;
		}

		ListViewItem GetListViewItem(int index)
		{
			if (this.xaml_PageList.ItemContainerGenerator.Status != 
				System.Windows.Controls.Primitives.GeneratorStatus.ContainersGenerated)
				return null;
			return this.xaml_PageList.ItemContainerGenerator.ContainerFromIndex(index) as ListViewItem;
		}

		private void Reverse(object sender, RoutedEventArgs e)
		{
			Pages.Reverse();
			xaml_PageList.Items.Refresh();
		}
	}
}
