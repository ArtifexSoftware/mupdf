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
	/// Interaction logic for Selection.xaml
	/// </summary>
	/// 

	public enum SelectStatus_t
	{
		OK,
		CANCEL,
		SELECT,
		CLOSE,
		ZOOMIN,
		ZOOMOUT
	}

	public class SelectEventArgs : EventArgs
	{
		Point m_topleft, m_size;
		double m_zoomFactor;
		SelectStatus_t m_state;
		int m_page_num;
		Extract_Type_t m_type;

		public Point TopLeft
		{
			get { return m_topleft; }
		}

		public Point Size
		{
			get { return m_size; }
		}

		public double ZoomFactor
		{
			get { return m_zoomFactor; }
		}

		public int PageNum
		{
			get { return m_page_num; }
		}

		public SelectStatus_t State
		{
			get { return m_state; }
		}

		public Extract_Type_t Type
		{
			get { return m_type; }
		}

		public SelectEventArgs(Point start, Point size, double zoom, 
			SelectStatus_t state, int page, Extract_Type_t type)
		{
			m_topleft = start;
			m_size = size;
			m_zoomFactor = zoom;
			m_state = state;
			m_page_num = page;
			m_type = type;
		}
	}

	public partial class Selection : Window
	{
		private Point m_startPoint, m_topleft;
		private Point m_size;
		public SelectStatus_t m_curr_state;
		double m_zoom;
		double m_old_zoom;
		int m_page_num;
		private Rectangle m_rect;
		Extract_Type_t m_type;
		internal delegate void CallBackMain(object gsObject, SelectEventArgs info);
		internal event CallBackMain UpdateMain;

		public Selection(int page, double init_zoom, Extract_Type_t type)
		{
			InitializeComponent();
			this.Closing += new System.ComponentModel.CancelEventHandler(WindowClosing);
			m_page_num = page;
			m_zoom = init_zoom;
			m_curr_state = SelectStatus_t.OK;
			m_type = type;
			m_rect = null;
		}

		void WindowClosing(object sender, System.ComponentModel.CancelEventArgs e)
		{
			var result = new SelectEventArgs(m_topleft, m_size, m_zoom,
				SelectStatus_t.CANCEL, m_page_num, m_type);
			UpdateMain(this, result);
		}

		private void ClickOK(object sender, RoutedEventArgs e)
		{
			if (m_curr_state != SelectStatus_t.OK)
				return;
			if (m_rect == null)
				Close();
			else
			{
				m_size.X = m_rect.Width;
				m_size.Y = m_rect.Height;
				m_topleft.Y = xaml_Image.Height - m_topleft.Y - m_size.Y;
				var result = new SelectEventArgs(m_topleft, m_size, m_zoom,
					SelectStatus_t.SELECT, m_page_num, m_type);
				UpdateMain(this, result);
			}
		}

		private void ClickExit(object sender, RoutedEventArgs e)
		{
			var result = new SelectEventArgs(m_topleft, m_size, m_zoom,
				SelectStatus_t.CANCEL, m_page_num, m_type);
			UpdateMain(this, result);
			Close();
		}

		private void ClickClear(object sender, RoutedEventArgs e)
		{
			if (m_rect != null)
			{
				xaml_Canvas.Children.Remove(m_rect);
				m_rect = null;
			}
		}

		private void ZoomIn(object sender, RoutedEventArgs e)
		{
			if (m_curr_state != SelectStatus_t.OK || m_zoom >= Constants.ZOOM_MAX)
				return;
			m_old_zoom = m_zoom;
			m_zoom = m_zoom + Constants.ZOOM_STEP;
			if (m_zoom > Constants.ZOOM_MAX)
			{
				m_zoom = Constants.ZOOM_MAX;
				return;
			}
			m_curr_state = SelectStatus_t.ZOOMIN;
			var result = new SelectEventArgs(m_startPoint, m_size, m_zoom,
				SelectStatus_t.ZOOMIN, m_page_num, m_type);
			UpdateMain(this, result);
		}

		private void ZoomOut(object sender, RoutedEventArgs e)
		{
			if (m_curr_state != SelectStatus_t.OK || m_zoom <= Constants.ZOOM_MIN)
				return;
			m_old_zoom = m_zoom;
			m_zoom = m_zoom - Constants.ZOOM_STEP;
			if (m_zoom < Constants.ZOOM_MIN)
			{
				m_zoom = Constants.ZOOM_MIN;
				return;
			}
			m_curr_state = SelectStatus_t.ZOOMOUT;
			var result = new SelectEventArgs(m_startPoint, m_size, m_zoom,
				SelectStatus_t.ZOOMOUT, m_page_num, m_type);
			UpdateMain(this, result);
		}

		/* Called when we have had a zoom change */
		public void UpdateRect()
		{
			if (m_rect != null)
			{
				double left = Canvas.GetLeft(m_rect);
				double top = Canvas.GetTop(m_rect);
				Canvas.SetLeft(m_rect, left * m_zoom / m_old_zoom);
				Canvas.SetTop(m_rect, top * m_zoom / m_old_zoom);
				m_rect.Width = m_rect.Width * m_zoom / m_old_zoom;
				m_rect.Height = m_rect.Height * m_zoom / m_old_zoom;
			}
		}

		private void Canvas_MouseDown(object sender, MouseButtonEventArgs e)
		{
			if (m_rect != null)
			{
				xaml_Canvas.Children.Remove(m_rect);
			}

			m_startPoint = e.GetPosition(xaml_Canvas);

			m_rect = new Rectangle
			{
				Stroke = Brushes.Red,
				StrokeThickness = 2
			};
			Canvas.SetLeft(m_rect, m_startPoint.X);
			Canvas.SetTop(m_rect, m_startPoint.X);
			xaml_Canvas.Children.Add(m_rect);
		}

		private void Canvas_MouseMove(object sender, MouseEventArgs e)
		{
			if (e.LeftButton == MouseButtonState.Released || m_rect == null)
				return;

			var pos = e.GetPosition(xaml_Canvas);

			var x = Math.Min(pos.X, m_startPoint.X);
			var y = Math.Min(pos.Y, m_startPoint.Y);

			var w = Math.Max(pos.X, m_startPoint.X) - x;
			var h = Math.Max(pos.Y, m_startPoint.Y) - y;

			m_rect.Width = w;
			m_rect.Height = h;

			m_topleft.X = x;
			m_topleft.Y = y;
			Canvas.SetLeft(m_rect, x);
			Canvas.SetTop(m_rect, y);
		}
	}
}
