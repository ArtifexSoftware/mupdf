using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Packaging;
using System.Printing;
using System.Windows.Controls;
using System.Windows.Documents;
using System.Windows.Documents.Serialization;
using System.Windows.Media;
using System.Windows.Xps;
using System.Windows.Xps.Packaging;
using System.Windows.Xps.Serialization;

namespace gsview
{
	public enum PrintStatus_t
	{
		PRINT_READY,
		PRINT_BUSY,
		PRINT_ERROR,
		PRINT_CANCELLED
	};

	/* Class for handling async print progress callback */
	public class gsPrintEventArgs : EventArgs
	{
		private PrintStatus_t m_status;
		private bool m_completed;
		private int m_page;

		public PrintStatus_t Status
		{
			get { return m_status; }
		}

		public bool Completed
		{
			get { return m_completed; }
		}

		public int Page
		{
			get { return m_page; }
		}

		public gsPrintEventArgs(PrintStatus_t status, bool completed, int page)
		{
			m_completed = completed;
			m_status = status;
			m_page = page;
		}
	}

	public class gsprint
	{
		private XpsDocumentWriter m_docWriter = null;
		internal delegate void AsyncPrintCallBack(object printObject, gsPrintEventArgs info);
		internal event AsyncPrintCallBack PrintUpdate;
		private bool m_busy;

		public bool IsBusy()
		{
			return m_busy;
		}

		public gsprint()
		{
			m_busy = false;
		}

		/* Show std. print dialog */
		public PrintDialog GetPrintDialog()
		{
			PrintDialog dlg = new PrintDialog();
			/* Current page and page ranges is going to require a little work */
			dlg.PageRangeSelection = PageRangeSelection.AllPages;
			//dlg.UserPageRangeEnabled = true;
			//dlg.CurrentPageEnabled = true;
			dlg.SelectedPagesEnabled = false;
			m_busy = false;
			if (dlg.ShowDialog() == true)
				return dlg;
			return null;
		}

		/* Main print entry point */
		public void Print(PrintQueue queu, FixedDocumentSequence fixdoc)
		{
			XpsDocumentWriter docwrite = GetDocWriter(queu);

			m_busy = true;
			docwrite.WritingPrintTicketRequired +=
				new WritingPrintTicketRequiredEventHandler(PrintTicket);
			PrintPages(docwrite, fixdoc);
		}

		/* Send it */
		private void PrintPages(XpsDocumentWriter xpsdw, FixedDocumentSequence fixdoc)
		{
			m_docWriter = xpsdw;
			xpsdw.WritingCompleted +=
				new WritingCompletedEventHandler(AsyncCompleted);
			xpsdw.WritingProgressChanged +=
				new WritingProgressChangedEventHandler(AsyncProgress);
			xpsdw.WriteAsync(fixdoc);
		}

		public void CancelAsync()
		{
			/* ick.  This does not work in windows 8. causes crash */
			/* https://connect.microsoft.com/VisualStudio/feedback/details/778145/xpsdocumentwriter-cancelasync-cause-crash-in-win8 */
			m_docWriter.CancelAsync();
		}

		/* Done */
		private void AsyncCompleted(object sender, WritingCompletedEventArgs e)
		{
			PrintStatus_t status;

			if (e.Cancelled)
				status = PrintStatus_t.PRINT_CANCELLED;
			else if (e.Error != null)
				status = PrintStatus_t.PRINT_ERROR;
			else
				status = PrintStatus_t.PRINT_READY;

			if (PrintUpdate != null)
			{
				gsPrintEventArgs info = new gsPrintEventArgs(status, true, 0);
				PrintUpdate(this, info);
			}
			m_busy = false;
		}

		/* Do this update with each fixed document (page) that is handled */
		private void AsyncProgress(object sender, WritingProgressChangedEventArgs e)
		{
			if (PrintUpdate != null)
			{
				gsPrintEventArgs info = new gsPrintEventArgs(PrintStatus_t.PRINT_BUSY, 
									false, e.Number);
				PrintUpdate(this, info);
			}
		}

		/* Print ticket handling. You can customize for PrintTicketLevel at
		  FixedDocumentSequencePrintTicket, FixedDocumentPrintTicket,
		 or FixedPagePrintTicket.  We may want to play around with this some */
		private void PrintTicket(Object sender, WritingPrintTicketRequiredEventArgs e)
		{
			if (e.CurrentPrintTicketLevel ==
					PrintTicketLevel.FixedDocumentSequencePrintTicket)
			{
				PrintTicket pts = new PrintTicket();
				pts.PageOrientation = PageOrientation.Portrait;
				e.CurrentPrintTicket = pts;
			}
		}

		/* Create the document write */
		private XpsDocumentWriter GetDocWriter(PrintQueue pq)
		{
			XpsDocumentWriter xpsdw = PrintQueue.CreateXpsDocumentWriter(pq);
			return xpsdw;
		}
	}
}
