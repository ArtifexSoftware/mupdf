using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.ComponentModel;
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
using System.Threading;

namespace gsview
{
	public enum PrintStatus_t
	{
		PRINT_READY,
		PRINT_BUSY,
		PRINT_ERROR
	};

	public enum PrintResult_t
	{
		PrintOK,
		PrintFAILED,
		PrintCANCELLED,
		PrintCOMPLETED
	}

	public struct PrintParams_t
	{
		public int num_pages;
		public int start_page;
		public int end_page;
		public PrintQueue queu;
		public FixedDocumentSequence fixdoc;
		public PrintResult_t result;
		public PrintStatus_t status;

	};

	public class PrintEventArgs : EventArgs
	{
		private PrintStatus_t m_status;
		private PrintResult_t m_result;
		private int m_percentdone;

		public PrintStatus_t Status
		{
			get { return m_status; }
		}

		public PrintResult_t Result
		{
			get { return m_result; }
		}

		public int Percent
		{
			get { return m_percentdone; }
		}

		public PrintEventArgs(PrintStatus_t status, PrintResult_t completed, int percent)
		{
			m_status = status;
			m_result = completed;
			m_percentdone = percent;
		}
	}

	public class gsprintbg
	{
		BackgroundWorker m_worker;
		private XpsDocumentWriter m_docWriter = null;
		PrintParams_t m_pparams;

		internal delegate void PrintCallBackMain(object gsObject, PrintEventArgs info);
		internal event PrintCallBackMain PrintUpdateMain;

		private void PrintProgressChanged(object sender, ProgressChangedEventArgs e)
		{
			/* Callback with progress */
			PrintEventArgs info = new PrintEventArgs(m_pparams.status, m_pparams.result, e.ProgressPercentage);
			if (PrintUpdateMain != null)
				PrintUpdateMain(this, info);
		}

		/* Callback */
		private void PrintCompleted(object sender, RunWorkerCompletedEventArgs e)
		{
			PrintParams_t Value;
			PrintEventArgs info;
			PrintParams_t Params = (PrintParams_t)e.Result;

			if (e.Cancelled)
			{
				info = new PrintEventArgs(PrintStatus_t.PRINT_READY, PrintResult_t.PrintCANCELLED, 100);
			}
			else
			{
				Value = (PrintParams_t)e.Result;
				info = new PrintEventArgs(PrintStatus_t.PRINT_READY, PrintResult_t.PrintCOMPLETED, 100);
			}
			PrintUpdateMain(this, info);
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
			if (dlg.ShowDialog() == true)
				return dlg;
			return null;
		}

		/* Main print entry point */
		private void Print(PrintParams_t pparams)
		{
			XpsDocumentWriter docwrite = GetDocWriter(pparams.queu);
			docwrite.WritingPrintTicketRequired +=
				new WritingPrintTicketRequiredEventHandler(PrintTicket);
			PrintPages(docwrite, pparams.fixdoc);
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

		private void CancelAsync()
		{
			/* ick.  This does not work in windows 8. causes crash */
			/* https://connect.microsoft.com/VisualStudio/feedback/details/778145/xpsdocumentwriter-cancelasync-cause-crash-in-win8 */
			m_docWriter.CancelAsync();
		}

		/* Done */
		private void AsyncCompleted(object sender, WritingCompletedEventArgs e)
		{
			if (e.Cancelled)
				m_pparams.result = PrintResult_t.PrintCANCELLED;
			else if (e.Error != null)
				m_pparams.result = PrintResult_t.PrintFAILED;
			else
				m_pparams.result = PrintResult_t.PrintCOMPLETED;
			m_worker.ReportProgress(100);
		}

		/* Do this update with each fixed document (page) that is handled */
		private void AsyncProgress(object sender, WritingProgressChangedEventArgs e)
		{
			double perc = 100.0 * (double) e.Number / (double) m_pparams.num_pages;
			m_worker.ReportProgress((int) perc);
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


		private void PrintWork(object sender, DoWorkEventArgs e)
		{
			PrintParams_t PParams = (PrintParams_t)e.Argument;
			BackgroundWorker worker = sender as BackgroundWorker;

			Print(PParams);
		}

		public bool IsBusy()
		{
			if (m_worker != null)
				return m_worker.IsBusy;
			else
				return false;
		}

		public void PrintWorkThread(object data)
		{
			PrintParams_t PParams = (PrintParams_t) data;
			Print(PParams);
		}
		
		public PrintStatus_t StartPrint(PrintParams_t pparams)
		{
			try
			{
				if (m_worker != null && m_worker.IsBusy)
				{
					m_worker.CancelAsync();
					return PrintStatus_t.PRINT_BUSY;
				}

				if (m_worker == null)
				{

					Thread asyncThread = new Thread(PrintWorkThread);
					asyncThread.SetApartmentState(ApartmentState.STA);
					asyncThread.Start(pparams);

				/*	m_worker = new BackgroundWorker();
					m_worker.WorkerReportsProgress = true;
					m_worker.WorkerSupportsCancellation = true;
					m_worker.RunWorkerCompleted += new RunWorkerCompletedEventHandler(PrintCompleted);
					m_worker.ProgressChanged += new ProgressChangedEventHandler(PrintProgressChanged);
					m_worker.DoWork += new DoWorkEventHandler(PrintWork);*/
				}

				////m_pparams = pparams;
				//m_worker.RunWorkerAsync(pparams);
				pparams.status = PrintStatus_t.PRINT_BUSY;
				return PrintStatus_t.PRINT_READY;
			}
			catch (OutOfMemoryException e)
			{
				Console.WriteLine("Memory allocation failed during printing\n");
				return PrintStatus_t.PRINT_ERROR;
			}
		}


		public void Cancel()
		{
			m_worker.CancelAsync();
		}
	}
}
