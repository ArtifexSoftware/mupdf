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
using System.Drawing.Printing;

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
			dlg.UserPageRangeEnabled = true;
			dlg.CurrentPageEnabled = true;
			dlg.SelectedPagesEnabled = false;
			m_busy = false;
			if (dlg.ShowDialog() == true)
				return dlg;
			return null;
		}

		/* Main print entry point */
		public void Print(PrintQueue queu, FixedDocumentSequence fixdoc, PrintControl printcontrol)
		{
			XpsDocumentWriter docwrite;
			PrintTicket Ticket = SetUpTicket(queu, printcontrol, fixdoc);
			docwrite = GetDocWriter(queu);
			m_busy = true;
#if DISABLED_FOR_NOW
			docwrite.WritingPrintTicketRequired +=
			 new WritingPrintTicketRequiredEventHandler(PrintTicket);
#endif
			PrintPages(docwrite, fixdoc, Ticket);
		}

		/* Set up the print ticket */
		private PrintTicket SetUpTicket(PrintQueue queue, PrintControl printcontrol, FixedDocumentSequence fixdoc)
		{
			PrintTicket Ticket = new PrintTicket();

			PageMediaSizeName name = PaperKindToPageMediaSize(printcontrol.m_pagedetails.PaperSize.Kind);
			PageMediaSize mediasize = new PageMediaSize(name, printcontrol.m_pagedetails.PaperSize.Width, printcontrol.m_pagedetails.PaperSize.Height);

			/* Media size */
			Ticket.PageMediaSize = mediasize;
			/* Scale to fit */
			Ticket.PageScalingFactor = (int)Math.Round(printcontrol.m_page_scale * 100.0);

			System.Windows.Size page_size = new System.Windows.Size(mediasize.Width.Value, mediasize.Height.Value);
			DocumentPaginator paginator = fixdoc.DocumentPaginator;
			paginator.PageSize = page_size;

			/* Copy Count */
			Ticket.CopyCount = printcontrol.m_numcopies;

			/* Orientation */
			if (printcontrol.m_isrotated)
				if (printcontrol.m_pagedetails.Landscape)
					Ticket.PageOrientation = PageOrientation.Portrait;
				else
					Ticket.PageOrientation = PageOrientation.Landscape;
			else
				if (printcontrol.m_pagedetails.Landscape)
					Ticket.PageOrientation = PageOrientation.Landscape;
				else
					Ticket.PageOrientation = PageOrientation.Portrait;

			System.Printing.ValidationResult result = queue.MergeAndValidatePrintTicket(queue.UserPrintTicket, Ticket);
			queue.UserPrintTicket = result.ValidatedPrintTicket;
			queue.Commit();
			return result.ValidatedPrintTicket;
		}

		/* Send it */
		private void PrintPages(XpsDocumentWriter xpsdw, FixedDocumentSequence fixdoc, PrintTicket Ticket)
		{
			m_docWriter = xpsdw;
			xpsdw.WritingCompleted +=
				new WritingCompletedEventHandler(AsyncCompleted);
			xpsdw.WritingProgressChanged +=
				new WritingProgressChangedEventHandler(AsyncProgress);
			xpsdw.WriteAsync(fixdoc, Ticket);
		}

		public void CancelAsync()
		{
			/* ick.  This does not work in windows 8. causes crash. */
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
#if DISABLED_FOR_NOW
		/* Print ticket handling. You can customize for PrintTicketLevel at
		   FixedDocumentSequencePrintTicket, FixedDocumentPrintTicket,
		   or FixedPagePrintTicket.  We may want to play around with this some */
		private void PrintTicket(Object sender, WritingPrintTicketRequiredEventArgs e)
		{
			if (e.CurrentPrintTicketLevel ==
					PrintTicketLevel.FixedDocumentSequencePrintTicket)
			{
				PrintTicket pts = new PrintTicket();
				e.CurrentPrintTicket = pts;
			}
		}
#endif
		/* Create the document write */
		private XpsDocumentWriter GetDocWriter(PrintQueue pq)
		{
			XpsDocumentWriter xpsdw = PrintQueue.CreateXpsDocumentWriter(pq);
			return xpsdw;
		}

		/* Two paths for designating printing = a pain in the ass.*/
		static PageMediaSizeName PaperKindToPageMediaSize(PaperKind paperKind)
		{
			switch (paperKind)
			{
				case PaperKind.Custom:
					return PageMediaSizeName.Unknown;
				case PaperKind.Letter:
					return PageMediaSizeName.NorthAmericaLetter;
				case PaperKind.Legal:
					return PageMediaSizeName.NorthAmericaLegal;
				case PaperKind.A4:
					return PageMediaSizeName.ISOA4;
				case PaperKind.CSheet:
					return PageMediaSizeName.NorthAmericaCSheet;
				case PaperKind.DSheet:
					return PageMediaSizeName.NorthAmericaDSheet;
				case PaperKind.ESheet:
					return PageMediaSizeName.NorthAmericaESheet;
				case PaperKind.LetterSmall:
					return PageMediaSizeName.Unknown;
				case PaperKind.Tabloid:
					return PageMediaSizeName.NorthAmericaTabloid;
				case PaperKind.Ledger:
					return PageMediaSizeName.Unknown;
				case PaperKind.Statement:
					return PageMediaSizeName.NorthAmericaStatement;
				case PaperKind.Executive:
					return PageMediaSizeName.NorthAmericaExecutive;
				case PaperKind.A3:
					return PageMediaSizeName.ISOA3;
				case PaperKind.A4Small:
					return PageMediaSizeName.Unknown;
				case PaperKind.A5:
					return PageMediaSizeName.ISOA5;
				case PaperKind.B4:
					return PageMediaSizeName.ISOB4;
				case PaperKind.B5:
					return PageMediaSizeName.Unknown;
				case PaperKind.Folio:
					return PageMediaSizeName.OtherMetricFolio;
				case PaperKind.Quarto:
					return PageMediaSizeName.NorthAmericaQuarto;
				case PaperKind.Standard10x14:
					return PageMediaSizeName.Unknown;
				case PaperKind.Standard11x17:
					return PageMediaSizeName.Unknown;
				case PaperKind.Note:
					return PageMediaSizeName.NorthAmericaNote;
				case PaperKind.Number9Envelope:
					return PageMediaSizeName.NorthAmericaNumber9Envelope;
				case PaperKind.Number10Envelope:
					return PageMediaSizeName.NorthAmericaNumber10Envelope;
				case PaperKind.Number11Envelope:
					return PageMediaSizeName.NorthAmericaNumber11Envelope;
				case PaperKind.Number12Envelope:
					return PageMediaSizeName.NorthAmericaNumber12Envelope;
				case PaperKind.Number14Envelope:
					return PageMediaSizeName.NorthAmericaNumber14Envelope;
				case PaperKind.DLEnvelope:
					return PageMediaSizeName.ISODLEnvelope;
				case PaperKind.C5Envelope:
					return PageMediaSizeName.ISOC5Envelope;
				case PaperKind.C3Envelope:
					return PageMediaSizeName.ISOC3Envelope;
				case PaperKind.C4Envelope:
					return PageMediaSizeName.ISOC4Envelope;
				case PaperKind.C6Envelope:
					return PageMediaSizeName.ISOC6Envelope;
				case PaperKind.C65Envelope:
					return PageMediaSizeName.ISOC6C5Envelope;
				case PaperKind.B4Envelope:
					return PageMediaSizeName.ISOB4Envelope;
				case PaperKind.B5Envelope:
					return PageMediaSizeName.ISOB5Envelope;
				case PaperKind.B6Envelope:
					return PageMediaSizeName.Unknown;
				case PaperKind.ItalyEnvelope:
					return PageMediaSizeName.OtherMetricItalianEnvelope;
				case PaperKind.MonarchEnvelope:
					return PageMediaSizeName.NorthAmericaMonarchEnvelope;
				case PaperKind.PersonalEnvelope:
					return PageMediaSizeName.NorthAmericaPersonalEnvelope;
				case PaperKind.USStandardFanfold:
					return PageMediaSizeName.Unknown;
				case PaperKind.GermanStandardFanfold:
					return PageMediaSizeName.NorthAmericaGermanStandardFanfold;
				case PaperKind.GermanLegalFanfold:
					return PageMediaSizeName.NorthAmericaGermanLegalFanfold;
				case PaperKind.IsoB4:
					return PageMediaSizeName.ISOB4;
				case PaperKind.JapanesePostcard:
					return PageMediaSizeName.JapanHagakiPostcard;
				case PaperKind.Standard9x11:
					return PageMediaSizeName.Unknown;
				case PaperKind.Standard10x11:
					return PageMediaSizeName.Unknown;
				case PaperKind.Standard15x11:
					return PageMediaSizeName.Unknown;
				case PaperKind.InviteEnvelope:
					return PageMediaSizeName.OtherMetricInviteEnvelope;
				case PaperKind.LetterExtra:
					return PageMediaSizeName.NorthAmericaLetterExtra;
				case PaperKind.LegalExtra:
					return PageMediaSizeName.NorthAmericaLegalExtra;
				case PaperKind.TabloidExtra:
					return PageMediaSizeName.NorthAmericaTabloidExtra;
				case PaperKind.A4Extra:
					return PageMediaSizeName.ISOA4Extra;
				case PaperKind.LetterTransverse:
					return PageMediaSizeName.Unknown;
				case PaperKind.A4Transverse:
					return PageMediaSizeName.Unknown;
				case PaperKind.LetterExtraTransverse:
					return PageMediaSizeName.Unknown;
				case PaperKind.APlus:
					return PageMediaSizeName.Unknown;
				case PaperKind.BPlus:
					return PageMediaSizeName.Unknown;
				case PaperKind.LetterPlus:
					return PageMediaSizeName.NorthAmericaLetterPlus;
				case PaperKind.A4Plus:
					return PageMediaSizeName.OtherMetricA4Plus;
				case PaperKind.A5Transverse:
					return PageMediaSizeName.Unknown;
				case PaperKind.B5Transverse:
					return PageMediaSizeName.Unknown;
				case PaperKind.A3Extra:
					return PageMediaSizeName.ISOA3Extra;
				case PaperKind.A5Extra:
					return PageMediaSizeName.ISOA5Extra;
				case PaperKind.B5Extra:
					return PageMediaSizeName.ISOB5Extra;
				case PaperKind.A2:
					return PageMediaSizeName.ISOA2;
				case PaperKind.A3Transverse:
					return PageMediaSizeName.Unknown;
				case PaperKind.A3ExtraTransverse:
					return PageMediaSizeName.Unknown;
				case PaperKind.JapaneseDoublePostcard:
					return PageMediaSizeName.JapanDoubleHagakiPostcard;
				case PaperKind.A6:
					return PageMediaSizeName.ISOA6;
				case PaperKind.JapaneseEnvelopeKakuNumber2:
					return PageMediaSizeName.JapanKaku2Envelope;
				case PaperKind.JapaneseEnvelopeKakuNumber3:
					return PageMediaSizeName.JapanKaku3Envelope;
				case PaperKind.JapaneseEnvelopeChouNumber3:
					return PageMediaSizeName.JapanChou3Envelope;
				case PaperKind.JapaneseEnvelopeChouNumber4:
					return PageMediaSizeName.JapanChou4Envelope;
				case PaperKind.LetterRotated:
					return PageMediaSizeName.NorthAmericaLetterRotated;
				case PaperKind.A3Rotated:
					return PageMediaSizeName.ISOA3Rotated;
				case PaperKind.A4Rotated:
					return PageMediaSizeName.ISOA4Rotated;
				case PaperKind.A5Rotated:
					return PageMediaSizeName.ISOA5Rotated;
				case PaperKind.B4JisRotated:
					return PageMediaSizeName.JISB4Rotated;
				case PaperKind.B5JisRotated:
					return PageMediaSizeName.JISB5Rotated;
				case PaperKind.JapanesePostcardRotated:
					return PageMediaSizeName.JapanHagakiPostcardRotated;
				case PaperKind.JapaneseDoublePostcardRotated:
					return PageMediaSizeName.JapanHagakiPostcardRotated;
				case PaperKind.A6Rotated:
					return PageMediaSizeName.ISOA6Rotated;
				case PaperKind.JapaneseEnvelopeKakuNumber2Rotated:
					return PageMediaSizeName.JapanKaku2EnvelopeRotated;
				case PaperKind.JapaneseEnvelopeKakuNumber3Rotated:
					return PageMediaSizeName.JapanKaku3EnvelopeRotated;
				case PaperKind.JapaneseEnvelopeChouNumber3Rotated:
					return PageMediaSizeName.JapanChou3EnvelopeRotated;
				case PaperKind.JapaneseEnvelopeChouNumber4Rotated:
					return PageMediaSizeName.JapanChou4EnvelopeRotated;
				case PaperKind.B6Jis:
					return PageMediaSizeName.JISB6;
				case PaperKind.B6JisRotated:
					return PageMediaSizeName.JISB6Rotated;
				case PaperKind.Standard12x11:
					return PageMediaSizeName.Unknown;
				case PaperKind.JapaneseEnvelopeYouNumber4:
					return PageMediaSizeName.JapanYou4Envelope;
				case PaperKind.JapaneseEnvelopeYouNumber4Rotated:
					return PageMediaSizeName.JapanYou4EnvelopeRotated;
				case PaperKind.Prc16K:
					return PageMediaSizeName.PRC16K;
				case PaperKind.Prc32K:
					return PageMediaSizeName.PRC32K;
				case PaperKind.Prc32KBig:
					return PageMediaSizeName.PRC32KBig;
				case PaperKind.PrcEnvelopeNumber1:
					return PageMediaSizeName.PRC1Envelope;
				case PaperKind.PrcEnvelopeNumber2:
					return PageMediaSizeName.PRC2Envelope;
				case PaperKind.PrcEnvelopeNumber3:
					return PageMediaSizeName.PRC3Envelope;
				case PaperKind.PrcEnvelopeNumber4:
					return PageMediaSizeName.PRC4Envelope;
				case PaperKind.PrcEnvelopeNumber5:
					return PageMediaSizeName.PRC5Envelope;
				case PaperKind.PrcEnvelopeNumber6:
					return PageMediaSizeName.PRC6Envelope;
				case PaperKind.PrcEnvelopeNumber7:
					return PageMediaSizeName.PRC7Envelope;
				case PaperKind.PrcEnvelopeNumber8:
					return PageMediaSizeName.PRC8Envelope;
				case PaperKind.PrcEnvelopeNumber9:
					return PageMediaSizeName.PRC9Envelope;
				case PaperKind.PrcEnvelopeNumber10:
					return PageMediaSizeName.PRC10Envelope;
				case PaperKind.Prc16KRotated:
					return PageMediaSizeName.PRC16KRotated;
				case PaperKind.Prc32KRotated:
					return PageMediaSizeName.PRC32KRotated;
				case PaperKind.Prc32KBigRotated:
					return PageMediaSizeName.Unknown;
				case PaperKind.PrcEnvelopeNumber1Rotated:
					return PageMediaSizeName.PRC1EnvelopeRotated;
				case PaperKind.PrcEnvelopeNumber2Rotated:
					return PageMediaSizeName.PRC2EnvelopeRotated;
				case PaperKind.PrcEnvelopeNumber3Rotated:
					return PageMediaSizeName.PRC3EnvelopeRotated;
				case PaperKind.PrcEnvelopeNumber4Rotated:
					return PageMediaSizeName.PRC4EnvelopeRotated;
				case PaperKind.PrcEnvelopeNumber5Rotated:
					return PageMediaSizeName.PRC5EnvelopeRotated;
				case PaperKind.PrcEnvelopeNumber6Rotated:
					return PageMediaSizeName.PRC6EnvelopeRotated;
				case PaperKind.PrcEnvelopeNumber7Rotated:
					return PageMediaSizeName.PRC7EnvelopeRotated;
				case PaperKind.PrcEnvelopeNumber8Rotated:
					return PageMediaSizeName.PRC8EnvelopeRotated;
				case PaperKind.PrcEnvelopeNumber9Rotated:
					return PageMediaSizeName.PRC9EnvelopeRotated;
				case PaperKind.PrcEnvelopeNumber10Rotated:
					return PageMediaSizeName.PRC10EnvelopeRotated;
				default:
					throw new ArgumentOutOfRangeException("paperKind");
			}
		}
	}
}
