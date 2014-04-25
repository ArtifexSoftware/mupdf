using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Threading;
using System.Runtime.InteropServices;
using System.Security;
using System.Windows;
using System.ComponentModel;

/* This file contains the interface between the muctx cpp class, which
	implements the mupdf calls and the .net managed code  */

namespace gsview
{
	/* Parameters for conversion */
	public struct ConvertParams_t
	{
		public int resolution;
		public gsDevice_t device;
		public String outputfile;
		public int num_pages;
		public System.Collections.IList pages;
		public int currpage;
		public GS_Result_t result;
	};

	/* Must match enum in muctx.h */
	enum mudevice_t
	{
		SVG_OUT,
		PNM_OUT,
		PCL_OUT,
		PWG_OUT,
	};

	public class muPDFEventArgs : EventArgs
	{
		private bool m_completed;
		private int m_progress;
		private ConvertParams_t m_param;

		public bool Completed
		{
			get { return m_completed; }
		}

		public ConvertParams_t Params
		{
			get { return m_param; }
		}

		public int Progress
		{
			get { return m_progress; }
		}

		public muPDFEventArgs(bool completed, int progress, ConvertParams_t param)
		{
			m_completed = completed;
			m_progress = progress;
			m_param = param;
		}
	}

	public struct content_s
	{
		public int page;
		public IntPtr string_margin;
	}

	[SuppressUnmanagedCodeSecurity]
	class mudocument
	{
		IntPtr mu_object;
		BackgroundWorker m_worker;
		ConvertParams_t m_params;
		/* Callbacks to Main */
		internal delegate void mupdfCallBackMain(object gsObject, muPDFEventArgs info);
		internal event mupdfCallBackMain mupdfUpdateMain;

		private System.Object m_lock = new System.Object();  
		public List<ContentItem> contents;

		/* The list of functions that we use to call into C interface of muctx.
		 * Calling into C++ code from managed code is complex. Since CLR 
		 * compiling is needed and that does not support mutex. Hence the C
		 * interface */
		[DllImport("mupdfnet.dll", CharSet = CharSet.Auto,
			CallingConvention = CallingConvention.StdCall)]
		public static extern IntPtr mInitialize();

		[DllImport("mupdfnet.dll", CharSet = CharSet.Auto,
			CallingConvention = CallingConvention.StdCall)]
		public static extern status_t mOpenDocument(IntPtr ctx, string filename);

		[DllImport("mupdfnet.dll", CharSet = CharSet.Auto,
			CallingConvention = CallingConvention.StdCall)]
		public static extern void mCleanUp(IntPtr ctx);

		[DllImport("mupdfnet.dll", CharSet = CharSet.Auto,
			CallingConvention = CallingConvention.StdCall)]
		public static extern int mGetPageCount(IntPtr ctx);

		[DllImport("mupdfnet.dll", CharSet = CharSet.Auto,
			CallingConvention = CallingConvention.StdCall)]
		public static extern bool mRequiresPassword(IntPtr ctx);

		[DllImport("mupdfnet.dll", CharSet = CharSet.Auto,
			CallingConvention = CallingConvention.StdCall)]
		public static extern bool mApplyPassword(IntPtr ctx, string password);

		[DllImport("mupdfnet.dll", CharSet = CharSet.Auto,
			CallingConvention = CallingConvention.StdCall)]
		public static extern int mRenderPage(IntPtr ctx,
			int page_num, Byte[] bmp_data, int bmp_width, 
			int bmp_height, double scale, bool flipy);

		[DllImport("mupdfnet.dll", CharSet = CharSet.Auto,
			CallingConvention = CallingConvention.StdCall)]
		public static extern int mMeasurePage(IntPtr ctx, int page_num,
			ref double width, ref double height);

		[DllImport("mupdfnet.dll", CharSet = CharSet.Auto,
			CallingConvention = CallingConvention.StdCall)]
		public static extern int mGetContents(IntPtr ctx);

		[DllImport("mupdfnet.dll", CharSet = CharSet.Auto,
			CallingConvention = CallingConvention.StdCall)]
		public static extern void mReleaseContents();

		/* The managed code Marshal actually releases the allocated string from C */
		[DllImport("mupdfnet.dll", CharSet = CharSet.Ansi,
			CallingConvention = CallingConvention.StdCall)]
		[return: MarshalAs(UnmanagedType.LPStr)]
		public static extern string mGetContentsItem(int k, ref int len, ref int page);

		[DllImport("mupdfnet.dll", CharSet = CharSet.Auto,
			CallingConvention = CallingConvention.StdCall)]
		public static extern IntPtr mCreateDisplayList(IntPtr ctx, int page_num,
				ref int page_width, ref int page_height);

		[DllImport("mupdfnet.dll", CharSet = CharSet.Auto,
			CallingConvention = CallingConvention.StdCall)]
		public static extern IntPtr mCreateDisplayListText(IntPtr ctx, int page_num,
				ref int page_width, ref int page_height, ref IntPtr text, ref int length);

		[DllImport("mupdfnet.dll", CharSet = CharSet.Auto,
			CallingConvention = CallingConvention.StdCall)]
		public static extern int mRenderPageMT(IntPtr ctx, IntPtr dlist,
			int page_width, int page_height, Byte[] bmp_data, int bmp_width, 
			int bmp_height, double scale, bool flipy);

		[DllImport("mupdfnet.dll", CharSet = CharSet.Auto,
			CallingConvention = CallingConvention.StdCall)]
		public static extern int mTextSearchPage(IntPtr ctx, int page_num,
			string needle);

		[DllImport("mupdfnet.dll", CharSet = CharSet.Auto,
			CallingConvention = CallingConvention.StdCall)]
		public static extern bool mGetTextSearchItem(int item_num, ref double top_x,
			ref double top_y, ref double height, ref double width);
		
		[DllImport("mupdfnet.dll", CharSet = CharSet.Auto,
			CallingConvention = CallingConvention.StdCall)]
		public static extern void mReleaseTextSearch();

		[DllImport("mupdfnet.dll", CharSet = CharSet.Auto,
			CallingConvention = CallingConvention.StdCall)]
		public static extern int mGetLinksPage(IntPtr ctx, int page_num);

		/* The managed code Marshal actually releases the allocated string from C */
		[DllImport("mupdfnet.dll", CharSet = CharSet.Ansi,
			CallingConvention = CallingConvention.StdCall)]
		[return: MarshalAs(UnmanagedType.LPStr)]
		public static extern string mGetLinkItem(int item_num, ref double top_x,
			ref double top_y, ref double height, ref double width, ref int topage, 
			ref int type);

		[DllImport("mupdfnet.dll", CharSet = CharSet.Auto,
			CallingConvention = CallingConvention.StdCall)]
		public static extern void mReleaseLink();

		[DllImport("mupdfnet.dll", CharSet = CharSet.Auto,
			CallingConvention = CallingConvention.StdCall)]
		public static extern void mReleaseText(IntPtr ctx, IntPtr textpage);

		[DllImport("mupdfnet.dll", CharSet = CharSet.Auto,
			CallingConvention = CallingConvention.StdCall)]
		public static extern int mGetTextBlock(IntPtr textpage, int block_num,
			ref double top_x,ref double top_y, ref double height, ref double width);

		[DllImport("mupdfnet.dll", CharSet = CharSet.Auto,
			CallingConvention = CallingConvention.StdCall)]
		public static extern int mGetTextLine(IntPtr textpage, int block_num, 
			int line_num, ref double top_x, ref double top_y, ref double height, 
			ref double width);

		[DllImport("mupdfnet.dll", CharSet = CharSet.Auto,
			CallingConvention = CallingConvention.StdCall)]
		public static extern int mGetTextCharacter(IntPtr textpage, int block_num, 
			int line_num, int item_num, ref double top_x,
			ref double top_y, ref double height, ref double width);

		[DllImport("mupdfnet.dll", CharSet = CharSet.Auto,
			CallingConvention = CallingConvention.StdCall)]
		public static extern int mExtractPages(String infile, String outfile, 
			String password, bool has_password, bool linearize, int num_pages, 
			IntPtr pages);

		[DllImport("mupdfnet.dll", CharSet = CharSet.Auto,
			CallingConvention = CallingConvention.StdCall)]
		public static extern int mSavePage(IntPtr ctx, String outfile, 
			int page_num, int res, int type, bool append);

		public status_t Initialize()
		{
			mu_object = mInitialize();
			if (mu_object == null)
			{
				return status_t.E_FAILURE;
			}
			else
			{
				return status_t.S_ISOK;
			}
		}

		public void CleanUp()
		{
			if (mu_object != null)
			{
				lock(m_lock)
					mCleanUp(mu_object);
			}
		}

		public int GetPageCount()
		{
			return mGetPageCount(mu_object);
		}

		public bool RequiresPassword()
		{
			return mRequiresPassword(mu_object);
		}

		public bool ApplyPassword(String password)
		{
			return mApplyPassword(mu_object, password);
		}

		public int RenderPage(int page_num, Byte[] bmp_data, int bmp_width,
			int bmp_height, double scale, bool flipy, bool use_dlist, bool
			get_text, out BlocksText blocks)
		{
			int code;
			blocks = null;
			String blockcolor = "#00FFFFFF";
			String linecolor = "#402572AC";
			/* Debug */
			//blockcolor = "#4000FF00";

			if (use_dlist) 
			{
				IntPtr dlist = IntPtr.Zero;
				IntPtr text = IntPtr.Zero;
				int num_blocks = 0;

				int page_height = 0;
				int page_width = 0;

				if (get_text)
				{
					lock (m_lock)
					{
						dlist = mCreateDisplayListText(mu_object, page_num,
							ref page_width, ref page_height, ref text, ref num_blocks);
					}
					/* If we have some text go ahead and get the bounding boxes 
					 * now. There is likely a better way to do this with passing
					 * a structure across the boundary in a single call.  ToDO */
					/* Length here is the number of blocks.  mupdf splits block
					 * into lines (spans) and then these into text characters 
					 * Our goal here is to get them into a structure that we 
					 * can rapidly use in our ui display.  Maintaining the block
					 * and span stucture so that we can minimize the number of
					 * rects that are introduced */
					if (num_blocks > 0)
					{
						blocks = new BlocksText();
						for (int kk = 0; kk < num_blocks; kk++)
						{
							double top_x = 0, top_y = 0, height = 0, width = 0;
							var block = new TextBlock();

							int num_lines = mGetTextBlock(text, kk, ref top_x,
								ref top_y, ref height, ref width);

							block.X = top_x;
							block.Y = top_y;
							block.Width = width;
							block.Height = height;
							block.Color = blockcolor;
							block.Scale = 1.0;
							block.PageNumber = page_num;
							blocks.Add(block);

							blocks[kk].TextLines = new List<TextLine>();
							for (int jj = 0; jj < num_lines; jj++)
							{
								var line = new TextLine();
								int num_chars = mGetTextLine(text, kk, jj, ref top_x,
									ref top_y, ref height, ref width);
								line.X = top_x;
								line.Y = top_y;
								line.Width = width;
								line.Height = height;
								line.Scale = 1.0;
								line.Color = linecolor;
								blocks[kk].TextLines.Add(line);

								blocks[kk].TextLines[jj].TextCharacters = new List<TextCharacter>();
								for (int mm = 0; mm < num_chars; mm++)
								{
									var textchars = new TextCharacter();
									int character = mGetTextCharacter(text, kk, jj, mm, ref top_x,
										ref top_y, ref height, ref width);
									textchars.X = top_x;
									textchars.Y = top_y;
									textchars.Width = width;
									textchars.Height = height;
									textchars.Scale = 1.0;
									textchars.Color = linecolor;
									textchars.character = System.Convert.ToChar(character).ToString();
									blocks[kk].TextLines[jj].TextCharacters.Add(textchars);
								}
							}
						}
						/* We are done with the text object */
						mReleaseText(mu_object, text);
					}
				}
				else
					lock (m_lock)
					{
						dlist = mCreateDisplayList(mu_object, page_num, 
							ref page_width, ref page_height);
					}

				/* Rendering of display list can occur with other threads so unlock */
				if (dlist == null)
				{
					return (int) status_t.E_FAILURE;
				}
				code = mRenderPageMT(mu_object, dlist, page_width, page_height,
									bmp_data, bmp_width, bmp_height,
									scale, flipy);
			} 
			else
 			{
				lock(m_lock)
				{
					code = mRenderPage(mu_object, page_num, bmp_data, bmp_width,
						bmp_height, scale, flipy);
				}
			}
			return code;
		}

		public status_t OpenFile(string filename)
		{
			return mOpenDocument(mu_object, filename);
		}

		public int GetPageSize(int page_num, out Point size_out)
		{
			int code;
			double height = 0, width = 0;

			size_out = new Point();

			lock(m_lock)
			{
				code = mMeasurePage(mu_object, page_num, ref width, ref height);
			}

			size_out.X = width;
			size_out.Y = height;
			return code;
		}

		public int ComputeContents()
		{
			int num_items;
			int len = 0, page = 0;

			lock(m_lock)
			{
				num_items = mGetContents(mu_object);
			}

			if (contents == null)
				contents = new List<ContentItem>();

			for (int k = 0; k < num_items; k++)
			{
				ContentItem item = new ContentItem();
				item.StringMargin = mGetContentsItem(k, ref len, ref page);
				item.Page = page;
				contents.Add(item);
			}
			return num_items;
		}

		public void ReleaseContents()
		{
			mReleaseContents();
		}

		public int TextSearchPage(int page_num, String needle)
		{
			int num_found;
			lock (m_lock)
			{
				num_found = mTextSearchPage(mu_object, page_num, needle);
			}
			return num_found;
		}

		public bool GetTextSearchItem(int k, out Point top_left, out Size size_rect)
		{
			double top_x = 0, top_y = 0 , height = 0, width = 0;
			bool found = mGetTextSearchItem(k, ref top_x, ref top_y, ref height, ref width);

			top_left = new Point();
			size_rect = new Size();

			top_left.X = top_x;
			top_left.Y = top_y;
			size_rect.Width = width;
			size_rect.Height = height;

			return found;
		}

		public void ReleaseTextSearch()
		{
			mReleaseTextSearch();
		}

		public int GetLinksPage(int page_num)
		{
			int num_found;
			lock (m_lock)
			{
				num_found = mGetLinksPage(mu_object, page_num);
			}
			return num_found;
		}

		public void GetLinkItem(int k, out Point top_left, out Size size_rect, 
			out String uri, out int topage, out int typea)
		{
			double top_x = 0, top_y = 0, height = 0, width = 0;
			int typeb = 0;
			int linkpage = 0;

			uri = mGetLinkItem(k, ref top_x, ref top_y, ref height, ref width,
				ref linkpage, ref typeb);

			topage = linkpage;
			typea = typeb;
			top_left = new Point();
			size_rect = new Size();

			top_left.X = top_x;
			top_left.Y = top_y;
			size_rect.Width = width;
			size_rect.Height = height;
		}

		public void ReleaseLink()
		{
			mReleaseLink();
		}

		public void ReleaseText(IntPtr textpage)
		{
			mReleaseText(mu_object, textpage);
		}

		public void PDFExtract(String infile, String outfile, String password, 
			bool has_password, bool linearize, int num_pages, System.Collections.IList pages)
		{
			if (num_pages > 0)
			{
				/* We need to do an allocation for our array of page numbers and
				 * perform pinning to avoid GC while in the c++ code */
				GCHandle pagesPtrStable;
				int[] page_list;
				page_list = new int[pages.Count];

				for (int kk = 0; kk < pages.Count; kk++)
				{
					SelectPage currpage = (SelectPage)pages[kk];
					page_list[kk] = currpage.Page;
				}
				pagesPtrStable = GCHandle.Alloc(page_list, GCHandleType.Pinned);
				mExtractPages(infile, outfile, password, has_password, linearize,
					num_pages, pagesPtrStable.AddrOfPinnedObject());
				pagesPtrStable.Free();
			}
			else
			{
				mExtractPages(infile, outfile, password, has_password, linearize,
							num_pages, IntPtr.Zero);
			}
		}

		public gsStatus ConvertSave(gsDevice_t device, String outputFile, int num_pages, 
			System.Collections.IList pages, int resolution)
		{
			ConvertParams_t convertparams = new ConvertParams_t();

			convertparams.device = device;
			convertparams.outputfile = outputFile;
			convertparams.num_pages = num_pages;
			convertparams.resolution = resolution;
			convertparams.pages = pages;
			convertparams.currpage = 1;
			return ConvertMuPDF(convertparams);
		}

		/* Render page by page in background with progress call back */
		private gsStatus ConvertMuPDF(ConvertParams_t Params)
		{
			try
			{
				if (m_worker != null && m_worker.IsBusy)
				{
					m_worker.CancelAsync();
					return gsStatus.GS_BUSY;
				}
				if (m_worker == null)
				{
					m_worker = new BackgroundWorker();
					m_worker.WorkerReportsProgress = true;
					m_worker.WorkerSupportsCancellation = true;
					m_worker.RunWorkerCompleted += new RunWorkerCompletedEventHandler(MuPDFCompleted);
					m_worker.ProgressChanged += new ProgressChangedEventHandler(MuPDFProgressChanged);
					m_worker.DoWork += new DoWorkEventHandler(MuPDFWork);
				}

				m_params = Params;
				m_worker.RunWorkerAsync(Params);
				return gsStatus.GS_READY;
			}
			catch (OutOfMemoryException e)
			{
				Console.WriteLine("Memory allocation failed during mupdf rendering\n");
				return gsStatus.GS_ERROR;
			}
		}

		private void MuPDFCompleted(object sender, RunWorkerCompletedEventArgs e)
		{
			ConvertParams_t Value;
			muPDFEventArgs info;

			if (e.Cancelled)
			{
				Value = new ConvertParams_t();
				Value.result = GS_Result_t.gsCANCELLED;
				info = new muPDFEventArgs(true, 100, Value);
			}
			else
			{
				Value = (ConvertParams_t)e.Result;
				info = new muPDFEventArgs(true, 100, Value);
			}
			mupdfUpdateMain(this, info);
		}

		private void MuPDFProgressChanged(object sender, ProgressChangedEventArgs e)
		{
			/* Callback with progress */
			ConvertParams_t Value = new ConvertParams_t();
			muPDFEventArgs info = new muPDFEventArgs(false, e.ProgressPercentage, Value);
			mupdfUpdateMain(this, info);
		}

		public void Cancel()
		{
			m_worker.CancelAsync();
		}

		/* ToDo:  do we report pages that failed? or just push on */
		private void MuPDFWork(object sender, DoWorkEventArgs e)
		{
			ConvertParams_t muparams = (ConvertParams_t)e.Argument;
			String out_file = muparams.outputfile;
			int num_pages = muparams.num_pages;
			int resolution = muparams.resolution;
			var pages = muparams.pages;
			BackgroundWorker worker = sender as BackgroundWorker;

			muparams.result = GS_Result_t.gsOK;

			int result;

			for (int kk = 0; kk < num_pages; kk++)
			{
				SelectPage curr_page = (SelectPage)pages[kk];
				int page_num = curr_page.Page;
				bool append = (kk != 0);

				/* Look for file extension. */
				string extension = System.IO.Path.GetExtension(out_file);
				int len = extension.Length;
				String new_out_file = out_file.Substring(0, out_file.Length - len);
				String out_file_name = new_out_file + "_" + page_num + extension;

				/* Question:  is lock valid when done from this worker thread? */
				switch (muparams.device)
				{
					case gsDevice_t.svg:
						lock (this.m_lock)  /* Single-page format */
							result = mSavePage(mu_object, out_file_name,
								page_num - 1, resolution, (int) mudevice_t.SVG_OUT,
								false);
						break;
					case gsDevice_t.pnm:
						lock (this.m_lock) /* Single-page format */
							result = mSavePage(mu_object, out_file_name,
								page_num - 1, resolution, (int)mudevice_t.PNM_OUT,
								false);
						break;
					case gsDevice_t.pclbitmap:  /* Multi-page format */
						lock (this.m_lock)
							result = mSavePage(mu_object, out_file,
								page_num - 1, resolution, (int)mudevice_t.PCL_OUT,
								append);
						break;
					case gsDevice_t.pwg:  /* Multi-page format */
						lock (this.m_lock)
							result = mSavePage(mu_object, out_file,
								page_num - 1, resolution, (int)mudevice_t.PWG_OUT,
								append);
						break;
				}
				double prog = (double) (kk+1.0)/((double) num_pages) * 100.0;
				worker.ReportProgress((int)prog);

				if (worker.CancellationPending == true)
				{
					e.Cancel = true;
					muparams.result = GS_Result_t.gsCANCELLED;
					break;
				}
			}
			e.Result = muparams;
			return;
		}
	}
}
