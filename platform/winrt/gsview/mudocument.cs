using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Threading;
using System.Runtime.InteropServices;
using System.Security;
using System.Windows;

/* This file contains the interface between the muctx cpp class, which
	implements the mupdf calls and the .net managed code  */

namespace gsview
{

	public struct content_s
	{
		public int page;
		public IntPtr string_margin;
	}

	[SuppressUnmanagedCodeSecurity]
	class mudocument
	{
		IntPtr mu_object;
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
	}
}
