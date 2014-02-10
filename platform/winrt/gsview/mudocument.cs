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
		List<Links> links;
		List<Links> textsearch;
		public List<ContentItem> contents;

		/* The list of functions that we use to call into C interface of muctx.
		 * Calling into C++ code from managed code is complex. Since CLR 
		 * compiling is needed and that does not support mutex. Hence the C
		 * interface */
		[DllImport("munet.dll", CharSet = CharSet.Auto,
			CallingConvention = CallingConvention.StdCall)]
		public static extern IntPtr mInitialize();

		[DllImport("munet.dll", CharSet = CharSet.Auto,
			CallingConvention = CallingConvention.StdCall)]
		public static extern status_t mOpenDocument(IntPtr ctx, string filename);

		[DllImport("munet.dll", CharSet = CharSet.Auto,
			CallingConvention = CallingConvention.StdCall)]
		public static extern void mCleanUp(IntPtr ctx);

		[DllImport("munet.dll", CharSet = CharSet.Auto,
			CallingConvention = CallingConvention.StdCall)]
		public static extern int mGetPageCount(IntPtr ctx);

		[DllImport("munet.dll", CharSet = CharSet.Auto,
			CallingConvention = CallingConvention.StdCall)]
		public static extern bool mRequiresPassword(IntPtr ctx);

		[DllImport("munet.dll", CharSet = CharSet.Auto,
			CallingConvention = CallingConvention.StdCall)]
		public static extern bool mApplyPassword(IntPtr ctx, string password);

		[DllImport("munet.dll", CharSet = CharSet.Auto,
			CallingConvention = CallingConvention.StdCall)]
		public static extern int mRenderPage(IntPtr ctx,
			int page_num, Byte[] bmp_data, int bmp_width, 
			int bmp_height, double scale, bool flipy);

		[DllImport("munet.dll", CharSet = CharSet.Auto,
			CallingConvention = CallingConvention.StdCall)]
		public static extern int mMeasurePage(IntPtr ctx, int page_num,
			ref double width, ref double height);

		[DllImport("munet.dll", CharSet = CharSet.Auto,
			CallingConvention = CallingConvention.StdCall)]
		public static extern int mGetContents(IntPtr ctx);

		[DllImport("munet.dll", CharSet = CharSet.Auto,
			CallingConvention = CallingConvention.StdCall)]
		public static extern void mReleaseContents();

		/* The managed code Marshal actually releases the allocated string from C */
		[DllImport("munet.dll", CharSet = CharSet.Ansi,
			CallingConvention = CallingConvention.StdCall)]
		[return: MarshalAs(UnmanagedType.LPStr)]
		public static extern string mGetContentsItem(int k, ref int len, ref int page);

		[DllImport("munet.dll", CharSet = CharSet.Auto,
			CallingConvention = CallingConvention.StdCall)]
		public static extern IntPtr mCreateDisplayList(IntPtr ctx, int page_num,
				ref int page_width, ref int page_height);

		[DllImport("munet.dll", CharSet = CharSet.Auto,
			CallingConvention = CallingConvention.StdCall)]
		public static extern int mRenderPageMT(IntPtr ctx, IntPtr dlist,
			int page_width, int page_height, Byte[] bmp_data, int bmp_width, 
			int bmp_height, double scale, bool flipy);

/*
		[DllImport("mugs.dll", CharSet = CharSet.Auto,
	CallingConvention = CallingConvention.StdCall)]
		public static extern void GetLinks(IntPtr ctx);

		[DllImport("mugs.dll", CharSet = CharSet.Auto,
	CallingConvention = CallingConvention.StdCall)]
		public static extern void GetTextSearch(IntPtr ctx);

				[DllImport("mugs.dll", CharSet = CharSet.Auto,
	CallingConvention = CallingConvention.StdCall)]
		public static extern void GetHTML(IntPtr ctx);

	~muctx(void);

	unsigned int GetLinks(int page_num, sh_vector_link links_vec);
	int GetTextSearch(int page_num, char* needle, sh_vector_text texts_vec);
	std::string GetHTML(int page_num);
*/

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
				mCleanUp(mu_object);
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
			int bmp_height, double scale, bool flipy, bool use_dlist)
		{
			int code;

			if (use_dlist) 
			{
				IntPtr dlist;
				int page_height = 0;
				int page_width = 0;

				lock(m_lock)
				{
					dlist = mCreateDisplayList(mu_object, page_num, ref page_width, ref page_height);
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
	}
}
