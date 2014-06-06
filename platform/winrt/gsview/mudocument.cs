using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
//using System.Threading.Tasks;
using System.Threading;
using System.Runtime.InteropServices;
using System.Security;
using System.Windows;
using System.ComponentModel;
using System.Windows.Forms;

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
		public bool is64bit;
		IntPtr mu_object;
		BackgroundWorker m_worker;
		ConvertParams_t m_params;
		/* Callbacks to Main */
		internal delegate void mupdfDLLProblem(object muObject, String mess);
		internal event mupdfDLLProblem mupdfDLLProblemMain;
		internal delegate void mupdfCallBackMain(object muObject, muPDFEventArgs info);
		internal event mupdfCallBackMain mupdfUpdateMain;

		private System.Object m_lock = new System.Object();  
		public List<ContentItem> contents;

		#region DLLInterface
		/* The list of functions that we use to call into C interface of muctx.
		 * Calling into C++ code from managed code is complex. Since CLR 
		 * compiling is needed and that does not support mutex. Hence the C
		 * interface */
		[DllImport("mupdfnet64.dll", EntryPoint = "mInitialize", CharSet = CharSet.Auto,
			CallingConvention = CallingConvention.StdCall)]
		private static extern IntPtr mInitialize64();

		[DllImport("mupdfnet64.dll", EntryPoint = "mOpenDocument", CharSet = CharSet.Auto,
			CallingConvention = CallingConvention.StdCall)]
		private static extern status_t mOpenDocument64(IntPtr ctx, string filename);

		[DllImport("mupdfnet64.dll", EntryPoint = "mCleanUp", CharSet = CharSet.Auto,
			CallingConvention = CallingConvention.StdCall)]
		private static extern void mCleanUp64(IntPtr ctx);

		[DllImport("mupdfnet64.dll", EntryPoint = "mGetPageCount", CharSet = CharSet.Auto,
			CallingConvention = CallingConvention.StdCall)]
		private static extern int mGetPageCount64(IntPtr ctx);

		[DllImport("mupdfnet64.dll", EntryPoint = "mRequiresPassword", CharSet = CharSet.Auto,
			CallingConvention = CallingConvention.StdCall)]
		private static extern bool mRequiresPassword64(IntPtr ctx);

		[DllImport("mupdfnet64.dll", EntryPoint = "mApplyPassword", CharSet = CharSet.Auto,
			CallingConvention = CallingConvention.StdCall)]
		private static extern bool mApplyPassword64(IntPtr ctx, string password);

		[DllImport("mupdfnet64.dll", EntryPoint = "mRenderPage", CharSet = CharSet.Auto,
			CallingConvention = CallingConvention.StdCall)]
		private static extern int mRenderPage64(IntPtr ctx, int page_num, 
			Byte[] bmp_data, int bmp_width, int bmp_height, double scale, 
			bool flipy);

		[DllImport("mupdfnet64.dll", EntryPoint = "mMeasurePage", CharSet = CharSet.Auto,
			CallingConvention = CallingConvention.StdCall)]
		private static extern int mMeasurePage64(IntPtr ctx, int page_num,
			ref double width, ref double height);

		[DllImport("mupdfnet64.dll", EntryPoint = "mGetContents", CharSet = CharSet.Auto,
			CallingConvention = CallingConvention.StdCall)]
		private static extern int mGetContents64(IntPtr ctx);

		[DllImport("mupdfnet64.dll", EntryPoint = "mReleaseContents", CharSet = CharSet.Auto,
			CallingConvention = CallingConvention.StdCall)]
		private static extern void mReleaseContents64();

		[DllImport("mupdfnet64.dll", EntryPoint = "mSetAA", CharSet = CharSet.Auto,
			CallingConvention = CallingConvention.StdCall)]
		private static extern void mSetAA64(IntPtr ctx, int level);

		/* The managed code Marshal actually releases the allocated string from C */
		[DllImport("mupdfnet64.dll", EntryPoint = "mGetContentsItem", CharSet = CharSet.Ansi,
			CallingConvention = CallingConvention.StdCall)]
		[return: MarshalAs(UnmanagedType.LPStr)]
		private static extern string mGetContentsItem64(int k, ref int len, ref int page);

		[DllImport("mupdfnet64.dll", EntryPoint = "mCreateDisplayList", CharSet = CharSet.Auto,
			CallingConvention = CallingConvention.StdCall)]
		private static extern IntPtr mCreateDisplayList64(IntPtr ctx, int page_num,
				ref int page_width, ref int page_height);

		[DllImport("mupdfnet64.dll", EntryPoint = "mCreateDisplayListAnnot", 
			CharSet = CharSet.Auto, CallingConvention = CallingConvention.StdCall)]
		private static extern IntPtr mCreateDisplayListAnnot64(IntPtr ctx, int page_num);

		[DllImport("mupdfnet64.dll", EntryPoint = "mCreateDisplayListText", CharSet = CharSet.Auto,
			CallingConvention = CallingConvention.StdCall)]
		private static extern IntPtr mCreateDisplayListText64(IntPtr ctx, int page_num,
				ref int page_width, ref int page_height, ref IntPtr text, ref int length);

		[DllImport("mupdfnet64.dll", EntryPoint = "mRenderPageMT", CharSet = CharSet.Auto,
			CallingConvention = CallingConvention.StdCall)]
		private static extern int mRenderPageMT64(IntPtr ctx, IntPtr dlist,
			IntPtr annot_dlist, int page_width, int page_height, Byte[] bmp_data, 
			int bmp_width, int bmp_height, double scale, bool flipy);

		[DllImport("mupdfnet64.dll", EntryPoint = "mTextSearchPage", CharSet = CharSet.Auto,
			CallingConvention = CallingConvention.StdCall)]
		private static extern int mTextSearchPage64(IntPtr ctx, int page_num,
			string needle);

		[DllImport("mupdfnet64.dll", EntryPoint = "mGetTextSearchItem", CharSet = CharSet.Auto,
			CallingConvention = CallingConvention.StdCall)]
		private static extern bool mGetTextSearchItem64(int item_num, ref double top_x,
			ref double top_y, ref double height, ref double width);

		[DllImport("mupdfnet64.dll", EntryPoint = "mReleaseTextSearch", CharSet = CharSet.Auto,
			CallingConvention = CallingConvention.StdCall)]
		private static extern void mReleaseTextSearch64();

		[DllImport("mupdfnet64.dll", EntryPoint = "mGetLinksPage", CharSet = CharSet.Auto,
			CallingConvention = CallingConvention.StdCall)]
		private static extern int mGetLinksPage64(IntPtr ctx, int page_num);

		/* The managed code Marshal actually releases the allocated string from C */
		[DllImport("mupdfnet64.dll", EntryPoint = "mGetLinkItem", CharSet = CharSet.Ansi,
			CallingConvention = CallingConvention.StdCall)]
		[return: MarshalAs(UnmanagedType.LPStr)]
		private static extern string mGetLinkItem64(int item_num, ref double top_x,
			ref double top_y, ref double height, ref double width, ref int topage, 
			ref int type);

		[DllImport("mupdfnet64.dll", EntryPoint = "mReleaseLink", CharSet = CharSet.Auto,
			CallingConvention = CallingConvention.StdCall)]
		private static extern void mReleaseLink64();

		[DllImport("mupdfnet64.dll", EntryPoint = "mReleaseText", CharSet = CharSet.Auto,
			CallingConvention = CallingConvention.StdCall)]
		private static extern void mReleaseText64(IntPtr ctx, IntPtr textpage);

		[DllImport("mupdfnet64.dll", EntryPoint = "mGetTextBlock", CharSet = CharSet.Auto,
			CallingConvention = CallingConvention.StdCall)]
		private static extern int mGetTextBlock64(IntPtr textpage, int block_num,
			ref double top_x,ref double top_y, ref double height, ref double width);

		[DllImport("mupdfnet64.dll", EntryPoint = "mGetTextLine", CharSet = CharSet.Auto,
			CallingConvention = CallingConvention.StdCall)]
		private static extern int mGetTextLine64(IntPtr textpage, int block_num, 
			int line_num, ref double top_x, ref double top_y, ref double height, 
			ref double width);

		[DllImport("mupdfnet64.dll", EntryPoint = "mGetTextCharacter", CharSet = CharSet.Auto,
			CallingConvention = CallingConvention.StdCall)]
		private static extern int mGetTextCharacter64(IntPtr textpage, int block_num, 
			int line_num, int item_num, ref double top_x,
			ref double top_y, ref double height, ref double width);

		[DllImport("mupdfnet64.dll", EntryPoint = "mExtractPages", CharSet = CharSet.Auto,
			CallingConvention = CallingConvention.StdCall)]
		private static extern int mExtractPages64(String infile, String outfile, 
			String password, bool has_password, bool linearize, int num_pages, 
			IntPtr pages);

		[DllImport("mupdfnet64.dll", EntryPoint = "mSavePage", CharSet = CharSet.Auto,
			CallingConvention = CallingConvention.StdCall)]
		private static extern int mSavePage64(IntPtr ctx, String outfile, 
			int page_num, int res, int type, bool append);

		/* The managed code Marshal actually releases the allocated string from C */
		[DllImport("mupdfnet64.dll", EntryPoint = "mGetVers", CharSet = CharSet.Ansi,
			CallingConvention = CallingConvention.StdCall)]
		[return: MarshalAs(UnmanagedType.LPStr)]
		private static extern string mGetVers64();

		/* The managed code Marshal actually releases the allocated string from C */
		[DllImport("mupdfnet64.dll", EntryPoint = "mGetText", CharSet = CharSet.Ansi,
			CallingConvention = CallingConvention.StdCall)]
		[return: MarshalAs(UnmanagedType.LPStr)]
		private static extern string mGetText64(IntPtr ctx, int pagenum, int type);

		/* And the 32bit version */
		[DllImport("mupdfnet32.dll", EntryPoint = "mInitialize", CharSet = CharSet.Auto,
			CallingConvention = CallingConvention.StdCall)]
		private static extern IntPtr mInitialize32();

		[DllImport("mupdfnet32.dll", EntryPoint = "mOpenDocument", CharSet = CharSet.Auto,
			CallingConvention = CallingConvention.StdCall)]
		private static extern status_t mOpenDocument32(IntPtr ctx, string filename);

		[DllImport("mupdfnet32.dll", EntryPoint = "mCleanUp", CharSet = CharSet.Auto,
			CallingConvention = CallingConvention.StdCall)]
		private static extern void mCleanUp32(IntPtr ctx);

		[DllImport("mupdfnet32.dll", EntryPoint = "mGetPageCount", CharSet = CharSet.Auto,
			CallingConvention = CallingConvention.StdCall)]
		private static extern int mGetPageCount32(IntPtr ctx);

		[DllImport("mupdfnet32.dll", EntryPoint = "mRequiresPassword", CharSet = CharSet.Auto,
			CallingConvention = CallingConvention.StdCall)]
		private static extern bool mRequiresPassword32(IntPtr ctx);

		[DllImport("mupdfnet32.dll", EntryPoint = "mApplyPassword", CharSet = CharSet.Auto,
			CallingConvention = CallingConvention.StdCall)]
		private static extern bool mApplyPassword32(IntPtr ctx, string password);

		[DllImport("mupdfnet32.dll", EntryPoint = "mRenderPage", CharSet = CharSet.Auto,
			CallingConvention = CallingConvention.StdCall)]
		private static extern int mRenderPage32(IntPtr ctx, int page_num,
			Byte[] bmp_data, int bmp_width, int bmp_height, double scale,
			bool flipy);

		[DllImport("mupdfnet32.dll", EntryPoint = "mMeasurePage", CharSet = CharSet.Auto,
			CallingConvention = CallingConvention.StdCall)]
		private static extern int mMeasurePage32(IntPtr ctx, int page_num,
			ref double width, ref double height);

		[DllImport("mupdfnet32.dll", EntryPoint = "mGetContents", CharSet = CharSet.Auto,
			CallingConvention = CallingConvention.StdCall)]
		private static extern int mGetContents32(IntPtr ctx);

		[DllImport("mupdfnet32.dll", EntryPoint = "mReleaseContents", CharSet = CharSet.Auto,
			CallingConvention = CallingConvention.StdCall)]
		private static extern void mReleaseContents32();

		[DllImport("mupdfnet32.dll", EntryPoint = "mSetAA", CharSet = CharSet.Auto,
		CallingConvention = CallingConvention.StdCall)]
		private static extern void mSetAA32(IntPtr ctx, int level);

		/* The managed code Marshal actually releases the allocated string from C */
		[DllImport("mupdfnet32.dll", EntryPoint = "mGetContentsItem", CharSet = CharSet.Ansi,
			CallingConvention = CallingConvention.StdCall)]
		[return: MarshalAs(UnmanagedType.LPStr)]
		private static extern string mGetContentsItem32(int k, ref int len, ref int page);

		[DllImport("mupdfnet32.dll", EntryPoint = "mCreateDisplayList", CharSet = CharSet.Auto,
			CallingConvention = CallingConvention.StdCall)]
		private static extern IntPtr mCreateDisplayList32(IntPtr ctx, int page_num,
				ref int page_width, ref int page_height);

		[DllImport("mupdfnet32.dll", EntryPoint = "mCreateDisplayListAnnot",
			CharSet = CharSet.Auto, CallingConvention = CallingConvention.StdCall)]
		private static extern IntPtr mCreateDisplayListAnnot32(IntPtr ctx, int page_num);


		[DllImport("mupdfnet32.dll", EntryPoint = "mCreateDisplayListText", CharSet = CharSet.Auto,
			CallingConvention = CallingConvention.StdCall)]
		private static extern IntPtr mCreateDisplayListText32(IntPtr ctx, int page_num,
				ref int page_width, ref int page_height, ref IntPtr text, ref int length);

		[DllImport("mupdfnet32.dll", EntryPoint = "mRenderPageMT", CharSet = CharSet.Auto,
			CallingConvention = CallingConvention.StdCall)]
		private static extern int mRenderPageMT32(IntPtr ctx, IntPtr dlist,
			IntPtr annot_dlist, int page_width, int page_height, Byte[] bmp_data, 
			int bmp_width, int bmp_height, double scale, bool flipy);

		[DllImport("mupdfnet32.dll", EntryPoint = "mTextSearchPage", CharSet = CharSet.Auto,
			CallingConvention = CallingConvention.StdCall)]
		private static extern int mTextSearchPage32(IntPtr ctx, int page_num,
			string needle);

		[DllImport("mupdfnet32.dll", EntryPoint = "mGetTextSearchItem", CharSet = CharSet.Auto,
			CallingConvention = CallingConvention.StdCall)]
		private static extern bool mGetTextSearchItem32(int item_num, ref double top_x,
			ref double top_y, ref double height, ref double width);

		[DllImport("mupdfnet32.dll", EntryPoint = "mReleaseTextSearch", CharSet = CharSet.Auto,
			CallingConvention = CallingConvention.StdCall)]
		private static extern void mReleaseTextSearch32();

		[DllImport("mupdfnet32.dll", EntryPoint = "mGetLinksPage", CharSet = CharSet.Auto,
			CallingConvention = CallingConvention.StdCall)]
		private static extern int mGetLinksPage32(IntPtr ctx, int page_num);

		/* The managed code Marshal actually releases the allocated string from C */
		[DllImport("mupdfnet32.dll", EntryPoint = "mGetLinkItem", CharSet = CharSet.Ansi,
			CallingConvention = CallingConvention.StdCall)]
		[return: MarshalAs(UnmanagedType.LPStr)]
		private static extern string mGetLinkItem32(int item_num, ref double top_x,
			ref double top_y, ref double height, ref double width, ref int topage,
			ref int type);

		[DllImport("mupdfnet32.dll", EntryPoint = "mReleaseLink", CharSet = CharSet.Auto,
			CallingConvention = CallingConvention.StdCall)]
		private static extern void mReleaseLink32();

		[DllImport("mupdfnet32.dll", EntryPoint = "mReleaseText", CharSet = CharSet.Auto,
			CallingConvention = CallingConvention.StdCall)]
		private static extern void mReleaseText32(IntPtr ctx, IntPtr textpage);

		[DllImport("mupdfnet32.dll", EntryPoint = "mGetTextBlock", CharSet = CharSet.Auto,
			CallingConvention = CallingConvention.StdCall)]
		private static extern int mGetTextBlock32(IntPtr textpage, int block_num,
			ref double top_x, ref double top_y, ref double height, ref double width);

		[DllImport("mupdfnet32.dll", EntryPoint = "mGetTextLine", CharSet = CharSet.Auto,
			CallingConvention = CallingConvention.StdCall)]
		private static extern int mGetTextLine32(IntPtr textpage, int block_num,
			int line_num, ref double top_x, ref double top_y, ref double height,
			ref double width);

		[DllImport("mupdfnet32.dll", EntryPoint = "mGetTextCharacter", CharSet = CharSet.Auto,
			CallingConvention = CallingConvention.StdCall)]
		private static extern int mGetTextCharacter32(IntPtr textpage, int block_num,
			int line_num, int item_num, ref double top_x,
			ref double top_y, ref double height, ref double width);

		[DllImport("mupdfnet32.dll", EntryPoint = "mExtractPages", CharSet = CharSet.Auto,
			CallingConvention = CallingConvention.StdCall)]
		private static extern int mExtractPages32(String infile, String outfile,
			String password, bool has_password, bool linearize, int num_pages,
			IntPtr pages);

		[DllImport("mupdfnet32.dll", EntryPoint = "mSavePage", CharSet = CharSet.Auto,
			CallingConvention = CallingConvention.StdCall)]
		private static extern int mSavePage32(IntPtr ctx, String outfile,
			int page_num, int res, int type, bool append);

		/* The managed code Marshal actually releases the allocated string from C */
		[DllImport("mupdfnet32.dll", EntryPoint = "mGetVers", CharSet = CharSet.Ansi,
			CallingConvention = CallingConvention.StdCall)]
		[return: MarshalAs(UnmanagedType.LPStr)]
		private static extern string mGetVers32();

		/* The managed code Marshal actually releases the allocated string from C */
		[DllImport("mupdfnet32.dll", EntryPoint = "mGetText", CharSet = CharSet.Ansi,
			CallingConvention = CallingConvention.StdCall)]
		[return: MarshalAs(UnmanagedType.LPStr)]
		private static extern string mGetText32(IntPtr ctx, int pagenum, int type);

		#endregion DLLInterface

		#region DLLErrorTrap
		/* And make sure we can catch any issues in finding the DLL or if we have
		 * a 32bit 64bit issue */
		private IntPtr tc_mInitialize()
		{
			IntPtr output;
			try
			{
				if (is64bit)
					output = mInitialize64();
				else
					output = mInitialize32();
			}
			catch (DllNotFoundException)
			{
				/* DLL not found */
				String err = "DllNotFoundException: MuPDF DLL not found 1";
				mupdfDLLProblemMain(this, err);
				return IntPtr.Zero;
			}
			catch (BadImageFormatException)
			{
				/* Using 32 bit with 64 or vice versa */
				String err = "BadImageFormatException: Incorrect MuPDF DLL";
				mupdfDLLProblemMain(this, err);
				return IntPtr.Zero;
			}
			return output;
		}

		private status_t tc_mOpenDocument(IntPtr ctx, string filename)
		{
			status_t output;
			try
			{
				if (is64bit)
					output = mOpenDocument64(ctx, filename);
				else
					output = mOpenDocument32(ctx, filename);
			}
			catch (DllNotFoundException)
			{
				/* DLL not found */
				String err = "DllNotFoundException: MuPDF DLL not found 2";
				mupdfDLLProblemMain(this, err);
				return status_t.E_FAILURE;
			}
			catch (BadImageFormatException)
			{
				/* Using 32 bit with 64 or vice versa */
				String err = "BadImageFormatException: Incorrect MuPDF DLL";
				mupdfDLLProblemMain(this, err);
				return status_t.E_FAILURE;
			}
			return output;
		}

		private int tc_mCleanUp(IntPtr ctx)
		{
			try
			{
				if (is64bit)
					mCleanUp64(ctx);
				else
					mCleanUp32(ctx);
			}
			catch (DllNotFoundException)
			{
				/* DLL not found */
				String err = "DllNotFoundException: MuPDF DLL not found 3";
				mupdfDLLProblemMain(this, err);
				return -1;
			}
			catch (BadImageFormatException)
			{
				/* Using 32 bit with 64 or vice versa */
				String err = "BadImageFormatException: Incorrect MuPDF DLL";
				mupdfDLLProblemMain(this, err);
				return -1;
			}
			return 0;
		}

		private int tc_mGetPageCount(IntPtr ctx)
		{
			int output;
			try
			{
				if (is64bit)
					output = mGetPageCount64(ctx);
				else
					output = mGetPageCount32(ctx);
			}
			catch (DllNotFoundException)
			{
				/* DLL not found */
				String err = "DllNotFoundException: MuPDF DLL not found 4";
				mupdfDLLProblemMain(this, err);
				return -1;
			}
			catch (BadImageFormatException)
			{
				/* Using 32 bit with 64 or vice versa */
				String err = "BadImageFormatException: Incorrect MuPDF DLL";
				mupdfDLLProblemMain(this, err);
				return -1;
			}
			return output;
		}

		private bool tc_mRequiresPassword(IntPtr ctx)
		{
			bool output;
			try
			{
				if (is64bit)
					output = mRequiresPassword64(ctx);
				else
					output = mRequiresPassword32(ctx);
			}
			catch (DllNotFoundException)
			{
				/* DLL not found */
				String err = "DllNotFoundException: MuPDF DLL not found 5";
				mupdfDLLProblemMain(this, err);
				return false;
			}
			catch (BadImageFormatException)
			{
				/* Using 32 bit with 64 or vice versa */
				String err = "BadImageFormatException: Incorrect MuPDF DLL";
				mupdfDLLProblemMain(this, err);
				return false;
			}
			return output;
		}
		
		private bool tc_mApplyPassword(IntPtr ctx, string password)
		{
			bool output;
			try
			{
				if (is64bit)
					output = mApplyPassword64(ctx, password);
				else
					output = mApplyPassword32(ctx, password);
			}
			catch (DllNotFoundException)
			{
				/* DLL not found */
				String err = "DllNotFoundException: MuPDF DLL not found 6";
				mupdfDLLProblemMain(this, err);
				return false;
			}
			catch (BadImageFormatException)
			{
				/* Using 32 bit with 64 or vice versa */
				String err = "BadImageFormatException: Incorrect MuPDF DLL";
				mupdfDLLProblemMain(this, err);
				return false;
			}
			return output;
		}

		private int tc_mRenderPage(IntPtr ctx, int page_num, Byte[] bmp_data, 
			int bmp_width, int bmp_height, double scale, bool flipy)
		{
			int output;
			try
			{
				if (is64bit)
					output = mRenderPage64(ctx, page_num, bmp_data, bmp_width,
						bmp_height, scale, flipy);
				else
					output = mRenderPage32(ctx, page_num, bmp_data, bmp_width,
						bmp_height, scale, flipy);
			}
			catch (DllNotFoundException)
			{
				/* DLL not found */
				String err = "DllNotFoundException: MuPDF DLL not found 7";
				mupdfDLLProblemMain(this, err);
				return -1;
			}
			catch (BadImageFormatException)
			{
				/* Using 32 bit with 64 or vice versa */
				String err = "BadImageFormatException: Incorrect MuPDF DLL";
				mupdfDLLProblemMain(this, err);
				return -1;
			}
			return output;
		}

		private int tc_mMeasurePage(IntPtr ctx, int page_num, ref double width, 
			ref double height)
		{
			int output;
			try
			{
				if (is64bit)
					output = mMeasurePage64(ctx, page_num, ref width, ref height);
				else
					output = mMeasurePage32(ctx, page_num, ref width, ref height);
			}
			catch (DllNotFoundException)
			{
				/* DLL not found */
				String err = "DllNotFoundException: MuPDF DLL not found 8";
				mupdfDLLProblemMain(this, err);
				return -1;
			}
			catch (BadImageFormatException)
			{
				/* Using 32 bit with 64 or vice versa */
				String err = "BadImageFormatException: Incorrect MuPDF DLL";
				mupdfDLLProblemMain(this, err);
				return -1;
			}
			return output;
		}
		
		private int tc_mGetContents(IntPtr ctx)
		{
			int output;
			try
			{
				if (is64bit)
					output = mGetContents64(ctx);
				else
					output = mGetContents32(ctx);
			}
			catch (DllNotFoundException)
			{
				/* DLL not found */
				String err = "DllNotFoundException: MuPDF DLL not found 9";
				mupdfDLLProblemMain(this, err);
				return -1;
			}
			catch (BadImageFormatException)
			{
				/* Using 32 bit with 64 or vice versa */
				String err = "BadImageFormatException: Incorrect MuPDF DLL";
				mupdfDLLProblemMain(this, err);
				return -1;
			}
			return output;
		}

		private int tc_mReleaseContents()
		{
			try
			{
				if (is64bit)
					mReleaseContents64();
				else
					mReleaseContents32();
			}
			catch (DllNotFoundException)
			{
				/* DLL not found */
				String err = "DllNotFoundException: MuPDF DLL not found 10";
				mupdfDLLProblemMain(this, err);
				return -1;
			}
			catch (BadImageFormatException)
			{
				/* Using 32 bit with 64 or vice versa */
				String err = "BadImageFormatException: Incorrect MuPDF DLL";
				mupdfDLLProblemMain(this, err);
				return -1;
			}
			return 0;
		}

		private string tc_mGetContentsItem(int k, ref int len, ref int page)
		{
			String output;
			try
			{
				if (is64bit)
					output = mGetContentsItem64(k, ref len, ref page);
				else
					output = mGetContentsItem32(k, ref len, ref page);
			}
			catch (DllNotFoundException)
			{
				/* DLL not found */
				String err = "DllNotFoundException: MuPDF DLL not found 11";
				mupdfDLLProblemMain(this, err);
				return null;
			}
			catch (BadImageFormatException)
			{
				/* Using 32 bit with 64 or vice versa */
				String err = "BadImageFormatException: Incorrect MuPDF DLL";
				mupdfDLLProblemMain(this, err);
				return null;
			}
			return output;
		}

		private IntPtr tc_mCreateDisplayListAnnot(IntPtr ctx, int page_num)
		{
			IntPtr output;
			try
			{
				if (is64bit)
					output = mCreateDisplayListAnnot64(ctx, page_num);
				else
					output = mCreateDisplayListAnnot32(ctx, page_num);
			}
			catch (DllNotFoundException)
			{
				/* DLL not found */
				String err = "DllNotFoundException: MuPDF DLL not found 12";
				mupdfDLLProblemMain(this, err);
				return IntPtr.Zero;
			}
			catch (BadImageFormatException)
			{
				/* Using 32 bit with 64 or vice versa */
				String err = "BadImageFormatException: Incorrect MuPDF DLL";
				mupdfDLLProblemMain(this, err);
				return IntPtr.Zero;
			}
			return output;
		}

		private IntPtr tc_mCreateDisplayList(IntPtr ctx, int page_num, 
			ref int page_width, ref int page_height)
		{
			IntPtr output;
			try
			{
				if (is64bit)
					output = mCreateDisplayList64(ctx, page_num, ref page_width, 
						ref page_height);
				else
					output = mCreateDisplayList32(ctx, page_num, ref page_width,
						ref page_height);
			}
			catch (DllNotFoundException)
			{
				/* DLL not found */
				String err = "DllNotFoundException: MuPDF DLL not found 13";
				mupdfDLLProblemMain(this, err);
				return IntPtr.Zero;
			}
			catch (BadImageFormatException)
			{
				/* Using 32 bit with 64 or vice versa */
				String err = "BadImageFormatException: Incorrect MuPDF DLL";
				mupdfDLLProblemMain(this, err);
				return IntPtr.Zero;
			}
			return output;
		}

		private int tc_mSetAA(IntPtr ctx, int level)
		{
			try
			{
				if (is64bit)
					mSetAA64(ctx, level);
				else
					mSetAA32(ctx, level);
			}
			catch (DllNotFoundException)
			{
				/* DLL not found */
				String err = "DllNotFoundException: MuPDF DLL not found 14";
				mupdfDLLProblemMain(this, err);
				return -1;
			}
			catch (BadImageFormatException)
			{
				/* Using 32 bit with 64 or vice versa */
				String err = "BadImageFormatException: Incorrect MuPDF DLL";
				mupdfDLLProblemMain(this, err);
				return -1;
			}
			return 0;
		}

		private IntPtr tc_mCreateDisplayListText(IntPtr ctx, int page_num,
				ref int page_width, ref int page_height, ref IntPtr text, ref int length)
		{
			IntPtr output;
			try
			{
				if (is64bit)
					output = mCreateDisplayListText64(ctx, page_num, ref page_width, 
						ref page_height, ref text, ref length);
				else
					output = mCreateDisplayListText32(ctx, page_num, ref page_width,
						ref page_height, ref text, ref length);
			}
			catch (DllNotFoundException)
			{
				/* DLL not found */
				String err = "DllNotFoundException: MuPDF DLL not found 15";
				mupdfDLLProblemMain(this, err);
				return IntPtr.Zero;
			}
			catch (BadImageFormatException)
			{
				/* Using 32 bit with 64 or vice versa */
				String err = "BadImageFormatException: Incorrect MuPDF DLL";
				mupdfDLLProblemMain(this, err);
				return IntPtr.Zero;
			}
			return output;
		}

		private int tc_mRenderPageMT(IntPtr ctx, IntPtr dlist, IntPtr annot_dlist,
			int page_width, int page_height, Byte[] bmp_data, int bmp_width, 
			int bmp_height, double scale, bool flipy)
		{
			int output;
			try
			{
				if (is64bit)
					output = mRenderPageMT64(ctx, dlist, annot_dlist, page_width, 
						page_height, bmp_data, bmp_width, bmp_height, scale, flipy);
				else
					output = mRenderPageMT32(ctx, dlist, annot_dlist, page_width, 
						page_height, bmp_data, bmp_width, bmp_height, scale, flipy);
			}
			catch (DllNotFoundException)
			{
				/* DLL not found */
				String err = "DllNotFoundException: MuPDF DLL not found 16";
				mupdfDLLProblemMain(this, err);
				return -1;
			}
			catch (BadImageFormatException)
			{
				/* Using 32 bit with 64 or vice versa */
				String err = "BadImageFormatException: Incorrect MuPDF DLL";
				mupdfDLLProblemMain(this, err);
				return -1;
			}
			return output;
		}

		private int tc_mTextSearchPage(IntPtr ctx, int page_num, string needle)
		{
			int output;
			try
			{
				if (is64bit)
					output = mTextSearchPage64(ctx, page_num, needle);
				else
					output = mTextSearchPage32(ctx, page_num, needle);
			}
			catch (DllNotFoundException)
			{
				/* DLL not found */
				String err = "DllNotFoundException: MuPDF DLL not found 17";
				mupdfDLLProblemMain(this, err);
				return -1;
			}
			catch (BadImageFormatException)
			{
				/* Using 32 bit with 64 or vice versa */
				String err = "BadImageFormatException: Incorrect MuPDF DLL";
				mupdfDLLProblemMain(this, err);
				return -1;
			}
			return output;
		}

		private bool tc_mGetTextSearchItem(int item_num, ref double top_x,
			ref double top_y, ref double height, ref double width)
		{
			bool output;
			try
			{
				if (is64bit)
					output = mGetTextSearchItem64(item_num, ref top_x, ref top_y, 
						ref height, ref width);
				else
					output = mGetTextSearchItem32(item_num, ref top_x, ref top_y,
						ref height, ref width);
			}
			catch (DllNotFoundException)
			{
				/* DLL not found */
				String err = "DllNotFoundException: MuPDF DLL not found 18";
				mupdfDLLProblemMain(this, err);
				return false;
			}
			catch (BadImageFormatException)
			{
				/* Using 32 bit with 64 or vice versa */
				String err = "BadImageFormatException: Incorrect MuPDF DLL";
				mupdfDLLProblemMain(this, err);
				return false;
			}
			return output;
		}

		private int tc_mReleaseTextSearch()
		{
			try
			{
				if (is64bit)
					mReleaseTextSearch64();
				else
					mReleaseTextSearch32();
			}
			catch (DllNotFoundException)
			{
				/* DLL not found */
				String err = "DllNotFoundException: MuPDF DLL not found 18";
				mupdfDLLProblemMain(this, err);
				return -1;
			}
			catch (BadImageFormatException)
			{
				/* Using 32 bit with 64 or vice versa */
				String err = "BadImageFormatException: Incorrect MuPDF DLL";
				mupdfDLLProblemMain(this, err);
				return -1;
			}
			return 0;
		}

		private int tc_mGetLinksPage(IntPtr ctx, int page_num)
		{
			int output;
			try
			{
				if (is64bit)
					output = mGetLinksPage64(ctx, page_num);
				else
					output = mGetLinksPage32(ctx, page_num);
			}
			catch (DllNotFoundException)
			{
				/* DLL not found */
				String err = "DllNotFoundException: MuPDF DLL not found 19";
				mupdfDLLProblemMain(this, err);
				return -1;
			}
			catch (BadImageFormatException)
			{
				/* Using 32 bit with 64 or vice versa */
				String err = "BadImageFormatException: Incorrect MuPDF DLL";
				mupdfDLLProblemMain(this, err);
				return -1;
			}
			return output;
		}

		private string tc_mGetLinkItem(int item_num, ref double top_x,
			ref double top_y, ref double height, ref double width, ref int topage,
			ref int type)
		{
			String output;
			try
			{
				if (is64bit)
					output = mGetLinkItem64(item_num, ref top_x, ref top_y, ref height,
						ref width, ref topage, ref type);
				else
					output = mGetLinkItem32(item_num, ref top_x, ref top_y, ref height,
						ref width, ref topage, ref type);
			}
			catch (DllNotFoundException)
			{
				/* DLL not found */
				String err = "DllNotFoundException: MuPDF DLL not found 20";
				mupdfDLLProblemMain(this, err);
				return null;
			}
			catch (BadImageFormatException)
			{
				/* Using 32 bit with 64 or vice versa */
				String err = "BadImageFormatException: Incorrect MuPDF DLL";
				mupdfDLLProblemMain(this, err);
				return null;
			}
			return output;
		}

		private int tc_mReleaseLink()
		{
			try
			{
				if (is64bit)
					mReleaseLink64();
				else
					mReleaseLink32();
			}
			catch (DllNotFoundException)
			{
				/* DLL not found */
				String err = "DllNotFoundException: MuPDF DLL not found 21";
				mupdfDLLProblemMain(this, err);
				return -1;
			}
			catch (BadImageFormatException)
			{
				/* Using 32 bit with 64 or vice versa */
				String err = "BadImageFormatException: Incorrect MuPDF DLL";
				mupdfDLLProblemMain(this, err);
				return -1;
			}
			return 0;
		}

		private int tc_mReleaseText(IntPtr ctx, IntPtr textpage)
		{
			try
			{
				if (is64bit)
					mReleaseText64(ctx, textpage);
				else
					mReleaseText32(ctx, textpage);
			}
			catch (DllNotFoundException)
			{
				/* DLL not found */
				String err = "DllNotFoundException: MuPDF DLL not found 22";
				mupdfDLLProblemMain(this, err);
				return -1;
			}
			catch (BadImageFormatException)
			{
				/* Using 32 bit with 64 or vice versa */
				String err = "BadImageFormatException: Incorrect MuPDF DLL";
				mupdfDLLProblemMain(this, err);
				return -1;
			}
			return 0;
		}

		private int tc_mGetTextBlock(IntPtr textpage, int block_num,
			ref double top_x, ref double top_y, ref double height, ref double width)
		{
			int output;
			try
			{
				if (is64bit)
					output = mGetTextBlock64(textpage, block_num, ref top_x,
						ref top_y, ref height, ref width);
				else
					output = mGetTextBlock32(textpage, block_num, ref top_x,
						ref top_y, ref height, ref width);
			}
			catch (DllNotFoundException)
			{
				/* DLL not found */
				String err = "DllNotFoundException: MuPDF DLL not found 23";
				mupdfDLLProblemMain(this, err);
				return -1;
			}
			catch (BadImageFormatException)
			{
				/* Using 32 bit with 64 or vice versa */
				String err = "BadImageFormatException: Incorrect MuPDF DLL";
				mupdfDLLProblemMain(this, err);
				return -1;
			}
			return output;
		}

		private int tc_mGetTextLine(IntPtr textpage, int block_num,
			int line_num, ref double top_x, ref double top_y, ref double height,
			ref double width)
		{
			int output;
			try
			{
				if (is64bit)
					output = mGetTextLine64(textpage, block_num, line_num,
						ref top_x, ref top_y, ref height, ref width);
				else
					output = mGetTextLine32(textpage, block_num, line_num,
						ref top_x, ref top_y, ref height, ref width);
			}
			catch (DllNotFoundException)
			{
				/* DLL not found */
				String err = "DllNotFoundException: MuPDF DLL not found 24";
				mupdfDLLProblemMain(this, err);
				return -1;
			}
			catch (BadImageFormatException)
			{
				/* Using 32 bit with 64 or vice versa */
				String err = "BadImageFormatException: Incorrect MuPDF DLL";
				mupdfDLLProblemMain(this, err);
				return -1;
			}
			return output;
		}

		private int tc_mGetTextCharacter(IntPtr textpage, int block_num,
			int line_num, int item_num, ref double top_x,
			ref double top_y, ref double height, ref double width)
		{
			int output;
			try
			{
				if (is64bit)
					output = mGetTextCharacter64(textpage, block_num, line_num,
						item_num, ref top_x, ref top_y, ref height, ref width);
				else
					output = mGetTextCharacter32(textpage, block_num, line_num,
						item_num, ref top_x, ref top_y, ref height, ref width);
			}
			catch (DllNotFoundException)
			{
				/* DLL not found */
				String err = "DllNotFoundException: MuPDF DLL not found 25";
				mupdfDLLProblemMain(this, err);
				return -1;
			}
			catch (BadImageFormatException)
			{
				/* Using 32 bit with 64 or vice versa */
				String err = "BadImageFormatException: Incorrect MuPDF DLL";
				mupdfDLLProblemMain(this, err);
				return -1;
			}
			return output;
		}

		private int tc_mExtractPages(String infile, String outfile,
			String password, bool has_password, bool linearize, int num_pages,
			IntPtr pages)
		{
			int output;
			try
			{
				if (is64bit)
					output = mExtractPages64(infile, outfile, password, has_password,
						linearize, num_pages, pages);
				else
					output = mExtractPages32(infile, outfile, password, has_password,
						linearize, num_pages, pages);
			}
			catch (DllNotFoundException)
			{
				/* DLL not found */
				String err = "DllNotFoundException: MuPDF DLL not found 26";
				mupdfDLLProblemMain(this, err);
				return -1;
			}
			catch (BadImageFormatException)
			{
				/* Using 32 bit with 64 or vice versa */
				String err = "BadImageFormatException: Incorrect MuPDF DLL";
				mupdfDLLProblemMain(this, err);
				return -1;
			}
			return output;
		}

		private string tc_mGetVers()
		{
			String output;
			try
			{
				if (is64bit)
					output = mGetVers64();
				else
					output = mGetVers32();
			}
			catch (DllNotFoundException)
			{
				/* DLL not found */
				String err = "DllNotFoundException: MuPDF DLL not found 27";
				mupdfDLLProblemMain(this, err);
				return null;
			}
			catch (BadImageFormatException)
			{
				/* Using 32 bit with 64 or vice versa */
				String err = "BadImageFormatException: Incorrect MuPDF DLL";
				mupdfDLLProblemMain(this, err);
				return null;
			}
			return output;
		}

		private string tc_mGetText(IntPtr ctx, int pagenum, textout_t type)
		{
			String output;
			try
			{
				if (is64bit)
					output = mGetText64(ctx, pagenum, (int) type);
				else
					output = mGetText32(ctx, pagenum, (int) type);
			}
			catch (DllNotFoundException)
			{
				/* DLL not found */
				String err = "DllNotFoundException: MuPDF DLL not found 28";
				mupdfDLLProblemMain(this, err);
				return null;
			}
			catch (BadImageFormatException)
			{
				/* Using 32 bit with 64 or vice versa */
				String err = "BadImageFormatException: Incorrect MuPDF DLL";
				mupdfDLLProblemMain(this, err);
				return null;
			}
			return output;
		}

		private int tc_mSavePage(IntPtr ctx, String outfile, int page_num, 
			int res, int type, bool append)
		{
			int output;
			try
			{
				if (is64bit)
					output = mSavePage64(ctx, outfile, page_num, res, type, append);
				else
					output = mSavePage32(ctx, outfile, page_num, res, type, append);
			}
			catch (DllNotFoundException)
			{
				/* DLL not found */
				String err = "DllNotFoundException: MuPDF DLL not found 29";
				mupdfDLLProblemMain(this, err);
				return -1;
			}
			catch (BadImageFormatException)
			{
				/* Using 32 bit with 64 or vice versa */
				String err = "BadImageFormatException: Incorrect MuPDF DLL";
				mupdfDLLProblemMain(this, err);
				return -1;
			}
			return output;
		}
		#endregion DLLErrorTrap

		/* Now the actual code that does some work */
		public status_t Initialize()
		{
			is64bit = Environment.Is64BitOperatingSystem &&
				Environment.Is64BitProcess;

			mu_object = tc_mInitialize();
			if (mu_object == null)
				return status_t.E_FAILURE;
			else
				return status_t.S_ISOK;
		}

		public void CleanUp()
		{
			if (mu_object != null)
			{
				lock(m_lock)
					tc_mCleanUp(mu_object);
			}
		}

		public String GetText(int page_num, textout_t type)
		{
			return tc_mGetText(mu_object, page_num, type);
		}

		public void GetVersion(out String vers)
		{
			vers = tc_mGetVers();
		}

		public int GetPageCount()
		{
			return tc_mGetPageCount(mu_object);
		}

		public bool RequiresPassword()
		{
			return tc_mRequiresPassword(mu_object);
		}

		public bool ApplyPassword(String password)
		{
			return tc_mApplyPassword(mu_object, password);
		}

		public void SetAA(AA_t AAlevel)
		{
			lock (m_lock)
			{
				tc_mSetAA(mu_object, (int)AAlevel);
			}
		}

		public int RenderPage(int page_num, Byte[] bmp_data, int bmp_width,
			int bmp_height, double scale, bool flipy, bool use_dlist, bool
			get_text, out BlocksText blocks, bool annotation, 
			out Annotate_t annot_type)
		{
			int code;
			blocks = null;
			String blockcolor = "#00FFFFFF";
			String linecolor = "#402572AC";
			/* Debug */
			//blockcolor = "#20FFFF00";

			annot_type = Annotate_t.UNKNOWN;
			if (use_dlist) 
			{
				IntPtr dlist = IntPtr.Zero;
				IntPtr annot_dlist = IntPtr.Zero;
				IntPtr text = IntPtr.Zero;
				int num_blocks = 0;

				int page_height = 0;
				int page_width = 0;

				if (get_text)
				{
					lock (m_lock)
					{
						dlist = tc_mCreateDisplayListText(mu_object, page_num,
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

							int num_lines = tc_mGetTextBlock(text, kk, ref top_x,
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
								int num_chars = tc_mGetTextLine(text, kk, jj, ref top_x,
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
									int character = tc_mGetTextCharacter(text, kk, jj, mm, ref top_x,
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
						tc_mReleaseText(mu_object, text);
					}
				}
				else
					lock (m_lock)
					{
						dlist = tc_mCreateDisplayList(mu_object, page_num, 
							ref page_width, ref page_height);
					}
				if (annotation)
				{
					lock (m_lock)
					{
						annot_dlist = tc_mCreateDisplayListAnnot(mu_object, page_num);
						if (annot_dlist == IntPtr.Zero)
							annot_type = Annotate_t.NO_ANNOTATE;
						else
							annot_type = Annotate_t.HAS_ANNOTATE;
					}
				}

				/* Rendering of display list can occur with other threads so unlock */
				if (dlist == null)
				{
					return (int) status_t.E_FAILURE;
				}
				code = tc_mRenderPageMT(mu_object, dlist, annot_dlist, page_width, 
					page_height, bmp_data, bmp_width, bmp_height, scale, flipy);
			} 
			else
 			{
				lock(m_lock)
				{
					code = tc_mRenderPage(mu_object, page_num, bmp_data, bmp_width,
						bmp_height, scale, flipy);
				}
			}
			return code;
		}

		public status_t OpenFile(string filename)
		{
			return tc_mOpenDocument(mu_object, filename);
		}

		public int GetPageSize(int page_num, out Point size_out)
		{
			int code;
			double height = 0, width = 0;

			size_out = new Point();

			lock(m_lock)
			{
				code = tc_mMeasurePage(mu_object, page_num, ref width, ref height);
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
				num_items = tc_mGetContents(mu_object);
			}

			if (contents == null)
				contents = new List<ContentItem>();

			for (int k = 0; k < num_items; k++)
			{
				ContentItem item = new ContentItem();
				item.StringMargin = tc_mGetContentsItem(k, ref len, ref page);
				item.Page = page;
				contents.Add(item);
			}
			return num_items;
		}

		public void ReleaseContents()
		{
			tc_mReleaseContents();
		}

		public int TextSearchPage(int page_num, String needle)
		{
			int num_found;
			lock (m_lock)
			{
				num_found = tc_mTextSearchPage(mu_object, page_num, needle);
			}
			return num_found;
		}

		public bool GetTextSearchItem(int k, out Point top_left, out Size size_rect)
		{
			double top_x = 0, top_y = 0 , height = 0, width = 0;
			bool found = tc_mGetTextSearchItem(k, ref top_x, ref top_y, ref height, ref width);

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
			tc_mReleaseTextSearch();
		}

		public int GetLinksPage(int page_num)
		{
			int num_found;
			lock (m_lock)
			{
				num_found = tc_mGetLinksPage(mu_object, page_num);
			}
			return num_found;
		}

		public void GetLinkItem(int k, out Point top_left, out Size size_rect, 
			out String uri, out int topage, out int typea)
		{
			double top_x = 0, top_y = 0, height = 0, width = 0;
			int typeb = 0;
			int linkpage = 0;

			uri = tc_mGetLinkItem(k, ref top_x, ref top_y, ref height, ref width,
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
			tc_mReleaseLink();
		}

		public void ReleaseText(IntPtr textpage)
		{
			tc_mReleaseText(mu_object, textpage);
		}

		public void HTMLSaveAs(String infile, String outfile, String password, 
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
				tc_mExtractPages(infile, outfile, password, has_password, linearize,
					num_pages, pagesPtrStable.AddrOfPinnedObject());
				pagesPtrStable.Free();
			}
			else
			{
				tc_mExtractPages(infile, outfile, password, has_password, linearize,
							num_pages, IntPtr.Zero);
			}
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
				tc_mExtractPages(infile, outfile, password, has_password, linearize,
					num_pages, pagesPtrStable.AddrOfPinnedObject());
				pagesPtrStable.Free();
			}
			else
			{
				tc_mExtractPages(infile, outfile, password, has_password, linearize,
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
							result = tc_mSavePage(mu_object, out_file_name,
								page_num - 1, resolution, (int) mudevice_t.SVG_OUT,
								false);
						break;
					case gsDevice_t.pnm:
						lock (this.m_lock) /* Single-page format */
							result = tc_mSavePage(mu_object, out_file_name,
								page_num - 1, resolution, (int)mudevice_t.PNM_OUT,
								false);
						break;
					case gsDevice_t.pclbitmap:  /* Multi-page format */
						lock (this.m_lock)
							result = tc_mSavePage(mu_object, out_file,
								page_num - 1, resolution, (int)mudevice_t.PCL_OUT,
								append);
						break;
					case gsDevice_t.pwg:  /* Multi-page format */
						lock (this.m_lock)
							result = tc_mSavePage(mu_object, out_file,
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
