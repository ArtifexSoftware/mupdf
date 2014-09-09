using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
//using System.Threading.Tasks;
using System.Runtime.InteropServices;
using System.IO;
using System.Security;
using System.ComponentModel;

namespace gsview
{
	/* Warning. This list is in a particular order. The devices before 
	 * psdrgb do not support multiple pages.  Those including psdrgb do 
	 * support multiple pages.  This is used in the conversion process.
	 * Also note that mupdf devices go at the beginning of the list */
	public enum gsDevice_t
	{
		svg, 
		pnm,
		pclbitmap,
		pwg,
		bmp16,  /* Add mupdf devices before this one */
		bmp16m,
		bmp256,
		bmp32b,
		bmpgray,
		bmpmono,
		eps2write,
		jpeg,
		jpegcmyk,
		jpeggray,
		pamcmyk32,
		pamcmyk4,
		pbm,
		pgm,
		png16,
		png16m,
		png256,
		pngalpha,
		pnggray,
		pngmono,
		psdcmyk,
		psdrgb,  /* Add single page gs devices before this device */
		pdfwrite,
		ps2write,
		pxlcolor,
		pxlmono,
		tiff12nc,
		tiff24nc,
		tiff32nc,
		tiff64nc,
		tiffcrle,
		tiffg3,
		tiffg32d,
		tiffg4,
		tiffgray,
		tifflzw,
		tiffpack,
		tiffsep,
		txtwrite,
		xpswrite
	};

	public enum GS_Task_t
	{
		PS_DISTILL,
		CREATE_XPS,
		SAVE_RESULT
	}

	public enum GS_Result_t
	{
		gsOK,
		gsFAILED,
		gsCANCELLED
	}

	/* Parameters */
	public struct gsParams_t
	{
		public String init_string;
		public String init_file;
		public int resolution;
		public gsDevice_t device;
		public String devicename;
		public String outputfile;
		public String inputfile;
		public GS_Task_t task;
		public GS_Result_t result;
		public int num_pages;
		public String options;
		public bool need_multi_page;
		public System.Collections.IList pages;
		public int firstpage;
		public int lastpage;
		public int currpage; /* valid only when pages != null */
	};

	public class gsEventArgs : EventArgs
	{
		private bool m_completed;
		private int m_progress;
		private gsParams_t m_param;

		public bool Completed
		{
			get { return m_completed; }
		}

		public gsParams_t Params
		{
			get { return m_param; }
		}

		public int Progress
		{
			get { return m_progress; }
		}

		public gsEventArgs(bool completed, int progress, gsParams_t param)
		{
			m_completed = completed;
			m_progress = progress;
			m_param = param;
		}
	}

	/* from gs */
	public struct gsapi_revision_t 
	{
		public IntPtr product;
		public IntPtr copyright;
		public int revision;
		public int revisiondate;
	}

	public enum gsEncoding {
		GS_ARG_ENCODING_LOCAL = 0,
		GS_ARG_ENCODING_UTF8 = 1,
		GS_ARG_ENCODING_UTF16LE = 2
	};

	public enum gsStatus
	{
		GS_READY,
		GS_BUSY,
		GS_ERROR
	};

	static class gsConstants
	{
		public const int E_QUIT = -101;
		public const int GS_READ_BUFFER = 32768;
	}

	[SuppressUnmanagedCodeSecurity]
	class ghostsharp
	{
		/* Callback proto for stdio */
		public delegate int gsStdIOHandler(IntPtr caller_handle, IntPtr buffer, 
			int len);

		#region DLLInterface
		/* Ghostscript API */
		[DllImport("gsdll64.dll", EntryPoint = "gsapi_revision", CharSet = CharSet.Ansi,
			CallingConvention = CallingConvention.StdCall)]
		private static extern int gsapi_revision64(ref gsapi_revision_t vers, int size);

		[DllImport("gsdll64.dll", EntryPoint="gsapi_new_instance", CharSet = CharSet.Ansi,
			CallingConvention = CallingConvention.StdCall)]
		private static extern int gsapi_new_instance64(out IntPtr pinstance, 
			IntPtr caller_handle);

		[DllImport("gsdll64.dll", EntryPoint = "gsapi_delete_instance", CharSet = CharSet.Ansi,
			CallingConvention = CallingConvention.StdCall)]
		private static extern void gsapi_delete_instance64(IntPtr instance);

		[DllImport("gsdll64.dll", EntryPoint = "gsapi_init_with_args", CharSet = CharSet.Ansi,
			CallingConvention = CallingConvention.StdCall)]
		private static extern int gsapi_init_with_args64(IntPtr instance, int argc, 
			IntPtr argv);

		[DllImport("gsdll64.dll", EntryPoint = "gsapi_exit", CharSet = CharSet.Ansi,
			CallingConvention = CallingConvention.StdCall)]
		private static extern int gsapi_exit64(IntPtr instance);

		[DllImport("gsdll64.dll", EntryPoint = "gsapi_set_arg_encoding", CharSet = CharSet.Ansi,
			CallingConvention = CallingConvention.StdCall)]
		private static extern int gsapi_set_arg_encoding64(IntPtr instance, 
			int encoding);

		[DllImport("gsdll64.dll", EntryPoint = "gsapi_set_stdio", CharSet = CharSet.Ansi,
			CallingConvention = CallingConvention.StdCall)]
		private static extern int gsapi_set_stdio64(IntPtr instance,
			gsStdIOHandler stdin, gsStdIOHandler stdout, gsStdIOHandler stderr);

		[DllImport("gsdll64.dll", EntryPoint = "gsapi_run_string_begin", CharSet = CharSet.Ansi,
			CallingConvention = CallingConvention.StdCall)]
		private static extern void gsapi_run_string_begin64(IntPtr instance,
			int usererr, ref int exitcode);

		[DllImport("gsdll64.dll", EntryPoint = "gsapi_run_string_continue", CharSet = CharSet.Ansi,
		CallingConvention = CallingConvention.StdCall)]
		private static extern void gsapi_run_string_continue64(IntPtr instance, 
			IntPtr command, int count, int usererr, ref int exitcode);

		[DllImport("gsdll64.dll", EntryPoint = "gsapi_run_string_end", CharSet = CharSet.Ansi,
			CallingConvention = CallingConvention.StdCall)]
		private static extern void gsapi_run_string_end64(IntPtr instance,
			int usererr, ref int exitcode);

		/* 32 Bit DLL */
		[DllImport("gsdll32.dll", EntryPoint = "gsapi_revision", CharSet = CharSet.Ansi,
			CallingConvention = CallingConvention.StdCall)]
		private static extern int gsapi_revision32(ref gsapi_revision_t vers, int size);

		[DllImport("gsdll32.dll", EntryPoint = "gsapi_new_instance", CharSet = CharSet.Ansi,
			CallingConvention = CallingConvention.StdCall)]
		private static extern int gsapi_new_instance32(out IntPtr pinstance,
			IntPtr caller_handle);

		[DllImport("gsdll32.dll", EntryPoint = "gsapi_delete_instance", CharSet = CharSet.Ansi,
			CallingConvention = CallingConvention.StdCall)]
		private static extern void gsapi_delete_instance32(IntPtr instance);

		[DllImport("gsdll32.dll", EntryPoint = "gsapi_init_with_args", CharSet = CharSet.Ansi,
			CallingConvention = CallingConvention.StdCall)]
		private static extern int gsapi_init_with_args32(IntPtr instance, int argc,
			IntPtr argv);

		[DllImport("gsdll32.dll", EntryPoint = "gsapi_exit", CharSet = CharSet.Ansi,
			CallingConvention = CallingConvention.StdCall)]
		private static extern int gsapi_exit32(IntPtr instance);

		[DllImport("gsdll32.dll", EntryPoint = "gsapi_set_arg_encoding", CharSet = CharSet.Ansi,
			CallingConvention = CallingConvention.StdCall)]
		private static extern int gsapi_set_arg_encoding32(IntPtr instance,
			int encoding);

		[DllImport("gsdll32.dll", EntryPoint = "gsapi_set_stdio", CharSet = CharSet.Ansi,
			CallingConvention = CallingConvention.StdCall)]
		private static extern int gsapi_set_stdio32(IntPtr instance,
		gsStdIOHandler stdin, gsStdIOHandler stdout, gsStdIOHandler stderr);

		[DllImport("gsdll32.dll", EntryPoint = "gsapi_run_string_begin", CharSet = CharSet.Ansi,
			CallingConvention = CallingConvention.StdCall)]
		private static extern void gsapi_run_string_begin32(IntPtr instance,
			int usererr, ref int exitcode);

		[DllImport("gsdll32.dll", EntryPoint = "gsapi_run_string_continue", CharSet = CharSet.Ansi,
		CallingConvention = CallingConvention.StdCall)]
		private static extern void gsapi_run_string_continue32(IntPtr instance,
			IntPtr command, int count, int usererr, ref int exitcode);

		[DllImport("gsdll32.dll", EntryPoint = "gsapi_run_string_end", CharSet = CharSet.Ansi,
			CallingConvention = CallingConvention.StdCall)]
		private static extern void gsapi_run_string_end32(IntPtr instance,
			int usererr, ref int exitcode);
		#endregion DLLInterface

		#region DLLErrorCatch
		/* In case the DLL is not found we need to wrap the methods up with
		 * a try/catch.  Also select 32 or 64 bit DLL at this time.  This 
		 * C# code is compiled as ANYCPU type */
		private int tc_gsapi_revision(ref gsapi_revision_t vers, int size)
		{
			int code = 0;
			try
			{
				if (is64bit)
					code = gsapi_revision64(ref vers, size);
				else
					code = gsapi_revision32(ref vers, size);
			}
			catch (DllNotFoundException)
			{
				/* DLL not found */
				String output = "DllNotFoundException: Ghostscript DLL not found";
				gsDLLProblemMain(this, output);
				return -1;
			}
			catch (BadImageFormatException)
			{
				/* Using 32 bit with 64 or vice versa */
				String output = "BadImageFormatException: Incorrect Ghostscript DLL";
				gsDLLProblemMain(this, output);
				return -1;
			}
			return code;
		}

		private int tc_gsapi_new_instance(out IntPtr pinstance, IntPtr caller_handle)
		{
			int code = 0;
			pinstance = IntPtr.Zero;
			try
			{
				if (is64bit)
					code = gsapi_new_instance64(out pinstance, caller_handle);
				else
					code = gsapi_new_instance32(out pinstance, caller_handle);
			}
			catch (DllNotFoundException)
			{
				/* DLL not found */
				String output = "DllNotFoundException: Ghostscript DLL not found";
				gsDLLProblemMain(this, output);
				return -1;
			}
			catch (BadImageFormatException)
			{
				/* Using 32 bit with 64 or vice versa */
				String output = "BadImageFormatException: Incorrect Ghostscript DLL";
				gsDLLProblemMain(this, output);
				return -1;
			}
			return code;
		}

		private int tc_gsapi_delete_instance(IntPtr instance)
		{
			try
			{
				if (is64bit)
					gsapi_delete_instance64(instance);
				else
					gsapi_delete_instance32(instance);
			}
			catch (DllNotFoundException)
			{
				/* DLL not found */
				String output = "DllNotFoundException: Ghostscript DLL not found";
				gsDLLProblemMain(this, output);
				return -1;
			}
			catch (BadImageFormatException)
			{
				/* Using 32 bit with 64 or vice versa */
				String output = "BadImageFormatException: Incorrect Ghostscript DLL";
				gsDLLProblemMain(this, output);
				return -1;
			}
			return 0;
		}

		private int tc_gsapi_init_with_args(IntPtr instance, int argc, IntPtr argv)
		{
			int code;

			try
			{
				if (is64bit)
					code = gsapi_init_with_args64(instance, argc, argv);
				else
					code = gsapi_init_with_args32(instance, argc, argv);
			}
			catch (DllNotFoundException)
			{
				/* DLL not found */
				String output = "DllNotFoundException: Ghostscript DLL not found";
				gsDLLProblemMain(this, output);
				return -1;
			}
			catch (BadImageFormatException)
			{
				/* Using 32 bit with 64 or vice versa */
				String output = "BadImageFormatException: Incorrect Ghostscript DLL";
				gsDLLProblemMain(this, output);
				return -1;
			}
			catch(System.Reflection.TargetInvocationException ee)
			{
				String output = "TargetInvocationException";
				gsDLLProblemMain(this, output);
				return -1;
			}

			return code;
		}

		private int tc_gsapi_exit(IntPtr instance)
		{
			int code;
			try
			{
				if (is64bit)
					code = gsapi_exit64(instance);
				else
					code = gsapi_exit32(instance);
			}
			catch (DllNotFoundException)
			{
				/* DLL not found */
				String output = "DllNotFoundException: Ghostscript DLL not found";
				gsDLLProblemMain(this, output);
				return -1;
			}
			catch (BadImageFormatException)
			{
				/* Using 32 bit with 64 or vice versa */
				String output = "BadImageFormatException: Incorrect Ghostscript DLL";
				gsDLLProblemMain(this, output);
				return -1;
			}
			return code;
		}

		private int tc_gsapi_set_arg_encoding(IntPtr instance, int encoding)
		{
			int code;
			try
			{
				if (is64bit)
					code = gsapi_set_arg_encoding64(instance, encoding);
				else
					code = gsapi_set_arg_encoding32(instance, encoding);
			}
			catch (DllNotFoundException)
			{
				/* DLL not found */
				String output = "DllNotFoundException: Ghostscript DLL not found";
				gsDLLProblemMain(this, output);
				return -1;
			}
			catch (BadImageFormatException)
			{
				/* Using 32 bit with 64 or vice versa */
				String output = "BadImageFormatException: Incorrect Ghostscript DLL";
				gsDLLProblemMain(this, output);
				return -1;
			}
			return code;
		}

		private int tc_gsapi_set_stdio(IntPtr instance, gsStdIOHandler stdin, 
			gsStdIOHandler stdout, gsStdIOHandler stderr)
		{
			int code;
			try
			{
				if (is64bit)
					code = gsapi_set_stdio64(instance, stdin, stdout, stderr);
				else
					code = gsapi_set_stdio32(instance, stdin, stdout, stderr);
			}
			catch (DllNotFoundException)
			{
				/* DLL not found */
				String output = "DllNotFoundException: Ghostscript DLL not found";
				gsDLLProblemMain(this, output);
				return -1;
			}
			catch (BadImageFormatException)
			{
				/* Using 32 bit with 64 or vice versa */
				String output = "BadImageFormatException: Incorrect Ghostscript DLL";
				gsDLLProblemMain(this, output);
				return -1;
			}
			return code;
		}

		private int tc_gsapi_run_string_begin(IntPtr instance, int usererr, 
			ref int exitcode)
		{
			try
			{
				if (is64bit)
					gsapi_run_string_begin64(instance, usererr, ref exitcode);
				else
					gsapi_run_string_begin32(instance, usererr, ref exitcode);
			}
			catch (DllNotFoundException)
			{
				/* DLL not found */
				String output = "DllNotFoundException: Ghostscript DLL not found";
				gsDLLProblemMain(this, output);
				return -1;
			}
			catch (BadImageFormatException)
			{
				/* Using 32 bit with 64 or vice versa */
				String output = "BadImageFormatException: Incorrect Ghostscript DLL";
				gsDLLProblemMain(this, output);
				return -1;
			}
			return 0;
		}

		private int tc_gsapi_run_string_continue(IntPtr instance, IntPtr command, 
			int count, int usererr, ref int exitcode)
		{
			try
			{
				if (is64bit)
					gsapi_run_string_continue64(instance, command, count, usererr,
						ref exitcode);
				else
					gsapi_run_string_continue32(instance, command, count, usererr,
						ref exitcode);
			}
			catch (DllNotFoundException)
			{
				/* DLL not found */
				String output = "DllNotFoundException: Ghostscript DLL not found";
				gsDLLProblemMain(this, output);
				return -1;
			}
			catch (BadImageFormatException)
			{
				/* Using 32 bit with 64 or vice versa */
				String output = "BadImageFormatException: Incorrect Ghostscript DLL";
				gsDLLProblemMain(this, output);
				return -1;
			}
			return 0;
		}

		private int tc_gsapi_run_string_end(IntPtr instance, int usererr, 
			ref int exitcode)
		{
			try
			{
				if (is64bit)
					gsapi_run_string_end64(instance, usererr, ref exitcode);
				else
					gsapi_run_string_end32(instance, usererr, ref exitcode);
			}
			catch (DllNotFoundException)
			{
				/* DLL not found */
				String output = "DllNotFoundException: Ghostscript DLL not found";
				gsDLLProblemMain(this, output);
				return -1;
			}
			catch (BadImageFormatException)
			{
				/* Using 32 bit with 64 or vice versa */
				String output = "BadImageFormatException: Incorrect Ghostscript DLL";
				gsDLLProblemMain(this, output);
				return -1;
			}
			return 0;
		}
		#endregion DLLErrorCatch

		private int StdInCallback(IntPtr handle, IntPtr pointer, int count)
		{
			String output = Marshal.PtrToStringAnsi(pointer);
			return count;
		}

		private int StdOutCallback(IntPtr handle, IntPtr pointer, int count)
		{
			String output = Marshal.PtrToStringAnsi(pointer);
			gsIOUpdateMain(this, output, count);
			if (m_params.task != GS_Task_t.PS_DISTILL)
			{
				/* See if we have a page number */
				if (count >= 7 && output.Substring(0, 4) == "Page")
				{
					String page = output.Substring(5, count - 6);
					int numVal;
					try
					{
						double perc = 0.0;
						numVal = System.Convert.ToInt32(page);
						if (m_params.firstpage == -1 && m_params.lastpage == -1 &&
							m_params.pages == null)
						{
							/* Doing full document */
							perc = 100.0 * (double)numVal / (double)m_params.num_pages;
						}
						else
						{
							if (m_params.pages != null)
							{
								perc = 100.0 * ((double)numVal - m_params.currpage) / (double)m_params.num_pages;
								m_params.currpage = m_params.currpage + 1;
							}
							else
							{
								/* continugous set of pages */
								perc = 100.0 * ((double)numVal - m_params.firstpage + 1) / (double)m_params.num_pages;
							}
						}
						m_worker.ReportProgress((int)perc);
					}
					catch (FormatException e)
					{
						Console.WriteLine("XPSPrint Error: Input string is not a sequence of digits.");
					}
					catch (OverflowException e)
					{
						Console.WriteLine("XPSPrint Error: The number cannot fit in an Int32.");
					}
					
				}
			}
			return count;
		}

		private int StdErrCallback(IntPtr handle, IntPtr pointer, int count)
		{
			String output = Marshal.PtrToStringAnsi(pointer);
			gsIOUpdateMain(this, output, count);
			return count;
		}

		IntPtr gsInstance;
		BackgroundWorker m_worker;
		bool is64bit;
		gsParams_t m_params;
		/* Callbacks to Main */
		internal delegate void gsDLLProblem(object gsObject, String mess);
		internal event gsDLLProblem gsDLLProblemMain;
		internal delegate void gsIOCallBackMain(object gsObject, String mess, int len);
		internal event gsIOCallBackMain gsIOUpdateMain;
		internal delegate void gsCallBackMain(object gsObject, gsEventArgs info);
		internal event gsCallBackMain gsUpdateMain;
		/* These need to be declared as members, to keep a reference and avoid GC
		 * You do not pin delegates */
		gsStdIOHandler RaiseStdInCallback;
		gsStdIOHandler RaiseStdOutCallback;
		gsStdIOHandler RaiseStdErrCallback;

		public ghostsharp()
		{
			/* Determine now if we are 64 or 32 bit */
			is64bit = Environment.Is64BitOperatingSystem &&
				Environment.Is64BitProcess;
			m_worker = null;
			gsInstance = IntPtr.Zero;

			/* Go ahead and do the assignment here */
			RaiseStdInCallback = StdInCallback;
			RaiseStdOutCallback = StdOutCallback;
			RaiseStdErrCallback = StdErrCallback;
		}

		private List<String> GetOptions(String options)
		{
			List<String> optionlist = new List<String>();

			if (options != "")
			{
				string[] words = options.Split(' ');
				for (int k = 0; k < words.Length; k++)
				{
					if (words[k].Length > 0)
					{
						optionlist.Add(words[k]);
					}
				}
			}
			return optionlist;
		}

		/* A standard command line approach to using gs API */
		private void gsWork1(object sender, DoWorkEventArgs e)
		{
			gsParams_t gsparams = (gsParams_t) e.Argument;
			String out_file = gsparams.outputfile;
			String in_file = gsparams.inputfile;
			int num_params = 8;  /* base number */
			int rend_count = 1;
			String options;
			int count;
			List<String> optionlist;

			optionlist = GetOptions(gsparams.options);
			num_params = num_params + optionlist.Count;
			if (gsparams.pages != null)
			{
				rend_count = gsparams.pages.Count;
				num_params = num_params + 2;
			}
			if (gsparams.init_file != null)
				num_params = num_params + 1;
			if (gsparams.init_string != null)
				num_params = num_params + 2;

			var argParam = new GCHandle[num_params];
			var argPtrs = new IntPtr[num_params];
			String[] strParams = new String[num_params];
			List<byte[]> CharacterArray = new List<byte[]>(num_params);
			GCHandle argPtrsStable;

			/* New instance */
			int code = tc_gsapi_new_instance(out gsInstance, IntPtr.Zero);
			if (code < 0)
			{
				gsparams.result = GS_Result_t.gsFAILED;
				e.Result = gsparams;
				return;
			}

			code = tc_gsapi_set_stdio(gsInstance, RaiseStdInCallback, 
				RaiseStdOutCallback, RaiseStdErrCallback);
			code = tc_gsapi_set_arg_encoding(gsInstance, (int)gsEncoding.GS_ARG_ENCODING_UTF8);

			if (code == 0)
			{
				for (int jj = 0; jj < rend_count; jj++)
				{
					strParams[0] = "gs";   /* This does not matter */
					strParams[1] = "-dNOPAUSE";
					strParams[2] = "-dBATCH";
					if (gsparams.devicename != null)
					{
						strParams[3] = "-sDEVICE=" + gsparams.devicename;
					}
					else
					{
						strParams[3] = "-sDEVICE=" + Enum.GetName(typeof(gsDevice_t), gsparams.device);
					}
					strParams[4] = "-r" + gsparams.resolution;
					/* Create temp file if file not specified */
					if (out_file == null)
					{
						out_file = Path.GetTempFileName();
						gsparams.outputfile = out_file;
					}
					count = 5;
					/* Add in the options */
					for (int kk = 0; kk < optionlist.Count; kk++)
					{
						strParams[count] = optionlist[kk];
						count++;
					}
					/* We have discontinuous page selection */
					if (gsparams.pages != null)
					{
						String firstpage, lastpage;
						options = gsparams.options;
						SelectPage curr_page = (SelectPage)(gsparams.pages[jj]);
						firstpage = "-dFirstPage=" + curr_page.Page;
						lastpage =  "-dLastPage=" + curr_page.Page;
						strParams[count] = firstpage;
						count++;
						strParams[count] = lastpage;
						count++;
						/* Look for file extension. */
						string extension = System.IO.Path.GetExtension(out_file);
						int len = extension.Length;
						String new_out_file = out_file.Substring(0, out_file.Length - len);
						strParams[count] = "-o" + new_out_file + "_page" + curr_page.Page + extension;
					}
					else
					{
						if (gsparams.need_multi_page)
						{
							/* Look for file extension. */
							string extension = System.IO.Path.GetExtension(out_file);
							int len = extension.Length;
							String new_out_file = out_file.Substring(0, out_file.Length - len);
							strParams[count] = "-o" + new_out_file + "_page%d" + extension;
						}
						else
							strParams[count] = "-o" + out_file;
					}
					if (gsparams.init_string != null)
					{
						count++;
						strParams[count] = "-c";
						count++;
						strParams[count] = gsparams.init_string;
					}
					count++;
					strParams[count] = "-f";
					if (gsparams.init_file != null)
					{
						count++;
						strParams[count] = gsparams.init_file;
					}
					count++;
					strParams[count] = in_file;

					/* Now convert our Strings to char* and get pinned handles to these.
					 * This keeps the c# GC from moving stuff around on us */
					for (int k = 0; k < num_params; k++)
					{
						CharacterArray.Add(System.Text.Encoding.UTF8.GetBytes(strParams[k].ToCharArray()));
						argParam[k] = GCHandle.Alloc(CharacterArray[k], GCHandleType.Pinned);
						argPtrs[k] = argParam[k].AddrOfPinnedObject();
					}
					/* Also stick the array of pointers into memory that will not be GCd */
					argPtrsStable = GCHandle.Alloc(argPtrs, GCHandleType.Pinned);

					code = tc_gsapi_init_with_args(gsInstance, num_params, argPtrsStable.AddrOfPinnedObject());
					/* All the pinned items need to be freed so the GC can do its job */
					for (int k = 0; k < num_params; k++)
					{
						argParam[k].Free();
					}
					argPtrsStable.Free();
					/* Free the character array list in case we have multiple runs */
					CharacterArray.Clear();

					if (code < 0)
						break;
				}
			}

			int code1 = tc_gsapi_exit(gsInstance);
			if ((code == 0) || (code == gsConstants.E_QUIT))
				code = code1;

			tc_gsapi_delete_instance(gsInstance);
			if ((code == 0) || (code == gsConstants.E_QUIT))
			{
				gsparams.result = GS_Result_t.gsOK;
				e.Result = gsparams;
				return;
			}

			gsparams.result = GS_Result_t.gsFAILED;
			e.Result = gsparams;
			return;
		}

		/* Feeding gs piecemeal so that we can have some progress callback */
		/* Used only for PS Distill */
		private void gsWork2(object sender, DoWorkEventArgs e)
		{
			gsParams_t Params = (gsParams_t)e.Argument;
			String out_file = Params.outputfile;
			String in_file = Params.inputfile;
			int num_params = 6;
			if (Params.options.Length > 0)
				num_params = num_params + 1;

			int exitcode = 0;
			var argParam = new GCHandle[num_params];
			var argPtrs = new IntPtr[num_params];
			var Feed = new GCHandle();
			var FeedPtr = new IntPtr();
			String[] strParams = new String[num_params];
			List<byte[]> CharacterArray = new List<byte[]>(num_params);
			GCHandle argPtrsStable;
			Byte[] Buffer = new Byte[gsConstants.GS_READ_BUFFER];
			BackgroundWorker worker = sender as BackgroundWorker;

			/* Open the file */
			var fs = new FileStream(in_file, FileMode.Open);
			var len = (int) fs.Length;
			/* New instance */
			int code = tc_gsapi_new_instance(out gsInstance, IntPtr.Zero);
			if (code < 0)
			{
				Params.result = GS_Result_t.gsFAILED;
				e.Result = Params;
				return;
			}

			code = tc_gsapi_set_stdio(gsInstance, RaiseStdInCallback, 
				RaiseStdOutCallback, RaiseStdErrCallback);
			code = tc_gsapi_set_arg_encoding(gsInstance, (int)gsEncoding.GS_ARG_ENCODING_UTF8);

			if (code == 0)
			{
				strParams[0] = "gs";   /* This does not matter */
				strParams[1] = "-dNOPAUSE";
				strParams[2] = "-dBATCH";
				if (Params.devicename != null)
				{
					strParams[3] = "-sDEVICE=" + Params.devicename;
				}
				else
				{
					strParams[3] = "-sDEVICE=" + Enum.GetName(typeof(gsDevice_t), Params.device);
				}
				strParams[4] = "-r" + Params.resolution;
				/* Create temp file if file not specified */
				if (out_file == null)
				{
					out_file = Path.GetTempFileName();
					Params.outputfile = out_file;
				}
				if (Params.options.Length > 0)
				{
					strParams[5] = Params.options;
					strParams[6] = "-o" + out_file;
				} else 
					strParams[5] = "-o" + out_file;

				/* Now convert our Strings to char* and get pinned handles to these.
					* This keeps the c# GC from moving stuff around on us */
				for (int k = 0; k < num_params; k++)
				{
					CharacterArray.Add(System.Text.Encoding.UTF8.GetBytes(strParams[k].ToCharArray()));
					argParam[k] = GCHandle.Alloc(CharacterArray[k], GCHandleType.Pinned);
					argPtrs[k] = argParam[k].AddrOfPinnedObject();
				}
				/* Also stick the array of pointers into memory that will not be GCd */
				argPtrsStable = GCHandle.Alloc(argPtrs, GCHandleType.Pinned);

				code = tc_gsapi_init_with_args(gsInstance, num_params, argPtrsStable.AddrOfPinnedObject());

				/* First pin the data buffer */
				Feed = GCHandle.Alloc(Buffer, GCHandleType.Pinned);
				FeedPtr = Feed.AddrOfPinnedObject();

				/* Now start feeding the input piece meal and do a call back
					* with our progress */
				if (code == 0)
				{
					int count;
					double perc;
					int total = 0;

					tc_gsapi_run_string_begin(gsInstance, 0, ref exitcode);
					while ((count = fs.Read(Buffer, 0, gsConstants.GS_READ_BUFFER)) > 0)
					{
						tc_gsapi_run_string_continue(gsInstance, FeedPtr, count, 0, ref exitcode);
						if (exitcode < 0)
						{
							code = exitcode;
							break;
						}
						total =  total + count;
						perc = 100.0 * (double) total / (double) len;
						worker.ReportProgress((int)perc);
						if (worker.CancellationPending == true)
						{
							e.Cancel = true;
							break;
						}
					}
					tc_gsapi_run_string_end(gsInstance, 0, ref exitcode);
					if (code == 0)
						code = exitcode;
				}

				/* All the pinned items need to be freed so the GC can do its job */
				for (int k = 0; k < num_params; k++)
				{
					argParam[k].Free();
				}
				argPtrsStable.Free();
				Feed.Free();
			}

			int code1 = tc_gsapi_exit(gsInstance);
			if ((code == 0) || (code == gsConstants.E_QUIT))
				code = code1;

			tc_gsapi_delete_instance(gsInstance);
			if ((code == 0) || (code == gsConstants.E_QUIT))
			{
				Params.result = GS_Result_t.gsOK;
				e.Result = Params;
				return;
			}
			Params.result = GS_Result_t.gsFAILED;
			e.Result = Params;
			return;
		}

		/* Callback */
		private void gsCompleted(object sender, RunWorkerCompletedEventArgs e)
		{
			gsParams_t Value;
			gsEventArgs info;
			gsParams_t Params;

			try
			{
				Params = (gsParams_t)e.Result;
			}
			catch(System.Reflection.TargetInvocationException ee)
			{
				/* Something went VERY wrong with GS */
				/* Following is to help debug these issues */
				/* var inner = ee.InnerException;
				var message = ee.Message;
				var inner_message = inner.Message;
				String bound = "\n************\n";
				gsIOUpdateMain(this, bound, bound.Length);
				gsIOUpdateMain(this, message, message.Length);
				gsIOUpdateMain(this, bound, bound.Length);
				gsIOUpdateMain(this, inner_message, inner_message.Length);
				gsIOUpdateMain(this, bound, bound.Length);
				var temp = inner.Source;
				gsIOUpdateMain(this, bound, bound.Length);
				gsIOUpdateMain(this, temp, temp.Length);
				var method = inner.TargetSite;
				gsIOUpdateMain(this, bound, bound.Length);
				var method_name = method.Name;
				gsIOUpdateMain(this, method_name, method_name.Length);
				var stack = inner.StackTrace;
				gsIOUpdateMain(this, bound, bound.Length);
				gsIOUpdateMain(this, stack, stack.Length); */
				String output = "Ghostscript DLL Invalid Access.";
				gsDLLProblemMain(this, output);
				return;
			}
			
			if (Params.task == GS_Task_t.PS_DISTILL)
				m_worker.DoWork -= new DoWorkEventHandler(gsWork2);
			else
				m_worker.DoWork -= new DoWorkEventHandler(gsWork1);

			if (e.Cancelled)
			{
				Value = new gsParams_t();
				Value.result = GS_Result_t.gsCANCELLED;
				info = new gsEventArgs(true, 100, Value);
			} 
			else
			{
				Value = (gsParams_t)e.Result;
				info = new gsEventArgs(true, 100, Value);
			}
			gsUpdateMain(this, info);
		}

		private void gsProgressChanged(object sender, ProgressChangedEventArgs e)
		{
			/* Callback with progress */
			gsParams_t Value = new gsParams_t();
			gsEventArgs info = new gsEventArgs(false, e.ProgressPercentage, Value);
			gsUpdateMain(this, info);
		}

		public gsStatus DistillPS(String fileName, int resolution)
		{
			gsParams_t gsparams = new gsParams_t(); ;

			gsparams.init_file = null;
			gsparams.init_string = null;
			gsparams.device = gsDevice_t.pdfwrite;
			gsparams.devicename = null;
			gsparams.outputfile = null;
			gsparams.resolution = resolution;
			gsparams.inputfile = fileName;
			gsparams.num_pages = -1;
			gsparams.task = GS_Task_t.PS_DISTILL;
			gsparams.options = "";
			gsparams.need_multi_page = false;
			gsparams.pages = null;
			gsparams.firstpage = -1;
			gsparams.lastpage = -1;
			gsparams.currpage = -1;
			return RunGhostscript(gsparams);
		}

		public gsStatus CreateXPS(String fileName, int resolution, int num_pages)
		{
			gsParams_t gsparams = new gsParams_t();

			gsparams.init_file = null;
			gsparams.init_string = null;
			gsparams.device = gsDevice_t.xpswrite;
			gsparams.outputfile = null;
			gsparams.resolution = resolution;
			gsparams.inputfile = fileName;
			gsparams.task = GS_Task_t.CREATE_XPS;
			gsparams.num_pages = num_pages;
			gsparams.options = "-dNOCACHE";
			gsparams.need_multi_page = false;
			gsparams.pages = null;
			gsparams.firstpage = -1;
			gsparams.lastpage = -1;
			gsparams.currpage = -1;
			return RunGhostscript(gsparams);
		}

		public gsStatus Convert(String fileName, String options, String device, 
								String outputFile, int num_pages, int resolution,
								bool multi_page_needed, System.Collections.IList pages, 
								int firstpage, int lastpage, String init_file, String init_string)
		{
			gsParams_t gsparams = new gsParams_t();

			gsparams.init_file = init_file;
			gsparams.init_string = init_string;
			gsparams.devicename = device;
			gsparams.outputfile = outputFile;
			gsparams.inputfile = fileName;
			gsparams.task = GS_Task_t.SAVE_RESULT;
			gsparams.num_pages = num_pages;
			gsparams.options = options;
			gsparams.resolution = resolution;
			gsparams.need_multi_page = multi_page_needed;
			gsparams.pages = pages;
			gsparams.firstpage = firstpage;
			gsparams.lastpage = lastpage;
			gsparams.currpage = 1;
			return RunGhostscript(gsparams);
		}

		public gsStatus GetStatus()
		{
			if (m_worker != null && m_worker.IsBusy)
				return gsStatus.GS_BUSY;
			else
				return gsStatus.GS_READY;
		}

		public String GetVersion()
		{
			gsapi_revision_t vers;
			vers.copyright = IntPtr.Zero;
			vers.product = IntPtr.Zero;
			vers.revision = 0;
			vers.revisiondate = 0;
			int size = System.Runtime.InteropServices.Marshal.SizeOf(vers);

			if (tc_gsapi_revision(ref vers, size) == 0)
			{
				String product = Marshal.PtrToStringAnsi(vers.product);
				String output;
				int major = vers.revision / 100;
				int minor = vers.revision - major * 100;
				String versnum = major + "." + minor;
				output = product + " " + versnum;
				return output;
			}
			else
				return null;
		}

		private gsStatus RunGhostscript(gsParams_t Params)
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
					m_worker.RunWorkerCompleted += new RunWorkerCompletedEventHandler(gsCompleted);
					m_worker.ProgressChanged += new ProgressChangedEventHandler(gsProgressChanged);
				}

				if (Params.task == GS_Task_t.PS_DISTILL)
					m_worker.DoWork += new DoWorkEventHandler(gsWork2);
				else
					m_worker.DoWork += new DoWorkEventHandler(gsWork1);

				m_params = Params;
				m_worker.RunWorkerAsync(Params);
				return gsStatus.GS_READY;
			}
			catch (OutOfMemoryException e)
			{
				Console.WriteLine("Memory allocation failed during gs rendering\n");
				return gsStatus.GS_ERROR;
			}
		}

		public void Cancel()
		{
			m_worker.CancelAsync();
		}
	}
}
