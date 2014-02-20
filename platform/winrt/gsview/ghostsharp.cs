using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;using System.Runtime.InteropServices;
using System.IO;
using System.Security;
using System.ComponentModel;

namespace gsview
{
	public enum gsDevice_t
	{
		bmp16,
		bmp16m,
		bmp256,
		bmp32b,
		bmpgray,
		bmpmono,
		epswrite,
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
		pdfwrite,
		ps2write,
		psdcmyk,
		psdrgb,
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
		public int resolution;
		public gsDevice_t device;
		public String outputfile;
		public String inputfile;
		public GS_Task_t task;
		public GS_Result_t result;
		public int num_pages;
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
	struct gsapi_revision_t 
	{
		IntPtr product;
		IntPtr copyright;
		long revision;
		long revisiondate;
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

		/* Ghostscript API */
		[DllImport("gsdll64.dll", CharSet = CharSet.Ansi,
			CallingConvention = CallingConvention.StdCall)]
		public static extern int gsapi_revision(IntPtr stuct, int size);

		[DllImport("gsdll64.dll", CharSet = CharSet.Ansi,
			CallingConvention = CallingConvention.StdCall)]
		public static extern int gsapi_new_instance(out IntPtr pinstance, 
			IntPtr caller_handle);

		[DllImport("gsdll64.dll", CharSet = CharSet.Ansi,
			CallingConvention = CallingConvention.StdCall)]
		public static extern void gsapi_delete_instance(IntPtr instance);

		[DllImport("gsdll64.dll", CharSet = CharSet.Ansi,
			CallingConvention = CallingConvention.StdCall)]
		public static extern int gsapi_init_with_args(IntPtr instance, int argc, 
			IntPtr argv);

		[DllImport("gsdll64.dll", CharSet = CharSet.Ansi,
			CallingConvention = CallingConvention.StdCall)]
		public static extern int gsapi_exit(IntPtr instance);

		[DllImport("gsdll64.dll", CharSet = CharSet.Ansi,
			CallingConvention = CallingConvention.StdCall)]
		public static extern int gsapi_set_arg_encoding(IntPtr instance, 
			int encoding);

		[DllImport("gsdll64.dll", CharSet = CharSet.Ansi,
			CallingConvention = CallingConvention.StdCall)]
			public static extern int gsapi_set_stdio(IntPtr instance, 
			gsStdIOHandler stdin, gsStdIOHandler stdout, gsStdIOHandler stderr);

		[DllImport("gsdll64.dll", CharSet = CharSet.Ansi,
			CallingConvention = CallingConvention.StdCall)]
		public static extern void gsapi_run_string_begin(IntPtr instance,
			int usererr, ref int exitcode);

		[DllImport("gsdll64.dll", CharSet = CharSet.Ansi,
		CallingConvention = CallingConvention.StdCall)]
		public static extern void gsapi_run_string_continue(IntPtr instance, 
			IntPtr command, int count, int usererr, ref int exitcode);

		[DllImport("gsdll64.dll", CharSet = CharSet.Ansi,
			CallingConvention = CallingConvention.StdCall)]
		public static extern void gsapi_run_string_end(IntPtr instance,
			int usererr, ref int exitcode);

		private int StdInCallback(IntPtr handle, IntPtr pointer, int count)
		{
			String output = Marshal.PtrToStringAnsi(pointer);
			return count;
		}

		private int StdOutCallback(IntPtr handle, IntPtr pointer, int count)
		{
			String output = Marshal.PtrToStringAnsi(pointer);
			gsIOUpdateMain(this, output, count);
			if (m_params.task == GS_Task_t.CREATE_XPS)
			{
				/* See if we have a page number */
				if (count >= 7 && output.Substring(0, 4) == "Page")
				{
					String page = output.Substring(5, count - 6);
					int numVal;
					try
					{
						numVal = System.Convert.ToInt32(page);

						double perc = 100.0 * (double)numVal / (double)m_params.num_pages;
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
		gsParams_t m_params;
		/* Callbacks to Main */
		internal delegate void gsIOCallBackMain(object gsObject, String mess, int len);
		internal event gsIOCallBackMain gsIOUpdateMain;
		internal delegate void gsCallBackMain(object gsObject, gsEventArgs info);
		internal event gsCallBackMain gsUpdateMain;

		public ghostsharp()
		{
			m_worker = null;
			gsInstance = IntPtr.Zero;
		}

		/* A standard command line approach to using gs API */
		private void gsWork1(object sender, DoWorkEventArgs e)
		{
			gsParams_t Params = (gsParams_t) e.Argument;
			String out_file = Params.outputfile;
			String in_file = Params.inputfile;
			int num_params = 9;
			var argParam = new GCHandle[num_params];
			var argPtrs = new IntPtr[num_params];
			String[] strParams = new String[num_params];
			List<byte[]> CharacterArray = new List<byte[]>(num_params);
			GCHandle argPtrsStable;

			/* New instance */
			int code = gsapi_new_instance(out gsInstance, IntPtr.Zero);
			if (code < 0)
			{
				Params.result = GS_Result_t.gsFAILED;
				e.Result = Params;
				return;
			}

			var RaiseStdInCallback = new gsStdIOHandler(StdInCallback);
			var RaiseStdOutCallback = new gsStdIOHandler(StdOutCallback);
			var RaiseStdErrCallback = new gsStdIOHandler(StdErrCallback);

			var stdInPtr = Marshal.GetFunctionPointerForDelegate(RaiseStdInCallback);
			var stdOutPtr = Marshal.GetFunctionPointerForDelegate(RaiseStdOutCallback);
			var stdErrPtr = Marshal.GetFunctionPointerForDelegate(RaiseStdErrCallback);

			// Setup stdio callback functions
			code = gsapi_set_stdio(gsInstance, RaiseStdInCallback, RaiseStdOutCallback, RaiseStdErrCallback); 

			code = gsapi_set_arg_encoding(gsInstance, (int) gsEncoding.GS_ARG_ENCODING_UTF8);
			if (code == 0)
			{
				strParams[0] = "gs";   /* This does not matter */
				strParams[1] = "-dNOPAUSE";
				strParams[2] = "-dBATCH";
				strParams[3] = "-dSAFER";
				strParams[4] = "-sDEVICE=" + Enum.GetName(typeof(gsDevice_t), Params.device);
				strParams[5] = "-r" + Params.resolution;
				/* Create temp file if file not specified */
				if (out_file == null)
				{
					out_file = Path.GetTempFileName();
					Params.outputfile = out_file;
				}
				strParams[6] = "-o" + out_file;
				strParams[7] = "-f";
				strParams[8] = in_file;

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

				code = gsapi_init_with_args(gsInstance, num_params, argPtrsStable.AddrOfPinnedObject());

				/* All the pinned items need to be freed so the GC can do its job */
				for (int k = 0; k < num_params; k++)
				{
					argParam[k].Free();
				}
				argPtrsStable.Free();
			}

			int code1 = gsapi_exit(gsInstance);
			if ((code == 0) || (code == gsConstants.E_QUIT))
				code = code1;

			RaiseStdInCallback = null;
			RaiseStdOutCallback = null;
			RaiseStdErrCallback = null;

			gsapi_delete_instance(gsInstance);
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

		/* Feeding gs piecemeal so that we can have some progress callback */
		private void gsWork2(object sender, DoWorkEventArgs e)
		{
			gsParams_t Params = (gsParams_t)e.Argument;
			String out_file = Params.outputfile;
			String in_file = Params.inputfile;
			int num_params = 7;
			int exitcode = 0;
			var argParam = new GCHandle[num_params];
			var argPtrs = new IntPtr[num_params];
			var Feed = new GCHandle();
			var FeedPtr = new IntPtr();
			String[] strParams = new String[num_params];
			List<byte[]> CharacterArray = new List<byte[]>(num_params);
			GCHandle argPtrsStable;
			bool done = false;
			Byte[] Buffer = new Byte[gsConstants.GS_READ_BUFFER];
			BackgroundWorker worker = sender as BackgroundWorker;

			/* Open the file */
			var fs = new FileStream(in_file, FileMode.Open);
			var len = (int) fs.Length;
			/* New instance */
			int code = gsapi_new_instance(out gsInstance, IntPtr.Zero);
			if (code < 0)
			{
				Params.result = GS_Result_t.gsFAILED;
				e.Result = Params;
				return;
			}

			var RaiseStdInCallback = new gsStdIOHandler(StdInCallback);
			var RaiseStdOutCallback = new gsStdIOHandler(StdOutCallback);
			var RaiseStdErrCallback = new gsStdIOHandler(StdErrCallback);

			var stdInPtr = Marshal.GetFunctionPointerForDelegate(RaiseStdInCallback);
			var stdOutPtr = Marshal.GetFunctionPointerForDelegate(RaiseStdOutCallback);
			var stdErrPtr = Marshal.GetFunctionPointerForDelegate(RaiseStdErrCallback);

			// Setup stdio callback functions
			code = gsapi_set_stdio(gsInstance, RaiseStdInCallback, RaiseStdOutCallback, RaiseStdErrCallback); 

			code = gsapi_set_arg_encoding(gsInstance, (int)gsEncoding.GS_ARG_ENCODING_UTF8);

			if (code == 0)
			{
				strParams[0] = "gs";   /* This does not matter */
				strParams[1] = "-dNOPAUSE";
				strParams[2] = "-dBATCH";
				strParams[3] = "-dSAFER";
				strParams[4] = "-sDEVICE=" + Enum.GetName(typeof(gsDevice_t), Params.device);
				strParams[5] = "-r" + Params.resolution;
				/* Create temp file if file not specified */
				if (out_file == null)
				{
					out_file = Path.GetTempFileName();
					Params.outputfile = out_file;
				}
				strParams[6] = "-o" + out_file;

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

				code = gsapi_init_with_args(gsInstance, num_params, argPtrsStable.AddrOfPinnedObject());

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

					gsapi_run_string_begin(gsInstance, 0, ref exitcode);
					while ((count = fs.Read(Buffer, 0, gsConstants.GS_READ_BUFFER)) > 0)
					{
						gsapi_run_string_continue(gsInstance, FeedPtr, count, 0, ref exitcode);
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
					gsapi_run_string_end(gsInstance, 0, ref exitcode);
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

			int code1 = gsapi_exit(gsInstance);
			if ((code == 0) || (code == gsConstants.E_QUIT))
				code = code1;

			gsapi_delete_instance(gsInstance);
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
			gsParams_t Params = (gsParams_t) e.Result;

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

		public gsStatus DistillPS(String FileName, int resolution)
		{
			gsParams_t Params = new gsParams_t(); ;

			Params.device = gsDevice_t.pdfwrite;
			Params.outputfile = null;
			Params.resolution = resolution;
			Params.inputfile = FileName;
			Params.outputfile = null;
			Params.num_pages = -1;
			Params.task = GS_Task_t.PS_DISTILL;
			return RunGhostscript(Params);
		}

		public gsStatus CreateXPS(String FileName, int resolution, int num_pages)
		{
			gsParams_t Params = new gsParams_t(); ;

			Params.device = gsDevice_t.xpswrite;
			Params.outputfile = null;
			Params.resolution = resolution;
			Params.inputfile = FileName;
			Params.outputfile = null;
			Params.task = GS_Task_t.CREATE_XPS;
			Params.num_pages = num_pages;
			return RunGhostscript(Params);
		}

		public gsStatus GetStatus()
		{
			if (m_worker != null && m_worker.IsBusy)
				return gsStatus.GS_BUSY;
			else
				return gsStatus.GS_READY;
		}

		private gsStatus RunGhostscript(gsParams_t Params)
		{
			/* Create background task for rendering the thumbnails.  Allow
			this to be cancelled if we open a new doc while we are in loop
			rendering.  Put the UI updates in the progress changed which will
			run on the main thread */
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
