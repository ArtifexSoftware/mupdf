package com.artifex.mupdf.fitz;

// This class handles the loading of the MuPDF shared library, together
// with the ThreadLocal magic to get the required context.
//
// The only publicly accessible method here is Context.setStoreSize, which
// sets the store size to use. This must be called before any other MuPDF
// function.
public class Context
{
	private static boolean inited = false;
	private static native int initNative();
	public static native int gprfSupportedNative();

	public static void init() {
		if (!inited) {
			inited = true;
			System.loadLibrary(getLibraryName());
			if (initNative() < 0)
				throw new RuntimeException("cannot initialize mupdf library");
		}
	}

	private static String getLibraryName() {
		/* Mac OS always uses 64bit DLLs for any JDK 1.7 or above */
		if (System.getProperty("os.name").toLowerCase().contains("mac os")) {
			return "mupdf_java64";
		}
		/* Sun and OpenJDK JVMs support this way of finding bittedness */
		String val = System.getProperty("sun.arch.data.model");
		/* Android does NOT support this, and returns NULL */
		if (val != null && val.equals("64")) {
			return "mupdf_java64";
		}

		/* We might be running Android here. We could find out by
		 * doing the following test:
		 *  val = System.getProperty("java.vm.name");
		 *  if (val != null && val.toLowerCase().contains("dalvik")) {
		 *    ...Do something Androidy to test for 32/64 here...
		 *  }
		 * (Currently, both Dalvik and ART return 'Dalvik').
		 * We know of no portable way to detect 32 or 64bittedness
		 * on android though, so for now will assume 32.
		 */

		return "mupdf_java32";
	}

	static { init(); }

	// FIXME: We should support the store size being changed dynamically.
	// This requires changes within the MuPDF core.
	//public native static void setStoreSize(long newSize);
}
