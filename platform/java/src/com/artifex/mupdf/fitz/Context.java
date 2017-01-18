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
			try {
				System.loadLibrary("mupdf_java");
			} catch (UnsatisfiedLinkError e) {
				try {
					System.loadLibrary("mupdf_java64");
				} catch (UnsatisfiedLinkError ee) {
					System.loadLibrary("mupdf_java32");
				}
			}
			if (initNative() < 0)
				throw new RuntimeException("cannot initialize mupdf library");
		}
	}

	static { init(); }

	// FIXME: We should support the store size being changed dynamically.
	// This requires changes within the MuPDF core.
	//public native static void setStoreSize(long newSize);
}
