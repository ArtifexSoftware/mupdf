package com.artifex.mupdf.fitz;

public class Text
{
	// Private data
	private long nativeText = 0;
	private boolean isConst = false;

	// Cloning
	public Text(Text old)
	{
		nativeText = cloneNative(old);
	}

	private native long cloneNative(Text old);

	//public Text(Font font, Matrix trm, int wmode)
	//{
	//	nativeText = newNative(font, trm, wmode);
	//}

	// Private method used for creating Text entries for a
	// device implemented in java. These entries should be
	// immutable.
	private Text(long ptr)
	{
		nativeText = ptr;
		isConst = true;
	}

	// Operation
	public native Rect bound(StrokeState stroke, Matrix ctm);

	//public native void add(int gid, int ucs, float x, float y);

	// FIXME: Write accessors

	// Destruction
	public void destroy()
	{
		finalize();
		nativeText = 0;
	}

	protected native void finalize();
}
