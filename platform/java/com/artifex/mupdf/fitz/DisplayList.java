package com.artifex.mupdf.fitz;

public class DisplayList
{
	// Private data
	protected long nativeDisplayList;

	// Constructions
	public DisplayList()
	{
		nativeDisplayList = newNative();
	}

	private native long newNative();

	// Operation
	public native void run(Device device, Matrix ctm, Rect scissor, Cookie cookie);

	public void run(Device device, Matrix ctm, Cookie cookie)
	{
		run(device, ctm, null, cookie);
	}

	// Destruction
	public void destroy()
	{
		finalize();
		nativeDisplayList = 0;
	}

	protected native void finalize();
}
