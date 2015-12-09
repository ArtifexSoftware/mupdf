package com.artifex.mupdf.fitz;

public class Link
{
	// Private data
	private long nativeLink = 0;

	// Construction
	private Link(long l)
	{
		nativeLink = l;
	}

	// Operation
	public native Link getNext();

	//FIXME: Accessors

	// Destruction
	public void destroy()
	{
		finalize();
		nativeLink = 0;
	}

	protected native void finalize();
}
