package com.artifex.mupdf.fitz;

public class Cookie
{
	// Private data
	private long nativeCookie = 0;

	// Construction
	public Cookie()
	{
		nativeCookie = newNative();
	}

	private native long newNative();

	// Operation
	public native void abort();

	//FIXME: Cookie accessors

	// Destruction
	protected native void finalize();

	public void destroy()
	{
		finalize();
		nativeCookie = 0;
	}
	
}
