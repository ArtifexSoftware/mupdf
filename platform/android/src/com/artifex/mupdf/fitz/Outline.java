package com.artifex.mupdf.fitz;

public class Outline
{
	// Private data
	private long nativeOutline = 0;

	// Construction
	private Outline(long out)
	{
		nativeOutline = out;
	}

	// Destruction
	public void destroy()
	{
		finalize();
		nativeOutline = 0;
	}

	protected native void finalize();
}
