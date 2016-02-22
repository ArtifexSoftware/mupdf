package com.artifex.mupdf.fitz;

public class Font
{
	// Private data
	private long nativeFont;

	// Construction
	private Font(long font)
	{
		nativeFont = font;
	}

	// Destruction
	public void destroy()
	{
		finalize();
		nativeFont = 0;
	}

	protected native void finalize();
}
