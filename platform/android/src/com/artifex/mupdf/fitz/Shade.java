package com.artifex.mupdf.fitz;

public class Shade
{
	// Private data
	private long nativeShade = 0;

	// Construction
	// Private constructor for the C to use. Any objects created by the
	// C are done for purposes of calling back to a java device, and
	// should therefore be considered const.
	private Shade(long l)
	{
		nativeShade = l;
	}

	// FIXME: Constructors for the different types of shade
	// FIXME: Accessors for shade data

	// Destruction
	public void destroy()
	{
		finalize();
		nativeShade = 0;
	}

	protected native void finalize();
}
