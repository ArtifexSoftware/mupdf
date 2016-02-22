package com.artifex.mupdf.fitz;

public class Annotation
{
	// Private data
	private long nativeAnnot = 0;

	// Construction
	private Annotation(long ptr)
	{
		nativeAnnot = ptr;
	}

	// Operation
	public native void run(Device dev, Matrix ctm, Cookie cookie);

	// FIXME: Write accessors

	// Destruction
	public void destroy()
	{
		finalize();
		nativeAnnot = 0;
	}

	protected native void finalize();
}
