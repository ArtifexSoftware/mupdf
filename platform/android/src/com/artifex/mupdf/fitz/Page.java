package com.artifex.mupdf.fitz;

public class Page
{
	// Private data
	private long nativePage = 0;
	private Annotation nativeAnnots[];

	// Construction
	private Page(long page)
	{
		nativePage = page;
		nativeAnnots = null;
	}

	// Operation
	public native Rect bound();
	public native void run(Device dev, Matrix ctm, Cookie cookie);
	public native void runPageContents(Device dev, Matrix ctm, Cookie cookie);
	public native Annotation[] getAnnotations();

	// FIXME: Later
	public native Link[] getLinks();

	// FIXME: Later. Much later.
	//fz_transition *fz_page_presentation(fz_document *doc, fz_page *page, float *duration);

	// Destruction
	public void destroy()
	{
		finalize();
		nativePage = 0;
		nativeAnnots = null;
	}

	protected native void finalize();
}
