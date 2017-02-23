package com.artifex.mupdf.fitz;

public class PDFPage extends Page
{
	private PDFPage(long p) { super(p); }

	public native PDFAnnotation createAnnotation(int type);
	public native void deleteAnnotation(Annotation annot);
}
