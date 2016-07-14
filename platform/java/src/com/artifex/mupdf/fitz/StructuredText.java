package com.artifex.mupdf.fitz;

public class StructuredText
{
	private long pointer;

	protected native void finalize();

	public void destroy() {
		finalize();
		pointer = 0;
	}

	private StructuredText(long p) {
		pointer = p;
	}

	public native Rect[] search(String needle);
	public native Rect[] highlight(Rect rect);
	public native String copy(Rect rect);
}
