package com.artifex.mupdf.fitz;

public class PDFGraftMap
{
	private long pointer;

	protected native void finalize();

	public void destroy() {
		finalize();
		pointer = 0;
	}

	private PDFGraftMap(long p) {
		pointer = p;
	}
}
