package com.artifex.mupdf.fitz;

public class Link
{
	private long pointer;

	protected native void finalize();

	public void destroy() {
		finalize();
		pointer = 0;
	}

	private Link(long p) {
		pointer = p;
	}

	public native Link getNext();
}
