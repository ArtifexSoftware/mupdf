package com.artifex.mupdf.fitz;

public class Font
{
	private long pointer;

	protected native void finalize();

	public void destroy() {
		finalize();
		pointer = 0;
	}

	private Font(long p) {
		pointer = p;
	}

	public native String getName();

	public String toString() {
		return "Font(" + getName() + ")";
	}
}
