package com.artifex.mupdf.fitz;

public class Image
{
	private long pointer;

	protected native void finalize();

	public void destroy() {
		finalize();
		pointer = 0;
	}

	private Image(long p) {
		pointer = p;
	}

	public native int getWidth();
	public native int getHeight();
	public native int getNumberOfComponents();
	public native int getBitsPerComponent();
	public native int getXResolution();
	public native int getYResolution();
	public native boolean getImageMask();
	public native boolean getInterpolate();
	public native Image getMask();

	// FIXME: Get data back?
	// FIXME: Create images from data or java streams?
}
