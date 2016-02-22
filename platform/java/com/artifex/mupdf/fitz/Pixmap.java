package com.artifex.mupdf.fitz;

public class Pixmap
{
	private long pointer;

	protected native void finalize();

	public void destroy() {
		finalize();
		pointer = 0;
	}

	private native long newNative(ColorSpace cs, int x, int y, int w, int h);

	private Pixmap(long p) {
		pointer = p;
	}

	public Pixmap(ColorSpace colorspace, int x, int y, int w, int h) {
		pointer = newNative(colorspace, x, y, w, h);
	}

	public Pixmap(ColorSpace colorspace, int w, int h) {
		this(colorspace, 0, 0, w, h);
	}

	public Pixmap(ColorSpace colorspace, Rect rect) {
		this(colorspace, (int)rect.x0, (int)rect.y0, (int)(rect.x1 - rect.x0), (int)(rect.y1 - rect.y0));
	}

	public native void clear();
	public native void clearWithValue(int value);

	public native void saveAsPNG(String filename, boolean saveAlpha);

	public native int getX();
	public native int getY();
	public native int getWidth();
	public native int getHeight();
	public native int getStride();
	public native int getNumberOfComponents();
	public native ColorSpace getColorSpace();
	public native byte[] getSamples();
	public native int[] getPixels(); /* only valid for RGB or BGR pixmaps */

	public void clear(int value) {
		clearWithValue(value);
	}

	public String toString() {
		return "Pixmap(w=" + getWidth() +
			" h=" + getHeight() +
			" x=" + getX() +
			" y=" + getY() +
			" n=" + getNumberOfComponents() +
			" cs=" + getColorSpace() +
			")";
	}
}
