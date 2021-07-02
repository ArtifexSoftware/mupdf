package com.artifex.mupdf.fitz;

public class Image
{
	static {
		Context.init();
	}

	protected long pointer;

	protected native void finalize();

	public void destroy() {
		finalize();
	}

	private native long newNativeFromPixmap(Pixmap pixmap);
	private native long newNativeFromFile(String filename);
	private native long newNativeFromBytes(byte[] bytes);

	protected Image(long p) {
		pointer = p;
	}

	public Image(Pixmap pixmap) {
		pointer = newNativeFromPixmap(pixmap);
	}

	public Image(String filename) {
		pointer = newNativeFromFile(filename);
	}

	public Image(byte[] bytes) {
		pointer = newNativeFromBytes(bytes);
	}

	public native int getWidth();
	public native int getHeight();
	public native int getXResolution();
	public native int getYResolution();

	public native ColorSpace getColorSpace();
	public native int getNumberOfComponents();
	public native int getBitsPerComponent();
	public native boolean getImageMask();
	public native boolean getInterpolate();
	public native Image getMask();

	public native Pixmap toPixmap();
}
