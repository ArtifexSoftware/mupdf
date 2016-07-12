package com.artifex.mupdf.fitz;

public class DisplayList
{
	private long pointer;

	protected native void finalize();

	public void destroy() {
		finalize();
		pointer = 0;
	}

	private native long newNative();

	public DisplayList() {
		pointer = newNative();
	}

	public native void run(Device dev, Matrix ctm, Rect scissor, Cookie cookie);

	public void run(Device dev, Matrix ctm, Cookie cookie) {
		run(dev, ctm, null, cookie);
	}
}
