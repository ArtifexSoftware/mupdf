package com.artifex.mupdf.fitz;

public class DisplayList
{
	protected long pointer;

	protected native void finalize();

	public void destroy() {
		finalize();
		pointer = 0;
	}

	private native long newNative();

	public DisplayList() {
		pointer = newNative();
	}

	public native void run(Device device, Matrix ctm, Rect scissor, Cookie cookie);

	public void run(Device device, Matrix ctm, Cookie cookie) {
		run(device, ctm, null, cookie);
	}
}
