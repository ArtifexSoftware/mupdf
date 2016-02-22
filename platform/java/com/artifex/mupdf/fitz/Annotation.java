package com.artifex.mupdf.fitz;

public class Annotation
{
	private long pointer;

	protected native void finalize();

	public void destroy() {
		finalize();
		pointer = 0;
	}

	private Annotation(long p) {
		pointer = p;
	}

	public native void run(Device dev, Matrix ctm, Cookie cookie);

	private native long advance();
}
