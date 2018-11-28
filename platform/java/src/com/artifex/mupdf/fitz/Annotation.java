package com.artifex.mupdf.fitz;

public class Annotation
{
	static {
		Context.init();
	}

	private long pointer;

	protected native void finalize();

	public void destroy() {
		finalize();
		pointer = 0;
	}

	protected Annotation(long p) {
		pointer = p;
	}

	public boolean equals(Annotation other) {
		return (this.pointer == other.pointer);
	}

	public boolean equals(long other) {
		return (this.pointer == other);
	}

	public native void run(Device dev, Matrix ctm, Cookie cookie);
	public native Pixmap toPixmap(Matrix ctm, ColorSpace colorspace, boolean alpha);
	public native Rect getBounds();
	public native DisplayList toDisplayList();
}
